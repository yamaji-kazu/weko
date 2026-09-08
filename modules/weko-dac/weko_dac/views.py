# -*- coding: utf-8 -*-
"""REST API blueprints for weko-dac (RDC-AAP-01 §4–6)."""

import re
import time
from datetime import datetime
from urllib.parse import unquote

import jwt as pyjwt
from flask import (Blueprint, Response, current_app, g, jsonify, redirect,
                   request, send_file)
from invenio_db import db

from . import allowlist, audit, presentation, registered, services, signing
from .auth import (AuthError, jwk_to_public_key, problem_title, problem_type,
                   require_rags_token, verify_jws)
from .models import (DacAgreement, DacApplication, DacMessage, DacOffer,
                     DacPresentationJti, DacVisa)

blueprint_wellknown = Blueprint('weko_dac_wellknown', __name__, template_folder='templates')

blueprint_api = Blueprint('weko_dac_api', __name__, url_prefix='/dac/v1')


def _problem(status, code, detail=''):
    """RFC 9457 Problem Details response.

    The second argument is the stable machine ``code`` (snake_case); the
    ``type`` URI and human-readable ``title`` are auto-generated from it
    (RDC-AAP-01 §5.8.2). The raw code is never used as the title.
    """
    resp = jsonify({'type': problem_type(code), 'title': problem_title(code),
                    'status': status, 'detail': detail, 'code': code})
    resp.status_code = status
    resp.headers['Content-Type'] = 'application/problem+json'
    return resp


# --------------------------------------------------------------------------
# Federation entity configuration (§3)
# --------------------------------------------------------------------------

@blueprint_wellknown.route('/.well-known/openid-federation')
def openid_federation():
    """Self-signed Entity Configuration ([DEMO]: no Trust Anchor)."""
    try:
        token = signing.entity_configuration()
    except RuntimeError as ex:
        return _problem(503, 'key_unavailable', str(ex))
    return Response(token, mimetype='application/entity-statement+jwt')


# --------------------------------------------------------------------------
# Policy API (§4.2) — public
# --------------------------------------------------------------------------

_SCHEME_REPAIR_RE = re.compile(r'^(https?):/([^/].*)$')


def _dataset_candidates(raw):
    """Candidate spellings of a dataset id received via URL path.

    Reverse proxies decode %2F and merge slashes before the path
    reaches the app, so "https://host/x" arrives as "https:/host/x".
    We repair that here; the query-parameter form (below) avoids the
    problem entirely and is the recommended transport for URL-shaped
    identifiers.
    """
    cands = []

    def add(value):
        if value and value not in cands:
            cands.append(value)

    add(raw)
    add(unquote(raw))
    for c in list(cands):
        m = _SCHEME_REPAIR_RE.match(c)
        if m:
            add(m.group(1) + '://' + m.group(2))
    return cands


def _find_offer(raw):
    """Resolve a DacOffer from any candidate spelling.

    Returns (row_or_None, canonical_dataset_id).
    """
    for c in _dataset_candidates(raw):
        row = DacOffer.query.filter_by(dataset_id=c).first()
        if row is not None:
            return row, row.dataset_id
    return None, unquote(raw)


def _policy_response(raw):
    row, canonical = _find_offer(raw)
    if row is None:
        return _problem(404, 'unknown_dataset',
                        'No policy registered for %s' % canonical)
    return Response(
        response=jsonify(row.offer).get_data(),
        mimetype='application/odrl+json')


@blueprint_api.route('/datasets/<path:dataset_id>/policy',
                     methods=['GET'])
def get_policy(dataset_id):
    """Return the ODRL Offer of a dataset (path form, §4.2)."""
    return _policy_response(dataset_id)


@blueprint_api.route('/policy', methods=['GET'])
def get_policy_query():
    """Query-parameter form: ``GET /policy?dataset_id=<url-encoded>``.

    Reliable for URL-shaped identifiers, which proxies mangle in the
    path (%2F decoding + slash merging). Same response as §4.2.
    """
    raw = request.args.get('dataset_id', '')
    if not raw:
        return _problem(400, 'missing_dataset_id',
                        'dataset_id query parameter required')
    return _policy_response(raw)


@blueprint_api.route('/visa-jwks.json', methods=['GET'])
def visa_jwks():
    """JWKS for Visa / Agreement verification (§6.2)."""
    try:
        return jsonify(signing.public_jwks())
    except RuntimeError as ex:
        return _problem(503, 'key_unavailable', str(ex))


@blueprint_api.route('/visa-status', methods=['GET'])
def visa_status():
    """Revocation / status lookup for issued Visas (§6.2)."""
    jti = request.args.get('jti', '')
    row = DacVisa.query.filter_by(jti=jti).first()
    if row is None:
        return _problem(404, 'unknown_visa', 'jti not found')
    return jsonify({'jti': jti, 'status': row.current_status()})


# --------------------------------------------------------------------------
# Application intake (§5.2)
# --------------------------------------------------------------------------

@blueprint_api.route('/applications', methods=['POST'])
@require_rags_token(scope='rags:apply')
def create_application():
    """Accept an RDC-AAP application."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _problem(400, 'invalid_application', 'JSON body required')
    try:
        application = services.intake_application(
            payload, g.dac_sub, g.dac_agent)
    except services.IntakeError as err:
        db.session.rollback()
        return _problem(err.status, err.title, err.detail)
    return jsonify({
        'application_id': application.application_id,
        'status': application.status,
        'received_at': application.received_at.isoformat() + 'Z',
        'estimated_review':
            current_app.config['WEKO_DAC_ESTIMATED_REVIEW'],
        'links': {'self': '/api/dac/v1/applications/%s'
                          % application.application_id},
    }), 201


def _caller_owns(application):
    """Whether the caller may read/act on this application.

    Spec (§5.4): the delegation pair — researcher ``sub`` AND delegated
    agent (``act.sub``/``azp``) — must match what created the application.

    Demo option ``WEKO_DAC_SCOPE_OWNER_SUB_ONLY`` relaxes this to "the
    researcher (``sub``) may always read their own application", so the
    researcher can check status through any of their agents/portals
    (e.g. sub=researcher via dg-portal). The on-behalf-of agent still
    needs ``sub``=researcher; a token whose ``sub`` is a different
    identity is denied either way.
    """
    sub_ok = application.researcher_sub == g.dac_sub
    if current_app.config.get('WEKO_DAC_SCOPE_OWNER_SUB_ONLY'):
        return sub_ok
    return sub_ok and application.agent_id == g.dac_agent


def _own_application_or_none(app_id):
    application = DacApplication.query.filter_by(
        application_id=app_id).first()
    if application is None:
        return None
    if not _caller_owns(application):
        return None
    return application


@blueprint_api.route('/applications', methods=['GET'])
@require_rags_token(scope='rags:apply')
def list_applications():
    """List own applications (§5.4).

    Restricted to the caller's delegation pair (sub, act.sub); with
    ``WEKO_DAC_SCOPE_OWNER_SUB_ONLY`` the researcher (sub) lists their
    own applications regardless of which agent/portal presents the token.
    """
    query = DacApplication.query.filter_by(researcher_sub=g.dac_sub)
    if not current_app.config.get('WEKO_DAC_SCOPE_OWNER_SUB_ONLY'):
        query = query.filter_by(agent_id=g.dac_agent)
    status = request.args.get('status')
    if status:
        query = query.filter_by(status=status)
    madmp = request.args.get('madmp')
    if madmp:
        query = query.filter_by(madmp_id=madmp)
    items = [_application_summary(a)
             for a in query.order_by(DacApplication.id.desc()).limit(100)]
    return jsonify({'applications': items})


def _application_summary(application):
    return {
        'application_id': application.application_id,
        'status': application.status,
        'resource_type': application.resource_type,
        'madmp': application.madmp_id,
        'received_at': application.received_at.isoformat() + 'Z',
        'updated_at': application.updated_at.isoformat() + 'Z',
    }


@blueprint_api.route('/applications/<app_id>', methods=['GET'])
@require_rags_token(scope='rags:apply')
def get_application(app_id):
    """Application status, history and issued artifacts (§5.4)."""
    application = _own_application_or_none(app_id)
    if application is None:
        return _problem(404, 'unknown_application', app_id)
    agreements = DacAgreement.query.filter_by(
        application_id=app_id).all()
    visas = DacVisa.query.filter_by(application_id=app_id).all()
    body = _application_summary(application)
    body.update({
        'verification': application.verification,
        'artifacts': {
            'agreements': [
                {'uid': a.uid, 'dataset_id': a.dataset_id,
                 'href': '/api/dac/v1/applications/%s/agreement' % app_id}
                for a in agreements],
            'visas': [
                {'jti': v.jti, 'dataset_id': v.dataset_id,
                 'status': v.current_status(),
                 'wallet_credential_id': v.wallet_credential_id,
                 'wallet_deposited': v.wallet_deposited}
                for v in visas],
        },
    })
    # Fallback of §6.2: expose the raw Visa only when the wallet deposit
    # could not be completed (wallet outage / not configured).
    for v in visas:
        if not v.wallet_deposited:
            for entry in body['artifacts']['visas']:
                if entry['jti'] == v.jti:
                    entry['visa_jwt_fallback'] = v.visa_jwt
    return jsonify(body)


@blueprint_api.route('/applications/<app_id>/agreement', methods=['GET'])
@require_rags_token(scope='rags:apply')
def get_agreement(app_id):
    """Signed ODRL Agreement(s) of an application (§6.1)."""
    application = _own_application_or_none(app_id)
    if application is None:
        return _problem(404, 'unknown_application', app_id)
    rows = DacAgreement.query.filter_by(application_id=app_id).all()
    if not rows:
        return _problem(404, 'no_agreement', 'No agreement issued yet')
    return jsonify({'agreements': [
        {'uid': r.uid, 'dataset_id': r.dataset_id,
         'agreement': r.agreement, 'agreement_jws': r.agreement_jws}
        for r in rows]})


# --------------------------------------------------------------------------
# Messages (§5.5)
# --------------------------------------------------------------------------

@blueprint_api.route('/applications/<app_id>/messages', methods=['GET'])
@require_rags_token(scope='rags:apply')
def list_messages(app_id):
    """List the inquiry dialogue."""
    application = _own_application_or_none(app_id)
    if application is None:
        return _problem(404, 'unknown_application', app_id)
    rows = DacMessage.query.filter_by(application_id=app_id).order_by(
        DacMessage.id).all()
    return jsonify({'messages': [m.as_dict() for m in rows]})


@blueprint_api.route('/applications/<app_id>/messages', methods=['POST'])
@require_rags_token(scope='rags:apply')
def post_message(app_id):
    """Requester-side message (answer / info)."""
    application = _own_application_or_none(app_id)
    if application is None:
        return _problem(404, 'unknown_application', app_id)
    body = request.get_json(silent=True) or {}
    mtype = body.get('type', 'answer')
    if mtype not in ('answer', 'info'):
        return _problem(400, 'invalid_message',
                        'requester may send type answer|info')
    max_rounds = current_app.config['WEKO_DAC_MAX_NEGOTIATION_ROUNDS']
    if application.negotiation_rounds > max_rounds:
        return _problem(409, 'negotiation_limit',
                        'Negotiation exceeded %d rounds — escalated to a '
                        'human officer' % max_rounds)
    msg = services.add_message(
        application, 'requester', mtype, body.get('body'),
        author_kind=body.get('author_kind', 'ai'),
        structured=body.get('structured'),
        in_reply_to=body.get('in_reply_to'))
    db.session.commit()
    return jsonify(msg.as_dict()), 201


@blueprint_api.route('/applications/<app_id>/withdraw', methods=['POST'])
@require_rags_token(scope='rags:apply')
def withdraw(app_id):
    """Withdraw an application (§5.6)."""
    application = _own_application_or_none(app_id)
    if application is None:
        return _problem(404, 'unknown_application', app_id)
    if not application.can_transition('withdrawn'):
        return _problem(409, 'illegal_state',
                        'Cannot withdraw from status %s'
                        % application.status)
    services.transition(application, 'withdrawn')
    audit.record('application.withdrawn',
                 subject={'application_id': app_id},
                 actor={'kind': 'agent', 'id': g.dac_agent})
    db.session.commit()
    return jsonify({'application_id': app_id, 'status': 'withdrawn'})


# --------------------------------------------------------------------------
# Clearinghouse: access token + download (§6.3)
# --------------------------------------------------------------------------

# 提示物の外側検証と配列抽出は presentation.verify_presentation() に共有化した
# (分冊05 §11 / RDC-AAP-01 §6.3・§11.2.2)。access-token と registered-access は
# 同一の検証器を用いる。


def _verify_dac_visa(raw):
    """Verify a Visa issued by THIS DAC (signature via our jwks + active
    status). Returns the payload. The dataset match (§6.3 手順4) is done by
    the caller against the **raw** value (分冊05 §11.3)."""
    try:
        pub_jwk = signing.public_jwks()['keys'][0]
        payload = pyjwt.decode(
            raw, jwk_to_public_key(pub_jwk), algorithms=['ES256'],
            options={'verify_aud': False})
    except pyjwt.ExpiredSignatureError:
        raise AuthError(403, 'visa_expired', 'Visa has expired')
    except Exception as ex:
        raise AuthError(403, 'invalid_visa',
                        'Visa verification failed: %s' % ex)
    row = DacVisa.query.filter_by(jti=payload.get('jti')).first()
    if row is None or row.current_status() != 'active':
        raise AuthError(403, 'visa_revoked_or_unknown',
                        'Visa is not active')
    return payload


@blueprint_api.route('/datasets/<path:dataset_id>/access-token',
                     methods=['POST'])
@require_rags_token(scope='rags:retrieve')
def access_token(dataset_id):
    """Exchange a Grant Presentation for a signed download URL (§6.3,
    path form — subject to proxy path mangling for URL-shaped ids)."""
    return _access_token_impl(dataset_id)


@blueprint_api.route('/access-token', methods=['POST'])
@require_rags_token(scope='rags:retrieve')
def access_token_body():
    """Body form: ``POST /access-token`` with
    ``{"dataset_id": "...", "presentation": "..."}`` — recommended for
    URL-shaped identifiers (avoids proxy %2F decoding/slash merging)."""
    body = request.get_json(silent=True) or {}
    raw = body.get('dataset_id') or ''
    if not raw:
        return _problem(400, 'missing_dataset_id',
                        'dataset_id required in the JSON body')
    return _access_token_impl(raw)


def _access_token_impl(raw_dataset_id):
    """Shared §6.3 processing; dataset id resolved via _find_offer."""
    offer_row, dataset_id = _find_offer(raw_dataset_id)
    if offer_row is None:
        return _problem(404, 'unknown_dataset',
                        'No policy registered for %s' % dataset_id)
    body = request.get_json(silent=True) or {}
    try:
        # 提示物の外側検証 + 配列抽出は共有検証器 (presentation.py) で行う。
        # §11.2 の読み順 (credentials[] 優先, 無ければ単数 credential) も内包。
        if body.get('presentation'):
            pmeta, elements = presentation.verify_presentation(
                body['presentation'], expected_purpose='data-retrieval')
            presentation_absent = False
        elif body.get('visa') and \
                current_app.config['WEKO_DAC_ALLOW_DIRECT_VISA']:
            # 移行期フォールバック (§6.3): 監査に presentation_absent を立てる
            pmeta = {'sub': None, 'presented_by': g.dac_agent}
            elements = [{'raw': body['visa'],
                         'credential_format': 'ga4gh-visa+jwt',
                         'credential_type': None, 'credential_id': None}]
            presentation_absent = True
        else:
            return _problem(400, 'presentation_required',
                            'Body must contain "presentation"')
        # 提示物の sub / presented_by (§6.3 手順5-6)
        if pmeta['sub'] is not None:
            if pmeta['sub'] != g.dac_sub:
                raise AuthError(403, 'subject_mismatch',
                                'presentation.sub != token.sub')
            if pmeta['presented_by'] != g.dac_agent:
                raise AuthError(403, 'agent_mismatch',
                                'presented_by != token act.sub')
        # 内包クレデンシャルを各要素検証し、当該 dataset の DataAccessGrant を
        # 探す (§6.3 手順2-4)。判定値は原本 raw から (分冊05 §11.3)。
        visa_payload = None
        used_cid = None
        grant_seen = False
        cred_types = []
        for el in elements:
            fmt = el.get('credential_format') or 'ga4gh-visa+jwt'
            if fmt != 'ga4gh-visa+jwt':
                raise AuthError(400, 'unsupported_presentation_type',
                                'credential_format %s not yet supported' % fmt)
            p = _verify_dac_visa(el['raw'])
            csub = p.get('sub')
            if pmeta['sub'] is not None:
                if csub and csub != pmeta['sub']:
                    raise AuthError(403, 'subject_mismatch',
                                    'credential.sub != presentation.sub')
            elif csub != g.dac_sub:
                raise AuthError(403, 'subject_mismatch',
                                'credential.sub != token.sub')
            v = p.get('ga4gh_visa_v1') or {}
            cred_types.append(presentation.rdc_type(v.get('type')))
            # 発行者の権限 (§3.2 / §6.3 手順3)。未強制の間は素通り。
            presentation.check_issuer_authority(
                v.get('type'), v.get('source'),
                (offer_row.offer or {}).get('assigner'))
            if v.get('type') == 'ControlledAccessGrants':
                grant_seen = True
                if v.get('value') == dataset_id:
                    visa_payload = p
                    used_cid = el.get('credential_id')
                    break
        if visa_payload is None:
            if grant_seen:
                raise AuthError(403, 'visa_dataset_mismatch',
                                'Visa is not for this dataset')
            raise AuthError(403, 'requirements_not_met',
                            'no DataAccessGrant for this dataset was '
                            'presented')
        meta = {'presentation_absent': presentation_absent,
                'credential_format': 'ga4gh-visa+jwt',
                'credential_id': used_cid,
                'credential_types': cred_types,
                'purpose': pmeta.get('purpose')}
    except AuthError as err:
        db.session.rollback()
        return err.as_response()

    if not offer_row.distribution_uri:
        return _problem(404, 'no_distribution',
                        'No data registered for this dataset')
    token = signing.sign_download_token(
        dataset_id, g.dac_sub, visa_payload.get('rdc_agreement'))
    audit.record('data.accessed',
                 subject={'agreement_uid': visa_payload.get('rdc_agreement'),
                          'dataset_id': dataset_id},
                 actor={'kind': 'agent', 'id': g.dac_agent,
                        'on_behalf_of': g.dac_sub},
                 payload={'access_class': offer_row.access_class,
                          'purpose': meta['purpose'],
                          'credential_format': meta['credential_format'],
                          'credential_types': meta['credential_types'],
                          'credential_id': meta['credential_id'],
                          'presentation_absent':
                          meta['presentation_absent']})
    db.session.commit()
    return jsonify({
        'download_url': '{0}/api/dac/v1/download?token={1}'.format(
            current_app.config['WEKO_DAC_ENTITY_ID'], token),
        'file_name': _distribution_file_name(offer_row),
        'expires_in': current_app.config['WEKO_DAC_DOWNLOAD_URL_TTL'],
        'checksum': ({'algorithm': 'sha256', 'value': offer_row.checksum}
                     if offer_row.checksum else None),
    })


def _distribution_file_name(offer_row):
    """Best-effort file name from the Offer's distribution URI (path or URL)."""
    uri = (offer_row.distribution_uri or '').split('?')[0].rstrip('/')
    return uri.rsplit('/', 1)[-1] if uri else None


@blueprint_api.route('/registered-access', methods=['POST'])
@require_rags_token(scope='rags:apply')
def registered_access():
    """registered 層の自動許諾 (§11.2)。Passport の資格 Visa を決定的に検証し、
    Offer 要件を満たせばその場で Agreement + Visa を発行して Wallet に格納する。"""
    body = request.get_json(silent=True) or {}
    raw = body.get('dataset_id') or ''
    if not raw:
        return _problem(400, 'missing_dataset_id',
                        'dataset_id required in the JSON body')
    _offer, dataset_id = _find_offer(raw)
    # v0.4: 入力は Credential Wallet の提示物。移行期は passport も受理 (§11.2.2)。
    # 利用目的は intended_use (旧名 purpose も移行期は受理)。
    intended_use = body.get('intended_use')
    if intended_use is None:
        intended_use = body.get('purpose')
    try:
        _app, issued = registered.grant_registered(
            dataset_id, g.dac_sub, g.dac_agent,
            presentation_jws=body.get('presentation'),
            passport_jwt=body.get('passport'),
            intended_use=intended_use or {},
            callback_url=body.get('callback_url'))
    except (registered.RegError, AuthError) as err:
        db.session.rollback()
        return err.as_response()
    agreement, visa = issued[0]
    resp = jsonify({
        'granted': True,
        'agreement_uid': agreement.uid,
        'wallet_credential_id': visa.wallet_credential_id,
        'valid_until': visa.expires_at.strftime('%Y-%m-%d'),
    })
    resp.status_code = 201
    return resp


def _open_impl(raw):
    offer_row, dataset_id = _find_offer(raw)
    if offer_row is None:
        return _problem(404, 'unknown_dataset',
                        'No policy registered for %s' % dataset_id)
    if offer_row.access_class != 'open':
        return _problem(403, 'not_open',
                        'accessClass is "%s"; open-data serves open datasets '
                        'only' % offer_row.access_class)
    if not offer_row.distribution_uri:
        return _problem(404, 'no_distribution',
                        'No data registered for this dataset')
    audit.record('data.accessed',
                 subject={'dataset_id': dataset_id},
                 actor={'kind': 'public', 'id': 'anonymous'},
                 payload={'access_class': 'open', 'access_route': 'open',
                          'credential_types': [], 'purpose': None,
                          'presentation_absent': True})
    db.session.commit()
    uri = offer_row.distribution_uri
    if uri.startswith('http://') or uri.startswith('https://'):
        return redirect(uri)
    try:
        resp = send_file(uri, as_attachment=True)
        if offer_row.checksum:
            resp.headers['X-Checksum-Sha256'] = offer_row.checksum
        return resp
    except Exception as ex:
        return _problem(500, 'delivery_failed', str(ex))


@blueprint_api.route('/datasets/<path:dataset_id>/open-data', methods=['GET'])
def open_data(dataset_id):
    """open 層の直接取得 (§11.1、認証なし)。checksum は X-Checksum-Sha256 で返す。"""
    return _open_impl(dataset_id)


@blueprint_api.route('/open-data', methods=['GET'])
def open_data_query():
    """クエリ形式: ``GET /open-data?dataset_id=<url-encoded>`` (URL型ID向け)。"""
    return _open_impl(request.args.get('dataset_id', ''))


def _open_access_impl(raw):
    """open 層の取得情報 (§11.1、認証なし)。``access-token`` と**同一形式**の JSON を
    返す — ``download_url`` (controlled と同じ署名付き ``/download`` を指す) +
    ``file_name`` + ``checksum {algorithm, value}``。DG は区分に依らず同じ場所・
    同じ形で checksum を読める (DG 照会 O-1/O-3)。認証・提示は不要、access-token と
    ``/download`` の検証経路には触れない。"""
    offer_row, dataset_id = _find_offer(raw)
    if offer_row is None:
        return _problem(404, 'unknown_dataset',
                        'No policy registered for %s' % dataset_id)
    if offer_row.access_class != 'open':
        return _problem(403, 'not_open',
                        'accessClass is "%s"; open-access serves open '
                        'datasets only' % offer_row.access_class)
    if not offer_row.distribution_uri:
        return _problem(404, 'no_distribution',
                        'No data registered for this dataset')
    # 許諾なし: subject=anonymous, agreement=None の署名付きダウンロードトークン
    token = signing.sign_download_token(dataset_id, 'anonymous', None)
    # §11.1 監査: data.accessed を記録 (提示履歴=Wallet には残さない O-4)
    audit.record('data.accessed',
                 subject={'dataset_id': dataset_id},
                 actor={'kind': 'public', 'id': 'anonymous'},
                 payload={'access_class': 'open', 'access_route': 'open',
                          'credential_types': [], 'purpose': None,
                          'presentation_absent': True})
    db.session.commit()
    return jsonify({
        'download_url': '{0}/api/dac/v1/download?token={1}'.format(
            current_app.config['WEKO_DAC_ENTITY_ID'], token),
        'file_name': _distribution_file_name(offer_row),
        'expires_in': current_app.config['WEKO_DAC_DOWNLOAD_URL_TTL'],
        'checksum': ({'algorithm': 'sha256', 'value': offer_row.checksum}
                     if offer_row.checksum else None),
    })


@blueprint_api.route('/datasets/<path:dataset_id>/open-access',
                     methods=['GET'])
def open_access(dataset_id):
    """open 層の取得情報 (§11.1、認証なし)。access-token と同形の JSON を返す。"""
    return _open_access_impl(dataset_id)


@blueprint_api.route('/open-access', methods=['GET'])
def open_access_query():
    """クエリ形式: ``GET /open-access?dataset_id=<url-encoded>`` (URL型ID向け)。"""
    return _open_access_impl(request.args.get('dataset_id', ''))


@blueprint_api.route('/download', methods=['GET'])
def download():
    """Serve restricted data against a signed download token."""
    token = request.args.get('token', '')
    try:
        payload = signing.verify_download_token(token)
    except Exception as ex:
        return _problem(403, 'invalid_download_token', str(ex))
    offer_row = DacOffer.query.filter_by(
        dataset_id=payload.get('dataset')).first()
    if offer_row is None or not offer_row.distribution_uri:
        return _problem(404, 'no_distribution', 'Data not found')
    uri = offer_row.distribution_uri
    if uri.startswith('http://') or uri.startswith('https://'):
        return redirect(uri)
    try:
        return send_file(uri, as_attachment=True)
    except Exception as ex:
        return _problem(500, 'delivery_failed', str(ex))
