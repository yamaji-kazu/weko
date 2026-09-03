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

from . import allowlist, audit, services, signing
from .auth import (AuthError, jwk_to_public_key, require_rags_token,
                   verify_jws)
from .models import (DacAgreement, DacApplication, DacMessage, DacOffer,
                     DacPresentationJti, DacVisa)

blueprint_wellknown = Blueprint('weko_dac_wellknown', __name__, template_folder='templates')

blueprint_api = Blueprint('weko_dac_api', __name__, url_prefix='/dac/v1')


def _problem(status, title, detail=''):
    resp = jsonify({'type': 'about:blank', 'title': title,
                    'status': status, 'detail': detail})
    resp.status_code = status
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

def _verify_presentation(presentation, dataset_id):
    """Verify a Grant Presentation; returns (visa_payload, meta).

    Dispatches on the JWS header ``typ`` (RDC-AAP-04 §8.3 forward-compat:
    new presentation formats plug in beside 'rdc-gp+jwt')."""
    try:
        header = pyjwt.get_unverified_header(presentation)
    except Exception as ex:
        raise AuthError(400, 'invalid_presentation',
                        'Malformed presentation: %s' % ex)
    typ = header.get('typ')
    handlers = current_app.config['WEKO_DAC_PRESENTATION_TYPES']
    if typ not in handlers:
        raise AuthError(400, 'unsupported_presentation_type',
                        'typ %s not accepted' % typ)
    # Expected Presentation audience (§6.3). Defaults to the DAC identifier
    # (WEKO_DAC_PRESENTATION_AUD → WEKO_DAC_DAC_ID); agreed with DG/Wallet.
    entity_id = current_app.config.get('WEKO_DAC_PRESENTATION_AUD') \
        or current_app.config['WEKO_DAC_ENTITY_ID']
    # Wallet trust: static allowlist (DEMO-24 §3) supplies the wallet's
    # jwks (inline or by jwks_uri); config URL is the fallback.
    inline_keys = allowlist.wallet_inline_jwks()
    if inline_keys:
        try:
            header = pyjwt.get_unverified_header(presentation)
            key = None
            for k in inline_keys:
                if not header.get('kid') or k.get('kid') == header['kid']:
                    key = k
                    break
            payload = pyjwt.decode(
                presentation, jwk_to_public_key(key),
                algorithms=['ES256', 'RS256'], audience=entity_id)
        except AuthError:
            raise
        except Exception as ex:
            raise AuthError(401, 'invalid_presentation',
                            'Presentation verification failed: %s' % ex)
    else:
        wallet_jwks = allowlist.wallet_jwks_url()
        if not wallet_jwks:
            raise AuthError(503, 'wallet_not_configured',
                            'No wallet jwks (allowlist or '
                            'WEKO_DAC_WALLET_JWKS_URL)')
        payload = verify_jws(presentation, wallet_jwks, audience=entity_id)
    wallet_entity = allowlist.wallet_entity()
    if wallet_entity and payload.get('iss') != wallet_entity['entity_id']:
        raise AuthError(403, 'unknown_wallet',
                        'Presentation issuer %s is not the allowlisted '
                        'wallet' % payload.get('iss'))
    # freshness (exp <= iat + 300 already enforced by wallet; re-check age)
    max_age = current_app.config['WEKO_DAC_PRESENTATION_MAX_AGE']
    iat = payload.get('iat') or 0
    if time.time() - iat > max_age:
        raise AuthError(401, 'presentation_expired',
                        'Presentation older than %ds' % max_age)
    # replay prevention
    jti = payload.get('jti')
    if not jti:
        raise AuthError(400, 'invalid_presentation', 'jti missing')
    if DacPresentationJti.query.get(jti):
        raise AuthError(409, 'presentation_replayed',
                        'jti already used')
    db.session.add(DacPresentationJti(
        jti=jti, presented_by=payload.get('presented_by')))
    visa_jwt = payload.get('credential')
    if not visa_jwt:
        raise AuthError(400, 'invalid_presentation', 'credential missing')
    # presenting agent must also be allowlisted (Trust Chain 代替)
    if allowlist.check_agent(payload.get('presented_by') or '') == 'denied':
        raise AuthError(403, 'agent_not_allowlisted',
                        'presented_by %s is not in the static allowlist'
                        % payload.get('presented_by'))
    meta = {'presentation_sub': payload.get('sub'),
            'presented_by': payload.get('presented_by'),
            'credential_id': payload.get('credential_id'),
            'credential_format': 'ga4gh-visa+jwt',
            'presentation_absent': False}
    return visa_jwt, meta


def _verify_visa(visa_jwt, dataset_id):
    """Verify an inner Visa issued by this DAC. Returns its payload."""
    try:
        header = pyjwt.get_unverified_header(visa_jwt)
        pub_jwk = signing.public_jwks()['keys'][0]
        from .auth import jwk_to_public_key
        payload = pyjwt.decode(
            visa_jwt, jwk_to_public_key(pub_jwk), algorithms=['ES256'],
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
    visa_v1 = payload.get('ga4gh_visa_v1') or {}
    if visa_v1.get('value') != dataset_id:
        raise AuthError(403, 'visa_dataset_mismatch',
                        'Visa is not for this dataset')
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
        if body.get('presentation'):
            visa_jwt, meta = _verify_presentation(
                body['presentation'], dataset_id)
        elif body.get('visa') and \
                current_app.config['WEKO_DAC_ALLOW_DIRECT_VISA']:
            # transitional fallback (§6.3): audit-flagged
            visa_jwt = body['visa']
            meta = {'presentation_sub': None,
                    'presented_by': g.dac_agent,
                    'credential_id': None,
                    'credential_format': 'ga4gh-visa+jwt',
                    'presentation_absent': True}
        else:
            return _problem(400, 'presentation_required',
                            'Body must contain "presentation"')
        visa_payload = _verify_visa(visa_jwt, dataset_id)
        # subject chain checks (§6.3 items 3–4)
        if meta['presentation_sub'] is not None:
            if visa_payload.get('sub') != meta['presentation_sub']:
                raise AuthError(403, 'subject_mismatch',
                                'visa.sub != presentation.sub')
            if meta['presentation_sub'] != g.dac_sub:
                raise AuthError(403, 'subject_mismatch',
                                'presentation.sub != token.sub')
            if meta['presented_by'] != g.dac_agent:
                raise AuthError(403, 'agent_mismatch',
                                'presented_by != token act.sub')
        else:
            if visa_payload.get('sub') != g.dac_sub:
                raise AuthError(403, 'subject_mismatch',
                                'visa.sub != token.sub')
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
                 actor={'kind': 'agent', 'id': g.dac_agent},
                 payload={'presentation_absent':
                          meta['presentation_absent'],
                          'credential_format': meta['credential_format'],
                          'credential_id': meta['credential_id']})
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
