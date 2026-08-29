# -*- coding: utf-8 -*-
"""REST API blueprints for weko-dac (RDC-AAP-01 §4–6)."""

import time
from datetime import datetime
from urllib.parse import unquote

import jwt as pyjwt
from flask import (Blueprint, Response, current_app, g, jsonify, redirect,
                   request, send_file)
from invenio_db import db

from . import audit, services, signing
from .auth import AuthError, require_rags_token, verify_jws
from .models import (DacAgreement, DacApplication, DacMessage, DacOffer,
                     DacPresentationJti, DacVisa)

blueprint_wellknown = Blueprint('weko_dac_wellknown', __name__)

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

@blueprint_api.route('/datasets/<path:dataset_id>/policy',
                     methods=['GET'])
def get_policy(dataset_id):
    """Return the ODRL Offer of a dataset."""
    dataset_id = unquote(dataset_id)
    row = DacOffer.query.filter_by(dataset_id=dataset_id).first()
    if row is None:
        return _problem(404, 'unknown_dataset',
                        'No policy registered for %s' % dataset_id)
    return Response(
        response=jsonify(row.offer).get_data(),
        mimetype='application/odrl+json')


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


def _own_application_or_none(app_id):
    application = DacApplication.query.filter_by(
        application_id=app_id).first()
    if application is None:
        return None
    if application.agent_id != g.dac_agent or \
            application.researcher_sub != g.dac_sub:
        return None
    return application


@blueprint_api.route('/applications', methods=['GET'])
@require_rags_token(scope='rags:apply')
def list_applications():
    """List own applications (§5.4) — restricted to the caller's
    delegation pair (sub, act.sub)."""
    query = DacApplication.query.filter_by(
        agent_id=g.dac_agent, researcher_sub=g.dac_sub)
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
    wallet_jwks = current_app.config.get('WEKO_DAC_WALLET_JWKS_URL')
    if not wallet_jwks:
        raise AuthError(503, 'wallet_not_configured',
                        'WEKO_DAC_WALLET_JWKS_URL not set')
    entity_id = current_app.config['WEKO_DAC_ENTITY_ID']
    payload = verify_jws(presentation, wallet_jwks, audience=entity_id)
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
    """Exchange a Grant Presentation for a signed download URL (§6.3)."""
    dataset_id = unquote(dataset_id)
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

    offer_row = DacOffer.query.filter_by(dataset_id=dataset_id).first()
    if offer_row is None or not offer_row.distribution_uri:
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
        'expires_in': current_app.config['WEKO_DAC_DOWNLOAD_URL_TTL'],
        'checksum': ({'algorithm': 'sha256', 'value': offer_row.checksum}
                     if offer_row.checksum else None),
    })


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
