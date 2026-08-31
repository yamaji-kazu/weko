# -*- coding: utf-8 -*-
"""Business logic for weko-dac: offer templates, application intake,
decisions, agreement/visa issuance, wallet deposit and callbacks."""

import calendar
import json
import os
import uuid
from datetime import datetime, timedelta

import jsonschema
import requests
from flask import current_app
from invenio_db import db

from . import allowlist, audit, signing
from .auth import verify_jws
from .models import (DacAgreement, DacApplication, DacEventOutbox,
                     DacMessage, DacOffer, DacVisa, new_id)

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'schemas',
                            'application.json')
with open(_SCHEMA_PATH) as _fp:
    APPLICATION_SCHEMA = json.load(_fp)


class IntakeError(Exception):
    """Application intake rejection."""

    def __init__(self, status, title, detail=''):
        super(IntakeError, self).__init__(detail or title)
        self.status = status
        self.title = title
        self.detail = detail


# --------------------------------------------------------------------------
# Offer template (§4.1)
# --------------------------------------------------------------------------

_DUO_IRI = 'http://purl.obolibrary.org/obo/DUO_{0}'


def offer_from_template(dataset_id, template):
    """Generate an ODRL Offer (spec vol.05 §3) from a condition template.

    Template keys: access_class, duo_codes[], period (xsd:duration or
    date), storage_class, ethics_required, duties[], prohibitions[],
    spatial.
    """
    profile = current_app.config['WEKO_DAC_ODRL_PROFILE']
    constraints = []
    for code in template.get('duo_codes') or []:
        num = code.split(':')[-1]
        constraints.append({
            'leftOperand': 'purpose', 'operator': 'isA',
            'rightOperand': {'@id': _DUO_IRI.format(num)}})
    if template.get('period'):
        period = template['period']
        rtype = 'xsd:duration' if str(period).startswith('P') else 'xsd:date'
        constraints.append({
            'leftOperand': 'dateTime', 'operator': 'lteq',
            'rightOperand': {'@value': period, '@type': rtype}})
    if template.get('storage_class'):
        constraints.append({
            'leftOperand': 'rdc:storageClass', 'operator': 'isA',
            'rightOperand': {'@id': template['storage_class']}})
    if template.get('spatial'):
        constraints.append({
            'leftOperand': 'spatial', 'operator': 'eq',
            'rightOperand': template['spatial']})
    if template.get('ethics_required'):
        constraints.append({
            'leftOperand': 'rdc:ethicsApproval', 'operator': 'eq',
            'rightOperand': True})
    duties = [{'action': d} for d in (template.get('duties') or [])]
    prohibitions = [{'action': p}
                    for p in (template.get('prohibitions') or [])]
    return {
        '@context': ['http://www.w3.org/ns/odrl.jsonld', profile],
        '@type': 'Offer',
        'uid': '{0}/policies/off-{1}'.format(
            current_app.config['WEKO_DAC_ENTITY_ID'], uuid.uuid4().hex[:12]),
        'profile': profile,
        'rdc:accessClass': template.get('access_class', 'controlled'),
        'assigner': current_app.config['WEKO_DAC_DAC_ID'],
        'target': dataset_id,
        'permission': [{
            'action': 'use',
            'constraint': constraints,
            'duty': duties,
        }],
        'prohibition': prohibitions,
    }


# --------------------------------------------------------------------------
# Application intake (§5.2)
# --------------------------------------------------------------------------

def _verify_passport(passport_jwt):
    """[DEMO] Verify the passport JWT signature against the demo IdP.

    In DEMO-10 the GA4GH Passport is simplified to IdP attribute claims;
    a verification failure is therefore recorded rather than fatal.
    """
    issuer = current_app.config.get('WEKO_DAC_OIDC_ISSUER') or None
    jwks = current_app.config.get('WEKO_DAC_OIDC_JWKS_URL')
    if not jwks and issuer:
        jwks = issuer.rstrip('/') + '/protocol/openid-connect/certs'
    try:
        payload = verify_jws(passport_jwt, jwks, issuer=issuer)
        visas = payload.get('ga4gh_passport_v1') or []
        return {'result': 'valid',
                'sub': payload.get('sub'),
                'visa_count': len(visas)}
    except Exception as ex:
        return {'result': 'invalid', 'detail': str(ex)}


def intake_application(payload, researcher_sub, agent_id):
    """Validate and register an application. Returns the model instance."""
    # 0. static allowlist (DEMO-20 §4 / DEMO-24 §3 — Trust Chain 代替)
    allowlist_result = allowlist.check_agent(agent_id)
    if allowlist_result == 'denied':
        raise IntakeError(403, 'agent_not_allowlisted',
                          'Agent %s is not in the static allowlist'
                          % agent_id)

    # 1. envelope schema
    try:
        jsonschema.validate(payload, APPLICATION_SCHEMA)
    except jsonschema.ValidationError as err:
        raise IntakeError(400, 'invalid_application',
                          'Envelope schema violation: %s' % err.message)
    if payload.get('resource_type') != 'dataset':
        raise IntakeError(
            422, 'unsupported_resource_type',
            'Phase 1 implements resource_type "dataset" only')

    # 2. dataset existence / access class
    dataset_results = []
    for req in payload['requests']:
        dataset_id = req.get('dataset_id') or req.get('resource_id')
        if not dataset_id:
            raise IntakeError(400, 'invalid_application',
                              'requests[].dataset_id required')
        offer_row = DacOffer.query.filter_by(dataset_id=dataset_id).first()
        if offer_row is None:
            raise IntakeError(
                404, 'unknown_dataset',
                'No policy registered for %s' % dataset_id)
        entry = {'dataset_id': dataset_id,
                 'access_class': offer_row.access_class}
        if offer_row.access_class == 'open':
            entry['auto_granted'] = True
        # 3. ODRL Request syntax check (profile-level shallow validation)
        odrl_request = req.get('odrl_request') or {}
        if odrl_request.get('@type') != 'Request':
            raise IntakeError(400, 'invalid_odrl',
                              'odrl_request.@type must be "Request"')
        if not odrl_request.get('permission'):
            raise IntakeError(400, 'invalid_odrl',
                              'odrl_request.permission required')
        dataset_results.append(entry)

    # 4. passport verification ([DEMO] non-fatal)
    passport_result = _verify_passport(
        (payload.get('evidence') or {}).get('passport') or '')

    # 5. accept
    application = DacApplication(
        application_id='app-{0}-{1}'.format(
            datetime.utcnow().strftime('%Y'), uuid.uuid4().hex[:8]),
        status='submitted',
        resource_type=payload['resource_type'],
        researcher_sub=researcher_sub,
        agent_id=agent_id,
        callback_url=payload.get('callback_url'),
        madmp_id=((payload.get('madmp_ref') or {}).get('dmp_id') or
                  {}).get('identifier'),
        payload=payload,
        verification={
            # [DEMO] Trust Chain is replaced by the static allowlist
            # (DEMO-20 §4); trust_marks / dpop not verified
            'trust_chain': 'static_allowlist',
            'allowlist': allowlist_result,
            'trust_marks': [],
            'delegation': 'valid',
            'passport': passport_result,
            'datasets': dataset_results,
        },
    )
    db.session.add(application)
    audit.record('application.received',
                 subject={'application_id': application.application_id,
                          'madmp': application.madmp_id},
                 actor={'kind': 'agent', 'id': agent_id},
                 payload_digest=audit.digest(payload))
    audit.record('verification.completed',
                 subject={'application_id': application.application_id},
                 actor={'kind': 'service',
                        'id': current_app.config['WEKO_DAC_ENTITY_ID']},
                 payload=application.verification)
    db.session.commit()
    # submitted -> validating -> under_review (machine validation done)
    transition(application, 'validating')
    transition(application, 'under_review')
    db.session.commit()
    return application


# --------------------------------------------------------------------------
# State machine + callbacks (§5.3 / §5.7)
# --------------------------------------------------------------------------

def transition(application, new_status, extra_event=None):
    """Transition state and enqueue a status_changed callback."""
    if not application.can_transition(new_status):
        raise ValueError('Illegal transition %s -> %s'
                         % (application.status, new_status))
    application.status = new_status
    enqueue_event(application, 'application.status_changed',
                  {'new_status': new_status})
    if extra_event:
        enqueue_event(application, extra_event[0], extra_event[1])


def enqueue_event(application, event_type, extra=None):
    """Queue a signed callback event for the DG (§5.7)."""
    if not application.callback_url:
        return
    event = {
        'event_id': 'evt-' + uuid.uuid4().hex,
        'event_type': event_type,
        'application_id': application.application_id,
        'occurred_at': datetime.utcnow().isoformat() + 'Z',
    }
    event.update(extra or {})
    db.session.add(DacEventOutbox(
        event_id=event['event_id'],
        application_id=application.application_id,
        callback_url=application.callback_url,
        event=event))


# --------------------------------------------------------------------------
# Messages (§5.5)
# --------------------------------------------------------------------------

def add_message(application, sender, mtype, body, author_kind='human',
                structured=None, in_reply_to=None):
    """Append a message; handle needs_info transitions and callbacks."""
    msg = DacMessage(
        message_id='msg-' + uuid.uuid4().hex[:12],
        application_id=application.application_id,
        sender=sender, author_kind=author_kind, type=mtype,
        body=body, structured=structured, in_reply_to=in_reply_to)
    db.session.add(msg)
    if sender == 'dac' and mtype in ('inquiry', 'proposal'):
        application.negotiation_rounds += 1
        if application.status == 'under_review':
            transition(application, 'needs_info')
        enqueue_event(application, 'application.message_added',
                      {'message_id': msg.message_id})
    elif sender == 'requester' and mtype == 'answer':
        if application.status == 'needs_info':
            transition(application, 'under_review')
    audit.record('message.sent',
                 subject={'application_id': application.application_id},
                 actor={'kind': 'human' if author_kind == 'human'
                        else 'agent', 'id': sender},
                 payload={'message_id': msg.message_id, 'type': mtype})
    return msg


# --------------------------------------------------------------------------
# Grant issuance (§6)
# --------------------------------------------------------------------------

def _agreement_from(offer_row, req, application, conditions):
    """Build the ODRL Agreement JSON-LD (§6.1 / vol.05 §6)."""
    profile = current_app.config['WEKO_DAC_ODRL_PROFILE']
    odrl_request = req.get('odrl_request') or {}
    permission = []
    for perm in odrl_request.get('permission') or []:
        p = {'action': perm.get('action', 'use'),
             'constraint': perm.get('constraint') or [],
             'duty': list(perm.get('duty') or [])}
        for cond in conditions or []:
            p['duty'].append({'action': 'rdc:condition',
                              'rdc:description': cond})
        permission.append(p)
    researcher = ((application.payload.get('applicant') or {})
                  .get('researcher') or {})
    assignee = researcher.get('orcid') or application.researcher_sub
    uid = '{0}/agreements/agr-{1}-{2}'.format(
        current_app.config['WEKO_DAC_ENTITY_ID'],
        application.application_id, uuid.uuid4().hex[:6])
    return {
        '@context': ['http://www.w3.org/ns/odrl.jsonld', profile],
        '@type': 'Agreement',
        'uid': uid,
        'profile': profile,
        'assigner': current_app.config['WEKO_DAC_DAC_ID'],
        'assignee': assignee,
        'rdc:appliedBy': application.agent_id,
        'rdc:agreementBasis': {
            'offer': offer_row.offer.get('uid'),
            'request': odrl_request.get('uid'),
        },
        'rdc:madmp': application.madmp_id,
        'target': offer_row.dataset_id,
        'permission': permission,
        'prohibition': offer_row.offer.get('prohibition') or [],
    }


def _grant_period_end(application):
    period = ((application.payload.get('purpose') or {})
              .get('period') or {})
    end = period.get('end')
    if end:
        try:
            return datetime.strptime(end[:10], '%Y-%m-%d') + \
                timedelta(hours=23, minutes=59)
        except ValueError:
            pass
    return datetime.utcnow() + timedelta(days=365)


def issue_grants(application, conditions=None):
    """Issue Agreement + Visa per approved dataset; queue wallet deposit.

    Called after an officer approval. Returns list of (agreement, visa).
    """
    issued = []
    valid_until = _grant_period_end(application)
    valid_until_ts = calendar.timegm(valid_until.utctimetuple())
    # Holder identifier = access-token ``sub`` (the Keycloak user UUID
    # in the demo — NOT eppn/ORCID; see DEMO-11 §6 / DEMO-12 §0).
    # This keeps visa.sub == presentation.sub == token.sub verifiable
    # end-to-end (RDC-AAP-01 §6.3 items 3). The ORCID remains the
    # assignee of the ODRL Agreement (vol.05 §6).
    subject = application.researcher_sub

    for req in application.payload.get('requests') or []:
        dataset_id = req.get('dataset_id') or req.get('resource_id')
        offer_row = DacOffer.query.filter_by(dataset_id=dataset_id).first()
        if offer_row is None:
            continue
        agreement_doc = _agreement_from(offer_row, req, application,
                                        conditions)
        agreement_jws = signing.sign_agreement(agreement_doc)
        agreement = DacAgreement(
            uid=agreement_doc['uid'],
            application_id=application.application_id,
            dataset_id=dataset_id,
            agreement=agreement_doc,
            agreement_jws=agreement_jws)
        db.session.add(agreement)
        jti, visa_jwt = signing.issue_visa(
            subject, dataset_id, agreement_doc['uid'], valid_until_ts)
        visa = DacVisa(
            jti=jti,
            application_id=application.application_id,
            agreement_uid=agreement_doc['uid'],
            subject=subject,
            dataset_id=dataset_id,
            visa_jwt=visa_jwt,
            expires_at=valid_until)
        db.session.add(visa)
        audit.record('agreement.issued',
                     subject={'application_id': application.application_id,
                              'agreement_uid': agreement_doc['uid']},
                     actor={'kind': 'service',
                            'id': current_app.config['WEKO_DAC_DAC_ID']},
                     payload_digest=audit.digest(agreement_doc))
        audit.record('visa.issued',
                     subject={'application_id': application.application_id,
                              'jti': jti},
                     actor={'kind': 'service',
                            'id': current_app.config['WEKO_DAC_DAC_ID']})
        issued.append((agreement, visa))
    return issued


# --------------------------------------------------------------------------
# Outbound: service token, wallet deposit, callback delivery
# --------------------------------------------------------------------------

def _service_verify():
    ca = current_app.config.get('WEKO_DAC_TLS_CA_BUNDLE') or ''
    return ca if ca else False


def get_service_token():
    """client_credentials token for this DAC service. [DEMO] client_secret
    is accepted (production: private_key_jwt + DPoP)."""
    token_url = current_app.config.get('WEKO_DAC_TOKEN_URL')
    if not token_url:
        return None
    resp = requests.post(
        token_url,
        data={'grant_type': 'client_credentials',
              'client_id': current_app.config['WEKO_DAC_CLIENT_ID'],
              'client_secret': current_app.config['WEKO_DAC_CLIENT_SECRET']},
        timeout=10, verify=_service_verify())
    resp.raise_for_status()
    return resp.json()['access_token']


def deposit_visa_to_wallet(visa):
    """Deposit an issued Visa into the researcher's Grant Wallet
    (§6.2 / RDC-AAP-04 §5.3.2). Returns True on success."""
    base = current_app.config.get('WEKO_DAC_WALLET_API_BASE')
    if not base:
        current_app.logger.warning(
            'weko-dac: WEKO_DAC_WALLET_API_BASE not set — Visa %s kept '
            'available via the application resource only (fallback of '
            'RDC-AAP-01 §6.2)', visa.jti)
        return False
    token = get_service_token()
    if not token:
        return False
    from urllib.parse import quote
    url = '{0}/holders/{1}/credentials'.format(
        base.rstrip('/'), quote(visa.subject, safe=''))
    body = {
        'type': 'ControlledAccessGrants',
        'resource': visa.dataset_id,
        'issuer': current_app.config['WEKO_DAC_ENTITY_ID'],
        'visa_jwt': visa.visa_jwt,
        'agreement_uid': visa.agreement_uid,
        'valid_from': visa.issued_at.strftime('%Y-%m-%d'),
        'valid_until': visa.expires_at.strftime('%Y-%m-%d'),
    }
    resp = requests.post(
        url, json=body, timeout=15, verify=_service_verify(),
        headers={'Authorization': 'Bearer ' + token})
    if resp.status_code in (200, 201):
        data = {}
        try:
            data = resp.json()
        except ValueError:
            pass
        visa.wallet_credential_id = data.get('credential_id')
        visa.wallet_deposited = True
        audit.record('visa.deposited',
                     subject={'jti': visa.jti,
                              'wallet_credential_id':
                                  visa.wallet_credential_id},
                     actor={'kind': 'service',
                            'id': current_app.config['WEKO_DAC_DAC_ID']})
        return True
    current_app.logger.error(
        'weko-dac: wallet deposit failed (%s): %s',
        resp.status_code, resp.text[:500])
    return False


def deliver_event(outbox_row):
    """Deliver one callback event to the DG (§5.7). Returns True/False."""
    headers = {'Content-Type': 'application/json'}
    try:
        token = get_service_token()
        if token:
            headers['Authorization'] = 'Bearer ' + token
    except Exception:
        current_app.logger.exception('weko-dac: service token failed')
    try:
        resp = requests.post(outbox_row.callback_url, json=outbox_row.event,
                             timeout=15, headers=headers,
                             verify=_service_verify())
        if 200 <= resp.status_code < 300:
            outbox_row.delivered_at = datetime.utcnow()
            return True
    except Exception:
        current_app.logger.exception('weko-dac: callback delivery failed')
    schedule = current_app.config.get(
        'WEKO_DAC_CALLBACK_RETRY_SCHEDULE') or [300]
    delay = schedule[min(outbox_row.attempts, len(schedule) - 1)]
    outbox_row.attempts += 1
    outbox_row.next_attempt_at = datetime.utcnow() + \
        timedelta(seconds=delay)
    return False


# --------------------------------------------------------------------------
# Officer decisions (§7.3)
# --------------------------------------------------------------------------

def execute_decision(application, decision, reason, officer_id,
                     conditions=None, inquiry_body=None,
                     assessment_row=None):
    """Execute an officer decision (Phase 1: human decides everything).

    decision: approve | approve_with_conditions | reject | request_info
    Returns the created DacDecision row. Raises ValueError on illegal
    states.
    """
    from .models import DacDecision

    if application.status == 'needs_info' and decision != 'request_info':
        # Officer may decide while an inquiry is pending.
        transition(application, 'under_review')
    if application.status != 'under_review':
        raise ValueError('No decision possible in status %s'
                         % application.status)

    ai_reco = None
    if assessment_row is not None:
        ai_reco = (assessment_row.assessment.get('recommendation')
                   or {}).get('decision')
    row = DacDecision(
        application_id=application.application_id,
        decision=decision,
        reason=reason,
        conditions=conditions or [],
        decided_by=officer_id,
        assessment_id=assessment_row.id if assessment_row else None,
        diverges_from_ai=bool(ai_reco and ai_reco != decision))
    db.session.add(row)
    audit.record('decision.made',
                 subject={'application_id': application.application_id},
                 actor={'kind': 'human', 'id': officer_id},
                 payload={'decision': decision,
                          'diverges_from_ai': row.diverges_from_ai,
                          'assessment_id': row.assessment_id})

    if decision in ('approve', 'approve_with_conditions'):
        transition(application, 'approved')
        issued = issue_grants(application, conditions=conditions)
        transition(application, 'agreement_issued')
        # Wallet deposit (§6.2): confirm before the agreement.issued
        # callback; failures fall back to the application resource and
        # are retried by the periodic task.
        for agreement, visa in issued:
            try:
                deposit_visa_to_wallet(visa)
            except Exception:
                current_app.logger.exception(
                    'weko-dac: wallet deposit error for %s', visa.jti)
            enqueue_event(application, 'agreement.issued', {
                'agreement_uid': agreement.uid,
                'dataset_id': agreement.dataset_id,
                'visa_jti': visa.jti,
                'wallet_credential_id': visa.wallet_credential_id,
                'wallet_deposited': visa.wallet_deposited,
            })
        transition(application, 'active')
    elif decision == 'reject':
        transition(application, 'rejected')
    elif decision == 'request_info':
        add_message(application, 'dac', 'inquiry',
                    inquiry_body or reason, author_kind='human')
    else:
        raise ValueError('Unknown decision %s' % decision)
    db.session.commit()
    return row


def revoke_grant(application, reason, officer_id):
    """Revoke an active grant (visa revocation + callbacks)."""
    if application.status != 'active':
        raise ValueError('Only active grants can be revoked')
    visas = DacVisa.query.filter_by(
        application_id=application.application_id).all()
    for v in visas:
        if v.status == 'active':
            v.status = 'revoked'
            audit.record('visa.revoked',
                         subject={'jti': v.jti},
                         actor={'kind': 'human', 'id': officer_id},
                         payload={'reason': reason})
    transition(application, 'revoked',
               extra_event=('grant.revoked', {'reason': reason}))
    db.session.commit()
