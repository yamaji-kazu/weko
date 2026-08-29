# -*- coding: utf-8 -*-
"""Database models for weko-dac (RDC-AAP-01)."""

from datetime import datetime

from invenio_db import db
from sqlalchemy.dialects import postgresql
from sqlalchemy_utils.types import JSONType

from .utils import new_id

JSONB = JSONType().with_variant(
    postgresql.JSONB(none_as_null=True), 'postgresql')


def _now():
    return datetime.utcnow()


#: Application state machine (RDC-AAP-01 §5.3).
APPLICATION_STATES = [
    'submitted', 'validating', 'under_review', 'needs_info',
    'approved', 'rejected', 'partially_approved',
    'agreement_issued', 'active', 'expired', 'revoked', 'withdrawn',
]

ALLOWED_TRANSITIONS = {
    'submitted': ['validating', 'withdrawn'],
    'validating': ['under_review', 'rejected', 'withdrawn'],
    'under_review': ['needs_info', 'approved', 'rejected',
                     'partially_approved', 'withdrawn'],
    'needs_info': ['under_review', 'withdrawn'],
    'approved': ['agreement_issued', 'withdrawn'],
    'partially_approved': ['agreement_issued', 'withdrawn'],
    'agreement_issued': ['active'],
    'active': ['expired', 'revoked'],
}


class DacOffer(db.Model):
    """ODRL Offer attached to a dataset (RDC-AAP-01 §4)."""

    __tablename__ = 'dac_offer'

    id = db.Column(db.Integer, primary_key=True)
    #: Persistent identifier of the dataset (DOI / IRDB URI).
    dataset_id = db.Column(db.String(255), unique=True, nullable=False,
                           index=True)
    #: open / registered / controlled
    access_class = db.Column(db.String(16), nullable=False,
                             default='controlled')
    #: Human-oriented title (for the console).
    title = db.Column(db.String(255), nullable=True)
    #: Generated ODRL Offer (JSON-LD, spec vol.05 §3).
    offer = db.Column(JSONB, nullable=False)
    #: Condition template input used to generate the Offer (§4.1).
    template = db.Column(JSONB, nullable=True)
    #: Where the restricted data actually lives (local path or URL)
    #: used by the demo clearinghouse.
    distribution_uri = db.Column(db.Text, nullable=True)
    #: sha256 of the distribution (computed at registration if local).
    checksum = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, default=_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=_now, onupdate=_now,
                           nullable=False)


class DacApplication(db.Model):
    """Data access application (RDC-AAP-01 §5)."""

    __tablename__ = 'dac_application'

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.String(64), unique=True, nullable=False,
                               index=True)
    status = db.Column(db.String(32), nullable=False, default='submitted',
                       index=True)
    resource_type = db.Column(db.String(32), nullable=False,
                              default='dataset')
    #: Researcher (delegator) identifier — token ``sub``.
    researcher_sub = db.Column(db.String(255), nullable=False, index=True)
    #: Requesting agent id — token ``act.sub`` (or ``azp`` in the demo).
    agent_id = db.Column(db.String(255), nullable=False, index=True)
    callback_url = db.Column(db.Text, nullable=True)
    madmp_id = db.Column(db.String(255), nullable=True, index=True)
    #: Full application envelope as received (spec vol.05 §5).
    payload = db.Column(JSONB, nullable=False)
    #: Per-dataset machine verification snapshot.
    verification = db.Column(JSONB, nullable=True)
    #: Negotiation round counter (§5.5).
    negotiation_rounds = db.Column(db.Integer, nullable=False, default=0)
    received_at = db.Column(db.DateTime, default=_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=_now, onupdate=_now,
                           nullable=False)

    def can_transition(self, new_status):
        """Return True if the state machine allows the transition."""
        return new_status in ALLOWED_TRANSITIONS.get(self.status, [])


class DacMessage(db.Model):
    """Structured inquiry dialogue (RDC-AAP-01 §5.5)."""

    __tablename__ = 'dac_message'

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(64), unique=True, nullable=False)
    application_id = db.Column(db.String(64),
                               db.ForeignKey('dac_application.application_id'),
                               nullable=False, index=True)
    #: dac | requester
    sender = db.Column(db.String(16), nullable=False)
    #: ai | human
    author_kind = db.Column(db.String(16), nullable=False, default='human')
    #: inquiry | answer | info | proposal
    type = db.Column(db.String(16), nullable=False, default='info')
    body = db.Column(db.Text, nullable=True)
    structured = db.Column(JSONB, nullable=True)
    in_reply_to = db.Column(db.String(64), nullable=True)
    sent_at = db.Column(db.DateTime, default=_now, nullable=False)

    def as_dict(self):
        """Serialize for the API."""
        return {
            'message_id': self.message_id,
            'from': self.sender,
            'author_kind': self.author_kind,
            'type': self.type,
            'body': self.body,
            'structured': self.structured,
            'in_reply_to': self.in_reply_to,
            'sent_at': self.sent_at.isoformat() + 'Z',
        }


class DacAssessment(db.Model):
    """Assessment package generated by the review engine (§7)."""

    __tablename__ = 'dac_assessment'

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.String(64),
                               db.ForeignKey('dac_application.application_id'),
                               nullable=False, index=True)
    assessment = db.Column(JSONB, nullable=False)
    generated_at = db.Column(db.DateTime, default=_now, nullable=False)


class DacDecision(db.Model):
    """Officer decision record (§7.3–7.4)."""

    __tablename__ = 'dac_decision'

    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.String(64),
                               db.ForeignKey('dac_application.application_id'),
                               nullable=False, index=True)
    #: approve | approve_with_conditions | reject | request_info
    decision = db.Column(db.String(32), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    conditions = db.Column(JSONB, nullable=True)
    #: WEKO user id / email of the officer. 'agent' in Phase 2.
    decided_by = db.Column(db.String(255), nullable=False)
    #: id of the assessment shown to the officer.
    assessment_id = db.Column(db.Integer, nullable=True)
    #: True when the decision diverges from the AI recommendation.
    diverges_from_ai = db.Column(db.Boolean, nullable=False, default=False)
    decided_at = db.Column(db.DateTime, default=_now, nullable=False)


class DacAgreement(db.Model):
    """Issued ODRL Agreement (§6.1)."""

    __tablename__ = 'dac_agreement'

    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(255), unique=True, nullable=False)
    application_id = db.Column(db.String(64),
                               db.ForeignKey('dac_application.application_id'),
                               nullable=False, index=True)
    dataset_id = db.Column(db.String(255), nullable=False, index=True)
    agreement = db.Column(JSONB, nullable=False)
    agreement_jws = db.Column(db.Text, nullable=False)
    supersedes = db.Column(db.String(255), nullable=True)
    issued_at = db.Column(db.DateTime, default=_now, nullable=False)


class DacVisa(db.Model):
    """Issued ControlledAccessGrants Visa (§6.2)."""

    __tablename__ = 'dac_visa'

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(64), unique=True, nullable=False, index=True)
    application_id = db.Column(db.String(64),
                               db.ForeignKey('dac_application.application_id'),
                               nullable=False, index=True)
    agreement_uid = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=False, index=True)
    dataset_id = db.Column(db.String(255), nullable=False, index=True)
    visa_jwt = db.Column(db.Text, nullable=False)
    #: active | revoked | expired | superseded
    status = db.Column(db.String(16), nullable=False, default='active')
    expires_at = db.Column(db.DateTime, nullable=False)
    wallet_credential_id = db.Column(db.String(64), nullable=True)
    wallet_deposited = db.Column(db.Boolean, nullable=False, default=False)
    issued_at = db.Column(db.DateTime, default=_now, nullable=False)

    def current_status(self):
        """Status with lazy expiry evaluation."""
        if self.status == 'active' and self.expires_at < _now():
            return 'expired'
        return self.status


class DacPresentationJti(db.Model):
    """Replay prevention for Grant Presentations (§6.3)."""

    __tablename__ = 'dac_presentation_jti'

    jti = db.Column(db.String(128), primary_key=True)
    presented_by = db.Column(db.String(255), nullable=True)
    used_at = db.Column(db.DateTime, default=_now, nullable=False)


class DacEventOutbox(db.Model):
    """Callback events to the DG (§5.7), delivered asynchronously."""

    __tablename__ = 'dac_event_outbox'

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(64), unique=True, nullable=False)
    application_id = db.Column(db.String(64), nullable=False, index=True)
    callback_url = db.Column(db.Text, nullable=False)
    event = db.Column(JSONB, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    next_attempt_at = db.Column(db.DateTime, default=_now, nullable=False)
    delivered_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=_now, nullable=False)


class DacAuditOutbox(db.Model):
    """Audit event spool (RDC-AAP-01 §9 / RDC-AAP-04 §6). [DEMO] the
    audit log service may not exist yet; events are spooled here and
    flushed by a periodic task when configured."""

    __tablename__ = 'dac_audit_outbox'

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    payload = db.Column(JSONB, nullable=False)
    created_at = db.Column(db.DateTime, default=_now, nullable=False)
    sent_at = db.Column(db.DateTime, nullable=True)


__all__ = (
    'DacOffer', 'DacApplication', 'DacMessage', 'DacAssessment',
    'DacDecision', 'DacAgreement', 'DacVisa', 'DacPresentationJti',
    'DacEventOutbox', 'DacAuditOutbox',
    'APPLICATION_STATES', 'ALLOWED_TRANSITIONS', 'new_id',
)
