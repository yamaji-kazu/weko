# -*- coding: utf-8 -*-
"""Celery tasks: callback delivery, wallet deposit retry, visa expiry.

Register the periodic entries in CELERY_BEAT_SCHEDULE (see README) or
run them manually via ``invenio dac pump``.
"""

from datetime import datetime

from celery import shared_task
from flask import current_app
from invenio_db import db

from .models import DacApplication, DacEventOutbox, DacVisa
from .services import deliver_event, deposit_visa_to_wallet


@shared_task(ignore_result=True)
def pump_events():
    """Deliver pending callback events (§5.7, retry with backoff)."""
    now = datetime.utcnow()
    rows = DacEventOutbox.query.filter(
        DacEventOutbox.delivered_at.is_(None),
        DacEventOutbox.next_attempt_at <= now,
    ).order_by(DacEventOutbox.id).limit(50).all()
    delivered = 0
    for row in rows:
        if row.attempts > 30:
            continue  # give up silently after ~24h schedule exhaustion
        if deliver_event(row):
            delivered += 1
    db.session.commit()
    return delivered


@shared_task(ignore_result=True)
def retry_wallet_deposits():
    """Retry wallet deposits that failed at issuance time (§6.2)."""
    rows = DacVisa.query.filter_by(
        wallet_deposited=False, status='active').limit(20).all()
    ok = 0
    for visa in rows:
        if visa.expires_at < datetime.utcnow():
            continue
        try:
            if deposit_visa_to_wallet(visa):
                ok += 1
        except Exception:
            current_app.logger.exception(
                'weko-dac: wallet deposit retry failed for %s', visa.jti)
    db.session.commit()
    return ok


@shared_task(ignore_result=True)
def expire_grants():
    """Mark expired visas / applications (§5.3 active -> expired)."""
    now = datetime.utcnow()
    expired_apps = set()
    for visa in DacVisa.query.filter(
            DacVisa.status == 'active',
            DacVisa.expires_at < now).all():
        visa.status = 'expired'
        expired_apps.add(visa.application_id)
    for app_id in expired_apps:
        application = DacApplication.query.filter_by(
            application_id=app_id).first()
        if application and application.status == 'active':
            still_active = DacVisa.query.filter_by(
                application_id=app_id, status='active').count()
            if not still_active:
                from .services import transition
                transition(application, 'expired')
    db.session.commit()
