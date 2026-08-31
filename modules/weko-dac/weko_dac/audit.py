# -*- coding: utf-8 -*-
"""Audit event spooling (RDC-AAP-01 §9 / RDC-AAP-04 §6).

Events are written to ``dac_audit_outbox`` in the common event schema.
[DEMO] When ``WEKO_DAC_AUDIT_API_BASE`` is empty (no audit log service
yet), events remain spooled locally; a periodic task flushes them once
the service is configured. Personal data stays out of ``payload`` —
only digests are stored where the content is sensitive (§6.1).
"""

import hashlib
import json
import os
import uuid
from datetime import datetime

from flask import current_app
from invenio_db import db

from .models import DacAuditOutbox


def _jsonl_path():
    path = current_app.config.get('WEKO_DAC_AUDIT_JSONL_PATH') or ''
    if path == '-':
        return None
    if not path:
        path = os.path.join(current_app.instance_path, 'data',
                            'dac_audit.jsonl')
    return path


def _append_jsonl(event):
    """DEMO-20 §4: local JSONL audit sink (best-effort)."""
    path = _jsonl_path()
    if not path:
        return
    try:
        dirname = os.path.dirname(path)
        if dirname and not os.path.isdir(dirname):
            os.makedirs(dirname)
        with open(path, 'a') as fp:
            fp.write(json.dumps(event, ensure_ascii=False,
                                default=str) + '\n')
    except Exception:
        current_app.logger.exception('weko-dac: audit JSONL write failed')


def digest(obj):
    """sha256 digest of a JSON-serializable object."""
    return 'sha256:' + hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False,
                   default=str).encode('utf-8')).hexdigest()


def record(event_type, subject=None, actor=None, payload=None,
           payload_digest=None):
    """Spool one audit event. Never raises (audit is best-effort)."""
    try:
        event = {
            'event_id': str(uuid.uuid4()),
            'source': current_app.config.get('WEKO_DAC_ENTITY_ID'),
            'event_type': event_type,
            'occurred_at': datetime.utcnow().isoformat() + 'Z',
            'subject': subject or {},
            'actor': actor or {},
            'payload_digest': payload_digest or (
                digest(payload) if payload is not None else None),
            'payload': payload or {},
        }
        db.session.add(DacAuditOutbox(event_type=event_type, payload=event))
        # Caller is responsible for the surrounding commit.
        _append_jsonl(event)
    except Exception:
        current_app.logger.exception('weko-dac: audit spool failed')
