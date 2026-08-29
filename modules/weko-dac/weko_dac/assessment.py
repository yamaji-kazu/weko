# -*- coding: utf-8 -*-
"""Assessment package generation (RDC-AAP-01 §7, rule-engine profile).

The assessment is produced by the deterministic rule engine
(:mod:`weko_dac.matching`) plus rule-based risk findings. An LLM hook
is provided but disabled by default; when enabled it may only ADD
narrative findings — recommendations remain rule-derived and free-text
inputs are always treated as untrusted data (§7.5).
"""

import hashlib
import json
import re
from datetime import datetime

from flask import current_app

from . import matching
from .models import DacOffer

ENGINE_ID = 'rdc-odrl-eval 1.0 (weko-dac)'


def _digest(obj):
    return 'sha256:' + hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False,
                   default=str).encode('utf-8')).hexdigest()


def detect_directive_language(texts):
    """Prompt-injection detector over free-text fields (§7.5)."""
    patterns = current_app.config.get('WEKO_DAC_INJECTION_PATTERNS', [])
    hits = []
    for name, text in texts:
        if not text:
            continue
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                hits.append({'field': name, 'pattern': pat})
    return hits


def _collect_risk_findings(app_payload, offers, match_results,
                           injection_hits):
    findings = []
    evidence = app_payload.get('evidence') or {}
    purpose = app_payload.get('purpose') or {}
    security = evidence.get('security_measures') or {}

    if injection_hits:
        findings.append({
            'severity': 'high',
            'code': 'DIRECTIVE_LANGUAGE_DETECTED',
            'description': 'Directive language detected in free text '
                           '(possible prompt injection): %s'
                           % json.dumps(injection_hits, ensure_ascii=False),
        })
    if not security:
        findings.append({
            'severity': 'medium', 'code': 'SECURITY_MEASURES_MISSING',
            'description': 'evidence.security_measures is empty.'})
    else:
        if not security.get('encryption_at_rest'):
            findings.append({
                'severity': 'low', 'code': 'NO_ENCRYPTION_AT_REST',
                'description': 'Storage encryption at rest not declared.'})
        if not security.get('disposal'):
            findings.append({
                'severity': 'medium',
                'code': 'STORAGE_UNSPECIFIED_RETENTION',
                'description': 'No disposal / retention procedure declared '
                               'for the end of the use period.'})
    # ethics requirement from offers
    needs_ethics = False
    for offer_row in offers:
        for perm in (offer_row.offer.get('permission') or []):
            for c in (perm.get('constraint') or []):
                lo = c.get('leftOperand')
                lo = lo.get('@id') if isinstance(lo, dict) else lo
                if str(lo).endswith('ethicsApproval'):
                    needs_ethics = True
    if needs_ethics and not evidence.get('ethics_approval'):
        findings.append({
            'severity': 'high', 'code': 'ETHICS_APPROVAL_MISSING',
            'description': 'Offer requires ethics approval but none is '
                           'attached.'})
    if not (purpose.get('description') or '').strip():
        findings.append({
            'severity': 'medium', 'code': 'PURPOSE_DESCRIPTION_EMPTY',
            'description': 'purpose.description is empty.'})
    for mr in match_results:
        if mr['match']['overall'] == 'not_satisfied':
            findings.append({
                'severity': 'high', 'code': 'ODRL_MISMATCH',
                'description': 'Request for %s does not satisfy the Offer.'
                               % mr['dataset_id']})
    return findings


def _recommend(match_results, risk_findings):
    high = [f for f in risk_findings if f['severity'] == 'high']
    overalls = [m['match']['overall'] for m in match_results]
    mediums = [f for f in risk_findings if f['severity'] == 'medium']
    if any(f['code'] == 'DIRECTIVE_LANGUAGE_DETECTED'
           for f in risk_findings):
        # §7.5: forced human review
        return {'decision': 'needs_info',
                'rationale': 'Directive language detected in free text; '
                             'forced human review (needs_human).',
                'confidence': 1.0, 'conditions': []}
    if 'not_satisfied' in overalls or high:
        return {'decision': 'reject',
                'rationale': 'ODRL mismatch or high-severity finding. '
                             'See odrl_match / risk_findings.',
                'confidence': 0.9, 'conditions': []}
    if 'needs_human' in overalls:
        return {'decision': 'needs_info',
                'rationale': 'One or more constraints are not machine-'
                             'decidable; human confirmation required.',
                'confidence': 0.7, 'conditions': []}
    if mediums:
        conds = []
        if any(f['code'] == 'STORAGE_UNSPECIFIED_RETENTION'
               for f in mediums):
            conds.append('利用終了時の削除報告を義務化')
        return {'decision': 'approve_with_conditions',
                'rationale': 'All ODRL constraints satisfied; medium '
                             'findings addressed via conditions.',
                'confidence': 0.85, 'conditions': conds}
    return {'decision': 'approve',
            'rationale': 'All ODRL constraints satisfied; no findings.',
            'confidence': 0.95, 'conditions': []}


def generate_assessment(application):
    """Build the assessment package (§7.2 schema) for an application."""
    payload = application.payload
    purpose = payload.get('purpose') or {}
    period = purpose.get('period') or {}
    period_start = None
    if period.get('start'):
        try:
            period_start = datetime.strptime(
                period['start'][:10], '%Y-%m-%d').date()
        except ValueError:
            period_start = None

    match_results = []
    offers = []
    for req in payload.get('requests') or []:
        dataset_id = req.get('dataset_id') or req.get('resource_id')
        offer_row = DacOffer.query.filter_by(dataset_id=dataset_id).first()
        if offer_row is None:
            match_results.append({
                'dataset_id': dataset_id,
                'match': {'overall': 'needs_human',
                          'constraints': [],
                          'detail': 'no Offer registered'}})
            continue
        offers.append(offer_row)
        match_results.append({
            'dataset_id': dataset_id,
            'access_class': offer_row.access_class,
            'match': matching.match(offer_row.offer,
                                    req.get('odrl_request') or {},
                                    period_start=period_start)})

    injection_hits = detect_directive_language([
        ('purpose.description', purpose.get('description')),
        ('message', payload.get('message')),
    ])
    risk_findings = _collect_risk_findings(
        payload, offers, match_results, injection_hits)
    recommendation = _recommend(match_results, risk_findings)

    overalls = [m['match']['overall'] for m in match_results]
    if 'not_satisfied' in overalls:
        overall = 'not_satisfied'
    elif 'needs_human' in overalls:
        overall = 'needs_human'
    else:
        overall = 'satisfied'

    return {
        'application_id': application.application_id,
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'engine': {
            'rule_engine': ENGINE_ID,
            'llm': None,  # rule-engine-only profile
            'input_digest': _digest(payload),
        },
        'verification': application.verification or {},
        'odrl_match': {'overall': overall, 'per_dataset': match_results},
        'risk_findings': risk_findings,
        'recommendation': recommendation,
    }
