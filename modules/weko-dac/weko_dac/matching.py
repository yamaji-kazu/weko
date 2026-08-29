# -*- coding: utf-8 -*-
"""Deterministic ODRL Request-vs-Offer matching (spec vol.05 §8).

Per-constraint verdicts are ``satisfied`` / ``not_satisfied`` /
``needs_human``. The overall verdict follows §8 item 4. This engine is
shared by the Phase 1 assessment package and a future Phase 2 rule
evaluation (DoAP), and is intentionally free of any LLM dependency.
"""

import json
import os
import re
from datetime import date, datetime, timedelta

_DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

with open(os.path.join(_DATA_DIR, 'duo_snapshot.json')) as _fp:
    DUO_SNAPSHOT = json.load(_fp)
with open(os.path.join(_DATA_DIR, 'vocab_tables.json')) as _fp:
    VOCAB_TABLES = json.load(_fp)

_DUO_IRI_RE = re.compile(
    r'obo/DUO_(\d{7})$|^DUO:(\d{7})$')


def normalize_duo(value):
    """Normalize a DUO IRI or CURIE to ``DUO:NNNNNNN``; None if not DUO."""
    if isinstance(value, dict):
        value = value.get('@id') or value.get('@value') or ''
    if not isinstance(value, str):
        return None
    m = _DUO_IRI_RE.search(value)
    if not m:
        return None
    return 'DUO:' + (m.group(1) or m.group(2))


def duo_subsumes(offer_code, request_code):
    """True if request_code == offer_code or is a descendant of it."""
    parents = DUO_SNAPSHOT.get('parents', {})
    seen = set()
    code = request_code
    while code and code not in seen:
        if code == offer_code:
            return True
        seen.add(code)
        code = parents.get(code)
    return False


def _operand_value(operand):
    """Extract a plain value from an ODRL rightOperand."""
    if isinstance(operand, dict):
        if '@id' in operand:
            return operand['@id']
        if '@value' in operand:
            return operand['@value']
    return operand


_DURATION_RE = re.compile(
    r'^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?$')


def _parse_date(value):
    try:
        return datetime.strptime(str(value)[:10], '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None


def _duration_to_end(value, start=None):
    """Resolve an xsd:duration (PnYnMnD) into an end date."""
    m = _DURATION_RE.match(str(value))
    if not m:
        return None
    years = int(m.group(1) or 0)
    months = int(m.group(2) or 0)
    days = int(m.group(3) or 0)
    base = start or date.today()
    year = base.year + years + (base.month - 1 + months) // 12
    month = (base.month - 1 + months) % 12 + 1
    day = min(base.day, 28)
    return date(year, month, day) + timedelta(days=days)


def _find_constraint(constraints, left_operand):
    for c in constraints or []:
        lo = c.get('leftOperand')
        if isinstance(lo, dict):
            lo = lo.get('@id', '')
        lo = str(lo)
        if lo == left_operand or lo.endswith('/' + left_operand) or \
                lo.split(':')[-1] == left_operand.split(':')[-1]:
            return c
    return None


def _judge(result, detail):
    return {'result': result, 'detail': detail}


def evaluate_constraint(offer_c, request_perm, period_start=None):
    """Evaluate one Offer constraint against the Request (§8 item 2)."""
    left = offer_c.get('leftOperand')
    if isinstance(left, dict):
        left = left.get('@id', '')
    left = str(left)
    short = left.split('/')[-1].split(':')[-1]
    operator = str(offer_c.get('operator', ''))
    op_short = operator.split(':')[-1]
    offer_val = _operand_value(offer_c.get('rightOperand'))
    req_c = _find_constraint(request_perm.get('constraint'), left)

    # purpose (DUO subsumption)
    if short == 'purpose':
        offer_duo = normalize_duo(offer_c.get('rightOperand'))
        if req_c is None:
            return _judge('not_satisfied', 'purpose missing in Request')
        req_duo = normalize_duo(req_c.get('rightOperand'))
        if not offer_duo or not req_duo:
            return _judge('needs_human', 'non-DUO purpose value')
        if duo_subsumes(offer_duo, req_duo):
            return _judge('satisfied',
                          '%s ⊑ %s (DUO %s)' % (
                              req_duo, offer_duo,
                              DUO_SNAPSHOT.get('version')))
        return _judge('not_satisfied',
                      '%s is not subsumed by %s' % (req_duo, offer_duo))

    # dateTime (period comparison)
    if short == 'dateTime':
        if req_c is None:
            return _judge('needs_human', 'dateTime missing in Request')
        req_end = _parse_date(_operand_value(req_c.get('rightOperand')))
        offer_end = _parse_date(offer_val)
        if offer_end is None:
            offer_end = _duration_to_end(offer_val, start=period_start)
        if req_end is None or offer_end is None:
            return _judge('needs_human', 'unparseable dateTime values')
        if op_short in ('lteq', 'lt'):
            if req_end <= offer_end:
                return _judge('satisfied',
                              '%s <= %s' % (req_end, offer_end))
            return _judge('not_satisfied',
                          'requested end %s exceeds offer limit %s'
                          % (req_end, offer_end))
        return _judge('needs_human', 'operator %s on dateTime' % operator)

    # isA / isPartOf via vocabulary tables
    if op_short in ('isA', 'isPartOf'):
        table = VOCAB_TABLES.get(op_short, {})
        members = table.get(str(offer_val))
        if members is None:
            # normalize rdc: prefix variants
            members = table.get(str(offer_val).split('/')[-1])
        if req_c is None:
            return _judge('not_satisfied', '%s missing in Request' % short)
        req_val = str(_operand_value(req_c.get('rightOperand')))
        if members is None:
            return _judge('needs_human',
                          'no vocabulary table for %s' % offer_val)
        if req_val in members or req_val.split('/')[-1] in members:
            return _judge('satisfied', '%s ∈ %s' % (req_val, offer_val))
        return _judge('needs_human',
                      '%s not in table for %s' % (req_val, offer_val))

    # eq
    if op_short == 'eq':
        if req_c is None:
            return _judge('not_satisfied', '%s missing in Request' % short)
        req_val = _operand_value(req_c.get('rightOperand'))
        if str(req_val).lower() == str(offer_val).lower():
            return _judge('satisfied', '%s == %s' % (req_val, offer_val))
        return _judge('not_satisfied',
                      '%s != %s' % (req_val, offer_val))

    return _judge('needs_human', 'operator %s not machine-decidable'
                  % operator)


def _actions(rules):
    out = set()
    for r in rules or []:
        action = r.get('action')
        if isinstance(action, dict):
            action = action.get('@id') or action.get('value')
        if isinstance(action, list):
            for a in action:
                out.add(str(a))
        elif action is not None:
            out.add(str(action))
    return out


def match(offer, req, period_start=None):
    """Match one ODRL Request against one Offer (§8). Returns a report."""
    constraints_report = []
    verdicts = []

    offer_perms = offer.get('permission') or []
    req_perms = req.get('permission') or []
    offer_actions = _actions(offer_perms)
    req_actions = _actions(req_perms)
    prohibited = _actions(offer.get('prohibition'))

    # 1. action inclusion
    extra = req_actions - offer_actions
    clash = req_actions & prohibited
    if clash:
        action_res = _judge(
            'not_satisfied',
            'requested action(s) prohibited: %s' % ', '.join(sorted(clash)))
    elif extra:
        action_res = _judge(
            'not_satisfied',
            'requested action(s) not offered: %s' % ', '.join(sorted(extra)))
    else:
        action_res = _judge('satisfied',
                            'actions %s ⊆ offer' % ', '.join(
                                sorted(req_actions) or ['-']))
    constraints_report.append(dict(action_res, leftOperand='odrl:action'))
    verdicts.append(action_res['result'])

    req_perm = req_perms[0] if req_perms else {}

    # 2. constraint-by-constraint
    for offer_perm in offer_perms:
        for offer_c in offer_perm.get('constraint') or []:
            res = evaluate_constraint(offer_c, req_perm,
                                      period_start=period_start)
            lo = offer_c.get('leftOperand')
            if isinstance(lo, dict):
                lo = lo.get('@id')
            constraints_report.append(dict(res, leftOperand=str(lo)))
            verdicts.append(res['result'])

    # 3. duty acceptance
    offer_duties = set()
    req_duties = set()
    for p in offer_perms:
        offer_duties |= _actions(p.get('duty'))
    for p in req_perms:
        req_duties |= _actions(p.get('duty'))
    missing = offer_duties - req_duties
    if missing:
        duty_res = _judge('not_satisfied',
                          'duties not accepted: %s' % ', '.join(
                              sorted(missing)))
    else:
        duty_res = _judge('satisfied', 'all offer duties accepted')
    constraints_report.append(dict(duty_res, leftOperand='odrl:duty'))
    verdicts.append(duty_res['result'])

    # 4. overall
    if 'not_satisfied' in verdicts:
        overall = 'not_satisfied'
    elif 'needs_human' in verdicts:
        overall = 'needs_human'
    else:
        overall = 'satisfied'

    return {
        'overall': overall,
        'constraints': constraints_report,
        'duo_snapshot_version': DUO_SNAPSHOT.get('version'),
        'vocab_version': VOCAB_TABLES.get('version'),
    }
