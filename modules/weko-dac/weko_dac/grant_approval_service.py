# -*- coding: utf-8 -*-
"""DAC の許諾の VP 承認(aifs ADR-16)— Flask・DB・verifier2 につなぐ側。

流れ:
  1. 審査者が「承認」を選ぶ → request_grant: 許諾の中身を取引に綴じ、verifier2 に提示要求を作る
  2. 審査者が自分のウォレットで審査者の VC を提示し、取引に署名する
  3. confirm_grant: VP を確かめ(信頼する発行者・型・役割・自分の DAC・取引ハッシュ・中身が
     変わっていないこと)、承認記録・ログと許諾の発行(execute_decision)を同じ DB トランザクションで確定する

拒否は ApprovalRejected(code) で返す。code は閉じた語彙で、確認スクリプトはこれを固定して見る。
"""

import base64
import json
import os
import uuid
from datetime import datetime, timedelta

import requests
from flask import current_app
from invenio_db import db

from . import audit
from . import grant_approval as ga
from .models import (DacApprovalExplanation, DacApprovalLog,
                     DacApprovalRecord, DacGrantApproval)


class ApprovalRejected(Exception):
    def __init__(self, code, detail=''):
        super(ApprovalRejected, self).__init__('%s %s' % (code, detail))
        self.code = code
        self.detail = detail


def _now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'


def vp_enabled():
    """verifier2 の接続先が設定されていれば、許諾を出す決定には VP 承認を必須にする。"""
    return bool(current_app.config.get('WEKO_DAC_VERIFIER_BASE_URL'))


def _trusted_issuers():
    raw = current_app.config.get('WEKO_DAC_TRUSTED_AUTHZ_ISSUERS') or ''
    return [s.strip() for s in raw.split(',') if s.strip()]


def _signing_pem():
    path = current_app.config.get('WEKO_DAC_APPROVAL_SIGNING_KEY_PATH') or ''
    if not path or not os.path.exists(path):
        # 承認記録に署名できないなら、承認を成立させない(fail-closed)
        raise ApprovalRejected('signing_unavailable', path)
    with open(path, 'rb') as fp:
        return fp.read()


def _issuer():
    return current_app.config.get('WEKO_DAC_APPROVAL_ISSUER').rstrip('/')


def approvals_jwks():
    return {'keys': [ga.public_jwk_from_pem(_signing_pem())]}


# ---------------------------------------------------------------------------
# verifier2
# ---------------------------------------------------------------------------

def _verifier(method, path, body=None):
    base = current_app.config['WEKO_DAC_VERIFIER_BASE_URL'].rstrip('/')
    try:
        resp = requests.request(method, base + path, json=body, timeout=15)
    except requests.RequestException as ex:
        raise ApprovalRejected('verifier_unreachable', str(ex))
    if resp.status_code >= 300:
        raise ApprovalRejected('verifier_error',
                               '%s %s' % (resp.status_code, resp.text[:200]))
    return resp.json()


def _verifier_state(info):
    st = str((info or {}).get('status') or '').upper()
    if st in ('SUCCESSFUL', 'VERIFIED', 'SUCCESS'):
        return 'verified'
    if st in ('EXPIRED',):
        return 'expired'
    if st in ('UNUSED', 'ACTIVE', 'IN_USE', 'PENDING', 'RECEIVED', 'PROCESSING_FLOW'):
        return 'pending'
    return 'failed'


def _decode_td(td):
    return json.loads(base64.urlsafe_b64decode(td + '=' * (-len(td) % 4)).decode('utf-8'))


# ---------------------------------------------------------------------------
# 承認ログ(ハッシュ連鎖)
# ---------------------------------------------------------------------------

def _append_log(subject_id, kind, body, pem, kid):
    """ログを 1 件足す(commit しない。呼び出し側のトランザクションで確定する)。"""
    last = DacApprovalLog.query.filter_by(subject_id=subject_id).order_by(
        DacApprovalLog.seq.desc()).first()
    # 同じトランザクションで足したばかりの行も連鎖に入れる
    pending = [o for o in db.session.new if isinstance(o, DacApprovalLog)
               and o.subject_id == subject_id]
    if pending:
        last = max(pending, key=lambda o: o.seq)
    payload = ga.next_log_entry(last.jws if last else None, last.seq if last else 0,
                                _issuer(), subject_id, kind, body, _now_iso())
    row = DacApprovalLog(subject_id=subject_id, seq=payload['seq'], kind=kind,
                         jws=ga.sign_log_entry(payload, pem, kid))
    db.session.add(row)
    return row


# ---------------------------------------------------------------------------
# 1. 要求
# ---------------------------------------------------------------------------

def request_grant(application, decision, reason, conditions, officer):
    """許諾の中身を取引に綴じて提示要求を作る。officer = {'id':…, 'name':…}"""
    if decision not in ga.GRANT_DECISIONS:
        raise ApprovalRejected('not_a_grant_decision', decision)
    if application.status not in ('under_review', 'needs_info'):
        raise ApprovalRejected('not_under_review', application.status)
    pem = _signing_pem()
    kid = ga.public_jwk_from_pem(pem)['kid']
    dac_id = current_app.config['WEKO_DAC_DAC_ID']
    app_doc = {'application_id': application.application_id,
               'researcher_sub': application.researcher_sub,
               'payload': application.payload}
    content = ga.grant_content(app_doc, decision, reason, conditions, dac_id)
    ttl = current_app.config.get('WEKO_DAC_GRANT_APPROVAL_TTL', 3600)
    not_after = (datetime.utcnow() + timedelta(seconds=ttl)).replace(
        microsecond=0).isoformat() + 'Z'
    body = ga.build_explanation([
        ('申請', content['application_id']),
        ('宛先の DAC', content['dac']),
        ('対象データ', content['datasets']),
        ('申請者', '%s (%s)' % (content['researcher']['name'], content['researcher']['sub'])),
        ('利用目的(DUO)', content['purpose']['duo_codes']),
        ('利用目的(説明)', content['purpose']['description']),
        ('利用期間', '%s 〜 %s' % (content['purpose']['period_start'], content['purpose']['period_end'])),
        ('決定', content['decision']),
        ('条件', content['conditions']),
        ('理由', content['reason']),
    ], officer.get('name') or officer['id'], _issuer(), not_after,
        ga.GRANT_REVERSIBLE['how'])
    exp = DacApprovalExplanation(id=uuid.uuid4().hex, subject_id='', body=body,
                                 digest=ga.sha256_b64url(body))
    explanation = {'url': '%s/api/dac/v1/approvals/explain/%s' % (_issuer(), exp.id),
                   'digest': exp.digest}
    entry = ga.build_grant_entry(content, officer, _issuer(), explanation, not_after)
    created = _verifier('POST', '/verification-session/create', ga.session_create_body(entry))
    session_id = created.get('sessionId')
    url = created.get('fullAuthorizationRequestUrl') or created.get('bootstrapAuthorizationRequestUrl')
    if not session_id or not url:
        # 要求が作れないのに「作れた」と見せない
        raise ApprovalRejected('verifier_error', 'sessionId/URL 欠落')
    info = _verifier('GET', '/verification-session/%s/info' % session_id)
    td = ((info.get('authorizationRequest') or {}).get('transaction_data') or [None])[0]
    subject_id = 'dac-grant:%s' % uuid.uuid4()
    exp.subject_id = subject_id
    row = DacGrantApproval(
        subject_id=subject_id, application_id=application.application_id,
        decision=decision, reason=reason, conditions=list(conditions or []),
        officer_id=officer['id'], session_id=session_id,
        txdata_hash=ga.sha256_b64url(td) if isinstance(td, str) else None,
        authorization_request_url=url, state='pending')
    db.session.add(exp)
    db.session.add(row)
    _append_log(subject_id, 'request', {
        'type': ga.GRANT_TXDATA_TYPE, 'application_id': application.application_id,
        'decision': decision, 'verifier_session_id': session_id,
        'txdata_hash': row.txdata_hash, 'explanation': explanation,
        'requested_by': officer['id']}, pem, kid)
    audit.record('grant_approval.requested',
                 subject={'application_id': application.application_id},
                 actor={'kind': 'human', 'id': officer['id']},
                 payload={'subject_id': subject_id, 'decision': decision})
    db.session.commit()
    return row


# ---------------------------------------------------------------------------
# 2. 確認
# ---------------------------------------------------------------------------

def _fail(row, code, detail=''):
    row.state = ('failed:%s' % code)[:64]
    db.session.commit()
    raise ApprovalRejected(code, detail)


def confirm_grant(subject_id, officer_id, application):
    """VP を確かめ、承認記録・ログ・許諾の発行を同じトランザクションで確定する。"""
    from . import services
    row = DacGrantApproval.query.filter_by(subject_id=subject_id).first()
    if row is None or row.application_id != application.application_id:
        raise ApprovalRejected('approval_not_found', subject_id)
    if row.state != 'pending':
        raise ApprovalRejected('approval_not_pending', row.state)
    # 要求した審査者本人だけが確定できる(VC の持ち主と管理画面のログインは別に確かめる)
    if row.officer_id != officer_id:
        raise ApprovalRejected('approver_not_requester', officer_id)
    pem = _signing_pem()
    kid = ga.public_jwk_from_pem(pem)['kid']
    ttl = current_app.config.get('WEKO_DAC_GRANT_APPROVAL_TTL', 3600)
    if row.created_at + timedelta(seconds=ttl) <= datetime.utcnow():
        return _fail(row, 'expired')
    info = _verifier('GET', '/verification-session/%s/info' % row.session_id)
    state = _verifier_state(info)
    if state == 'pending':
        raise ApprovalRejected('pending', str(info.get('status')))
    if state != 'verified':
        return _fail(row, 'vp_' + state, str(info.get('status')))
    presented = ga.parse_presented(info)
    code = ga.check_officer(presented, _trusted_issuers(),
                            current_app.config['WEKO_DAC_DAC_ID'])
    if code:
        return _fail(row, code)
    evidence = ga.evidence_of(info, row.session_id, presented['holder'])
    td = evidence.get('transaction_data')
    if not row.txdata_hash or not td or ga.sha256_b64url(td) != row.txdata_hash:
        return _fail(row, 'txdata_mismatch')
    # 署名した中身と、いま確定しようとしている中身が同じか(申請・決定・条件・理由)
    app_doc = {'application_id': application.application_id,
               'researcher_sub': application.researcher_sub,
               'payload': application.payload}
    now_content = ga.grant_content(app_doc, row.decision, row.reason, row.conditions,
                                   current_app.config['WEKO_DAC_DAC_ID'])
    signed = _decode_td(td)
    if any(signed.get(k) != v for k, v in now_content.items()):
        return _fail(row, 'content_changed')

    record_id, summary_jws, full_jws = ga.sign_approval(
        pem, kid, _issuer(), _now_iso(), row.officer_id, presented['holder'],
        row.session_id, row.txdata_hash, application.application_id)
    db.session.add(DacApprovalRecord(
        record_id=record_id, subject_id=subject_id,
        application_id=application.application_id,
        summary_jws=summary_jws, full_jws=full_jws, kid=kid))
    _append_log(subject_id, 'signature', evidence, pem, kid)
    _append_log(subject_id, 'result', {
        'record_id': record_id, 'assurance_level': 'vp',
        'summary_sha256': ga.sha256_b64url(summary_jws),
        'full_sha256': ga.sha256_b64url(full_jws)}, pem, kid)
    row.state = 'approved'
    row.record_id = record_id
    try:
        # execute_decision が最後に commit する。承認記録・ログ・許諾は一緒に確定し、
        # 許諾の発行が失敗すれば承認記録も残らない。
        services.execute_decision(
            application, row.decision, row.reason, row.officer_id,
            conditions=row.conditions, grant_approval_record=record_id)
    except ValueError as ex:
        db.session.rollback()
        raise ApprovalRejected('decision_failed', str(ex))
    return row
