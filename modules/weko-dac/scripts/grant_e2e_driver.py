# -*- coding: utf-8 -*-
"""grant_e2e_driver.py — DAC の許諾の VP 承認(aifs ADR-16)を実機で確かめるための操作口。

140 の web コンテナで動かす(check-grant-approval.sh が 141 から ssh で呼ぶ)。管理画面と同じ
サービス関数(grant_approval_service)を呼ぶ。結果は 1 行の JSON で返し、拒否は code で返す。

  python grant_e2e_driver.py create-app <researcher_sub>      確認専用の申請(e2e-grant-*)を under_review で作る
  python grant_e2e_driver.py bypass <app_id> <officer>        署名なしで承認を試みる(拒否されるべき)
  python grant_e2e_driver.py request <app_id> <officer> [decision]
  python grant_e2e_driver.py tamper <subject_id>              保存した理由を書き換える(content_changed の対照)
  python grant_e2e_driver.py confirm <subject_id> <officer> <app_id>
  python grant_e2e_driver.py show <app_id>                    申請・決定・承認記録・ログ・説明文を返す
  python grant_e2e_driver.py revoke-e2e [--apply]           確認専用の active な許諾を取り消す(既定は表示だけ)
  python grant_e2e_driver.py cleanup [--apply]                確認専用の申請を消す(既定は表示だけ)
"""
import json
import sys
import uuid

from invenio_app.factory import create_api

E2E_PREFIX = 'e2e-grant-'


def out(**kw):
    print(json.dumps(kw, ensure_ascii=False, default=str))


def main(argv):
    from invenio_db import db
    from weko_dac import grant_approval_service as gas
    from weko_dac import services
    from weko_dac.models import (DacAgreement, DacApplication,
                                 DacApprovalExplanation, DacApprovalLog,
                                 DacApprovalRecord, DacDecision,
                                 DacEventOutbox, DacGrantApproval, DacVisa)
    cmd = argv[0]

    def app_of(app_id):
        return DacApplication.query.filter_by(application_id=app_id).one()

    if cmd == 'create-app':
        # 本物の controlled の申請から形だけ借りる(読むだけ)。生の Passport は写さない。
        src = None
        for d in DacDecision.query.order_by(DacDecision.id.desc()).all():
            a = DacApplication.query.filter_by(application_id=d.application_id).first()
            if a and (a.payload or {}).get('requests') and not a.application_id.startswith(E2E_PREFIX):
                src = a
                break
        payload = json.loads(json.dumps(src.payload))
        payload.pop('evidence', None)
        payload['callback_url'] = None
        payload.setdefault('applicant', {}).setdefault('researcher', {})['name'] = 'e2e 確認用'
        payload['purpose'] = {'duo_codes': ['DUO:0000042'],
                              'description': 'e2e: 許諾の VP 承認の確認(aifs ADR-16)',
                              'period': {'start': '2026-10-05', 'end': '2027-03-31'}}
        app_id = E2E_PREFIX + uuid.uuid4().hex[:8]
        db.session.add(DacApplication(
            application_id=app_id, status='under_review', resource_type='dataset',
            researcher_sub=argv[1], agent_id=src.agent_id, callback_url=None,
            payload=payload, verification={'e2e': True}))
        db.session.commit()
        return out(app_id=app_id, status='under_review',
                   dataset=payload['requests'][0].get('dataset_id'))

    if cmd == 'bypass':
        a = app_of(argv[1])
        try:
            services.execute_decision(a, 'approve', 'e2e: 署名なし', argv[2])
        except ValueError as ex:
            db.session.rollback()
            return out(result='rejected', detail=str(ex), status=app_of(argv[1]).status)
        return out(result='accepted', status=a.status)

    if cmd == 'request':
        a = app_of(argv[1])
        decision = argv[3] if len(argv) > 3 else 'approve_with_conditions'
        try:
            row = gas.request_grant(a, decision, 'e2e: 目的と DUO が許諾の範囲内',
                                    ['成果に出典を記す'], {'id': argv[2], 'name': argv[2]})
        except gas.ApprovalRejected as ex:
            db.session.rollback()
            return out(result='rejected', code=ex.code)
        return out(result='pending', subject_id=row.subject_id,
                   url=row.authorization_request_url, txdata_hash=row.txdata_hash)

    if cmd == 'tamper':
        row = DacGrantApproval.query.filter_by(subject_id=argv[1]).one()
        row.reason = row.reason + '(署名の後に書き換えた)'
        db.session.commit()
        return out(result='tampered')

    if cmd == 'confirm':
        try:
            row = gas.confirm_grant(argv[1], argv[2], app_of(argv[3]))
        except gas.ApprovalRejected as ex:
            db.session.rollback()
            row = DacGrantApproval.query.filter_by(subject_id=argv[1]).first()
            return out(result='rejected', code=ex.code,
                       state=row.state if row else None,
                       status=app_of(argv[3]).status,
                       records=DacApprovalRecord.query.filter_by(subject_id=argv[1]).count())
        return out(result='approved', record_id=row.record_id,
                   status=app_of(argv[3]).status)

    if cmd == 'show':
        a = app_of(argv[1])
        g = DacGrantApproval.query.filter_by(application_id=a.application_id,
                                             state='approved').first()
        rec = DacApprovalRecord.query.filter_by(subject_id=g.subject_id).first() if g else None
        logs = DacApprovalLog.query.filter_by(subject_id=g.subject_id).order_by(
            DacApprovalLog.seq).all() if g else []
        exps = DacApprovalExplanation.query.filter_by(subject_id=g.subject_id).all() if g else []
        decs = DacDecision.query.filter_by(application_id=a.application_id).all()
        return out(status=a.status, subject_id=g.subject_id if g else None,
                   txdata_hash=g.txdata_hash if g else None,
                   decisions=[{'decision': d.decision, 'by': d.decided_by,
                               'reason': d.reason, 'conditions': d.conditions} for d in decs],
                   agreements=DacAgreement.query.filter_by(application_id=a.application_id).count(),
                   record={'record_id': rec.record_id, 'summary_jws': rec.summary_jws,
                           'full_jws': rec.full_jws, 'kid': rec.kid} if rec else None,
                   log=[{'seq': l.seq, 'kind': l.kind, 'jws': l.jws} for l in logs],
                   explanations=[{'id': e.id, 'body': e.body, 'digest': e.digest} for e in exps])

    if cmd == 'revoke-e2e':
        # 確認専用の許諾(e2e-grant-*)だけを取り消す。既定は表示だけ。
        apps = DacApplication.query.filter(
            DacApplication.application_id.like(E2E_PREFIX + '%'),
            DacApplication.status == 'active').all()
        rows = [{'app_id': a.application_id, 'researcher_sub': a.researcher_sub,
                 'visas': [{'jti': v.jti, 'status': v.status,
                            'wallet_credential_id': v.wallet_credential_id}
                           for v in DacVisa.query.filter_by(application_id=a.application_id)]}
                for a in apps]
        if '--apply' not in argv:
            return out(dry_run=True, targets=rows, hint='取り消すには revoke-e2e --apply')
        for a in apps:
            services.revoke_grant(a, 'e2e: 確認用の許諾をデモのユーザに誤って発行したため取り消す', 'e2e-cleanup')
        return out(revoked=rows)

    if cmd == 'cleanup':
        apps = DacApplication.query.filter(
            DacApplication.application_id.like(E2E_PREFIX + '%')).all()
        ids = [a.application_id for a in apps]
        subj = [g.subject_id for g in DacGrantApproval.query.filter(
            DacGrantApproval.application_id.in_(ids)).all()] if ids else []
        if '--apply' not in argv:
            return out(dry_run=True, applications=ids, approvals=len(subj),
                       hint='消すには cleanup --apply')
        for m, col, vals in ((DacApprovalLog, 'subject_id', subj),
                             (DacApprovalExplanation, 'subject_id', subj),
                             (DacApprovalRecord, 'subject_id', subj),
                             (DacGrantApproval, 'application_id', ids),
                             (DacVisa, 'application_id', ids),
                             (DacAgreement, 'application_id', ids),
                             (DacDecision, 'application_id', ids),
                             (DacEventOutbox, 'application_id', ids),
                             (DacApplication, 'application_id', ids)):
            if vals and hasattr(m, col):
                m.query.filter(getattr(m, col).in_(vals)).delete(synchronize_session=False)
        db.session.commit()
        return out(deleted=ids)

    raise SystemExit('unknown command %s' % cmd)


if __name__ == '__main__':
    app = create_api()
    with app.app_context():
        main(sys.argv[1:])
