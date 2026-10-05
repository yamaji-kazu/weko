# -*- coding: utf-8 -*-
"""aifs ADR-16 — DAC の許諾を審査者が本人の VP で署名する(grant_approval.py の純関数)。

WEKO の環境なしで走る:
    cd modules/weko-dac && python3 -m pytest tests/test_grant_approval.py -q
通るもの(審査者の VC)と同じだけ、拒否されるべきもの(PI の VC・別の DAC・信頼していない
発行者)が拒否されることを見る。
"""
import base64
import json
import os
import sys

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from weko_dac import grant_approval as ga  # noqa: E402

DAC = 'https://db.example/dacs/rdc-dac-001'
TRUST = ['did:jwk:trusted']
APP = {
    'application_id': 'app-1',
    'researcher_sub': 'sub-r',
    'payload': {
        'applicant': {'researcher': {'name': '研究者'}},
        'requests': [{'dataset_id': 'https://db.example/records/2000005'}],
        'purpose': {'duo_codes': ['DUO:0000042'], 'description': '目的',
                    'period': {'start': '2026-10-05', 'end': '2027-03-31'}},
    },
}


def _pem():
    k = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return k.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


def _dec(part):
    return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))


def test_entry_has_type_content_and_common_fields():
    content = ga.grant_content(APP, 'approve_with_conditions', '妥当', ['引用'], DAC)
    e = ga.build_grant_entry(content, {'id': 'officer@x', 'name': '審査者'},
                             'https://db.example', {'url': 'u', 'digest': 'd'},
                             '2026-10-05T12:00:00Z')
    assert e['type'] == ga.GRANT_TXDATA_TYPE
    assert e['application_id'] == 'app-1' and e['dac'] == DAC
    assert e['datasets'] == ['https://db.example/records/2000005']
    assert e['purpose']['duo_codes'] == ['DUO:0000042']
    assert e['decision'] == 'approve_with_conditions' and e['conditions'] == ['引用']
    for k in ('responsible', 'agent', 'target_data', 'scope', 'not_after',
              'reversible', 'delegation_proof_hash', 'explanation'):
        assert k in e
    assert e['delegation_proof_hash'] is None
    assert e['target_data'][0]['class'] == 'controlled'
    body = ga.session_create_body(e)
    assert body['core_flow']['dcql_query']['credentials'][0]['meta']['vct_values'] == [ga.DAC_OFFICER_VCT]


def test_explanation_is_deterministic():
    a = ga.build_explanation([('申請', 'app-1'), ('条件', [])], '審査者', 'svc', 'na', 'h')
    b = ga.build_explanation([('申請', 'app-1'), ('条件', [])], '審査者', 'svc', 'na', 'h')
    assert a == b and '- 条件: (なし)' in a
    assert ga.sha256_b64url(a) != ga.sha256_b64url(a + ' ')


def _presented(**over):
    p = {'holder': 'did:jwk:h#0', 'role': 'dac_officer', 'dac_id': DAC,
         'issuer': 'did:jwk:trusted', 'vct': ga.DAC_OFFICER_VCT}
    p.update(over)
    return p


def test_officer_check_accepts_only_dac_officer_of_this_dac():
    assert ga.check_officer(_presented(), TRUST, DAC) is None


def test_officer_check_rejections():
    # PI の認可 VC(型も役割も違う)では許諾に署名できない
    assert ga.check_officer(_presented(vct='urn:rdc:credential:research-execution-authz:1',
                                       role='principal_investigator'), TRUST, DAC) == 'not_dac_officer_credential'
    assert ga.check_officer(_presented(role='member'), TRUST, DAC) == 'role_not_dac_officer'
    assert ga.check_officer(_presented(dac_id='https://other/dacs/x'), TRUST, DAC) == 'dac_not_authorized'
    assert ga.check_officer(_presented(issuer='did:jwk:self-made'), TRUST, DAC) == 'issuer_not_trusted'
    assert ga.check_officer(_presented(), [], DAC) == 'issuer_not_trusted'
    assert ga.check_officer(_presented(holder=None), TRUST, DAC) == 'holder_mismatch'


def test_parse_and_evidence_from_info():
    info = {
        'presented_credentials': {'rdc_officer': [{'credentialData': {
            'iss': 'did:jwk:trusted', 'vct': ga.DAC_OFFICER_VCT, 'authorized_role': 'dac_officer',
            'authorized_scope': {'dac_id': DAC}, 'cnf': {'jwk': {'kid': 'did:jwk:h#0'}}}}]},
        'presented_raw_data': {'vpToken': {'rdc_officer': ['iss~kb']}},
        'authorizationRequest': {'transaction_data': ['td-string']},
    }
    assert ga.check_officer(ga.parse_presented(info), TRUST, DAC) is None
    ev = ga.evidence_of(info, 's1', 'did:jwk:h#0')
    assert ev['evidence'] == 'vp' and ev['transaction_data'] == 'td-string'
    assert ga.evidence_of({}, 's1', 'h')['evidence'] == 'vp_unavailable'


def test_approval_record_two_layers():
    pem = _pem()
    jwk = ga.public_jwk_from_pem(pem)
    rid, summary, full = ga.sign_approval(pem, jwk['kid'], 'https://db.example',
                                          '2026-10-05T00:00:00Z', 'officer@x',
                                          'did:jwk:h#0', 's1', 'txh', 'app-1')
    # PyJWT 1.5.3(weko の実行環境)には ECAlgorithm.from_jwk が無いので、秘密鍵から公開鍵を作る
    pub = serialization.load_pem_private_key(pem, None, default_backend()).public_key()
    s = jwt.decode(summary, pub, algorithms=['ES256'])
    f = jwt.decode(full, pub, algorithms=['ES256'])
    assert jwt.get_unverified_header(summary)['typ'] == ga.SUMMARY_TYP
    assert jwt.get_unverified_header(full)['typ'] == ga.RECORD_TYP
    text = json.dumps(s, ensure_ascii=False)
    for secret in ('officer@x', 'did:jwk:h#0', 'txh', 's1'):
        assert secret not in text
    assert f['summary_sha256'] == ga.sha256_b64url(summary)
    assert f['key_custody'] == 'unattested' and f['approved_by'] == 'officer@x'
    disc = f['tx_disclosure']
    assert ga.sha256_b64url(disc) == s['tx_commitment']
    assert _dec(disc)[1:] == ['tx_hash', 'txh']


def test_log_chain():
    pem = _pem()
    kid = ga.public_jwk_from_pem(pem)['kid']
    a = ga.sign_log_entry(ga.next_log_entry(None, 0, 'iss', 'sub', 'signature', {}, 't'), pem, kid)
    b = ga.sign_log_entry(ga.next_log_entry(a, 1, 'iss', 'sub', 'result', {}, 't'), pem, kid)
    pb = _dec(b.split('.')[1])
    assert pb['seq'] == 2 and pb['prev'] == ga.sha256_b64url(a)
    assert _dec(a.split('.')[1])['prev'] is None
