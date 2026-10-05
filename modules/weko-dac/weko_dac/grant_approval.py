# -*- coding: utf-8 -*-
"""DAC の許諾を、審査者が本人の VP(walt.id)で署名する(aifs ADR-16、型 data-access-grant:1)。

承認の契約(取引の形・共通の必須項目・承認記録の 2 つの JWS・SD-JWT の開示形式・ハッシュ連鎖の
承認ログ)は RDC 承認プロファイルで共有し、実装は各アプリが持つ(ADR-09)。DG(TypeScript)の
実装と同じ契約を、ここでは Python で実装する。Flask に依存しない純関数を先に置き、単体で確かめる。

- 審査者であることは、PI の認可 VC と型を分けた審査者の VC(urn:rdc:credential:dac-officer:1)で示す
- 承認記録は weko-dac が自分の鍵(承認記録専用、Visa の鍵とは別)で署名し、公開基盤のドメインで公開する
- 署名を求めるのは許諾を出す決定(approve / approve_with_conditions)だけ
"""

import base64
import hashlib
import json
import os
import uuid

import jwt

GRANT_TXDATA_TYPE = 'urn:rdc:txdata:data-access-grant:1'
DAC_OFFICER_VCT = 'urn:rdc:credential:dac-officer:1'
SUMMARY_TYP = 'rdc-approval-summary+jwt'
RECORD_TYP = 'rdc-approval-record+jwt'
LOG_TYP = 'rdc-approval-log+jwt'
GRANT_DECISIONS = ('approve', 'approve_with_conditions')
GRANT_REVERSIBLE = {
    'revocable': True,
    'how': '許諾は後から取り消せる(DAC の取り消し)。ただし取り消すまでに行われた取得は戻らない',
}


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def sha256_b64url(text):
    return b64url(hashlib.sha256(text.encode('utf-8')).digest())


# ---------------------------------------------------------------------------
# 取引(transaction_data)と説明文
# ---------------------------------------------------------------------------

def _line(label, value):
    if value is None or value == '' or value == []:
        v = '(なし)'
    elif isinstance(value, (list, tuple)):
        v = ', '.join(str(x) for x in value)
    else:
        v = str(value)
    return '- %s: %s' % (label, v)


def build_explanation(facts, officer_name, agent_id, not_after, reversible_how):
    """説明文を取引の事実から機械的に作る(R3-5)。同じ入力から同じ文字列になる。"""
    lines = [
        '# DAC の許諾の承認',
        '',
        'この承認は、あなたのウォレットの鍵で署名して初めて成立します。',
        'この説明文は公開基盤が取引の内容から機械的に作ったもので、AI の文章は含みません。',
        '',
        '## 取引の内容',
    ]
    lines += [_line(k, v) for k, v in facts]
    lines += ['', '## 責任と期限',
              _line('責任を持つ人(審査者)', officer_name),
              _line('許諾を出すサービス', agent_id),
              _line('この承認の期限', not_after),
              _line('取り消し', reversible_how), '']
    return '\n'.join(lines)


def grant_content(application, decision, reason, conditions, dac_id):
    """署名で束ねる許諾の中身。承認の後の決定も、この中身で確定する。"""
    payload = application.get('payload') or {}
    purpose = payload.get('purpose') or {}
    period = purpose.get('period') or {}
    researcher = ((payload.get('applicant') or {}).get('researcher') or {})
    return {
        'application_id': application['application_id'],
        'dac': dac_id,
        'datasets': [r.get('dataset_id') for r in payload.get('requests') or []
                     if r.get('dataset_id')],
        'researcher': {'sub': application.get('researcher_sub'),
                       'name': researcher.get('name')},
        'purpose': {'duo_codes': purpose.get('duo_codes') or [],
                    'description': purpose.get('description'),
                    'period_start': period.get('start'),
                    'period_end': period.get('end')},
        'decision': decision,
        'conditions': list(conditions or []),
        'grant_until': period.get('end'),
        'reason': reason,
    }


def build_grant_entry(content, officer, entity_id, explanation, not_after):
    """data-access-grant:1 の transaction_data エントリ(型固有の項目+共通の必須項目 8 つ)。"""
    entry = {
        'type': GRANT_TXDATA_TYPE,
        'credential_ids': ['rdc_officer'],
        'transaction_data_hashes_alg': ['sha-256'],
    }
    entry.update(content)
    entry.update({
        'responsible': {'id': 'urn:rdc:dac-officer:%s' % officer['id'],
                        'name': officer.get('name')},
        'agent': {'id': entity_id, 'version': None, 'operator': None},
        'target_data': [{'id': d, 'title': None, 'class': 'controlled'}
                        for d in content['datasets']],
        'scope': {'summary': '%s が、申請 %s のデータ %s の利用を許諾する(%s)' % (
            content['dac'], content['application_id'],
            ', '.join(content['datasets']), content['decision']),
            'budget': None},
        'not_after': not_after,
        'reversible': GRANT_REVERSIBLE,
        # 委任の証明はまだ渡らない(ADR-14 §0)。でっち上げない。
        'delegation_proof_hash': None,
        'explanation': explanation,
    })
    return entry


def session_create_body(entry):
    """verifier2 の提示要求(審査者の VC を 1 件、取引を 1 件)。"""
    return {
        'flow_type': 'cross_device',
        'core_flow': {
            'dcql_query': {'credentials': [{
                'id': 'rdc_officer', 'format': 'dc+sd-jwt', 'multiple': False,
                'require_cryptographic_holder_binding': True,
                'meta': {'vct_values': [DAC_OFFICER_VCT]},
                'claims': [{'path': ['authorized_role']}],
            }]},
            'signed_request': False,
            'encrypted_response': True,
            'policies': {'vc_policies': ['signature', 'expiration', 'not-before']},
        },
        'openid': {'transactionData': [entry], 'responseType': 'vp_token'},
    }


# ---------------------------------------------------------------------------
# VP の検査(verifier2 の /info)
# ---------------------------------------------------------------------------

def parse_presented(info):
    """提示された審査者の VC から、holder・役割・DAC・発行者・型を取り出す。"""
    pc = (info or {}).get('presented_credentials') or {}
    for v in pc.values():
        entry = v[0] if isinstance(v, list) and v else v
        cd = (entry or {}).get('credentialData') or {}
        if not cd:
            continue
        cnf = cd.get('cnf') or {}
        holder = (cnf.get('jwk') or {}).get('kid') or cnf.get('kid')
        scope = cd.get('authorized_scope') or {}
        return {'holder': holder, 'role': cd.get('authorized_role'),
                'dac_id': scope.get('dac_id'), 'issuer': cd.get('iss'),
                'vct': cd.get('vct')}
    return None


def evidence_of(info, session_id, holder):
    """② の証拠: VP の原本と、提示要求に実際に載った取引の文字列(ADR-13)。"""
    raw = ((info or {}).get('presented_raw_data') or {}).get('vpToken') or {}
    first = next(iter(raw.values()), None) if raw else None
    vp = first[0] if isinstance(first, list) and first else first
    td = (((info or {}).get('authorizationRequest') or {})
          .get('transaction_data') or [None])[0]
    if not isinstance(vp, str) or not isinstance(td, str):
        return {'evidence': 'vp_unavailable', 'verifier_session_id': session_id,
                'holder': holder}
    return {'evidence': 'vp', 'vp_token': vp, 'transaction_data': td,
            'holder': holder, 'verifier_session_id': session_id}


def check_officer(presented, trusted_issuers, dac_id):
    """審査者の VC か(信頼する発行者・型・役割・自分の DAC)。拒否は理由を返す。"""
    if not presented or not presented.get('holder'):
        return 'holder_mismatch'
    issuer = (presented.get('issuer') or '').split('#')[0]
    if not issuer or issuer not in trusted_issuers:
        return 'issuer_not_trusted'
    if presented.get('vct') != DAC_OFFICER_VCT:
        return 'not_dac_officer_credential'
    if presented.get('role') != 'dac_officer':
        return 'role_not_dac_officer'
    if presented.get('dac_id') != dac_id:
        return 'dac_not_authorized'
    return None


# ---------------------------------------------------------------------------
# 承認記録(ADR-11)と承認ログ(ADR-13)
# ---------------------------------------------------------------------------

def jwk_thumbprint(pub_jwk):
    canon = json.dumps({'crv': pub_jwk['crv'], 'kty': pub_jwk['kty'],
                        'x': pub_jwk['x'], 'y': pub_jwk['y']},
                       separators=(',', ':'), sort_keys=True)
    return sha256_b64url(canon)


def public_jwk_from_pem(pem):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_private_key(pem, password=None,
                                             backend=default_backend())
    nums = key.public_key().public_numbers()
    jwk = {'kty': 'EC', 'crv': 'P-256',
           'x': b64url(nums.x.to_bytes(32, 'big')),
           'y': b64url(nums.y.to_bytes(32, 'big'))}
    jwk.update({'kid': jwk_thumbprint(jwk), 'alg': 'ES256', 'use': 'sig'})
    return jwk


def _sign(payload, pem, kid, typ):
    tok = jwt.encode(payload, pem, algorithm='ES256',
                     headers={'kid': kid, 'typ': typ})
    return tok.decode('ascii') if isinstance(tok, bytes) else tok


def tx_disclosure(tx_hash, salt=None):
    """SD-JWT の開示 [salt, "tx_hash", 値](R9-7a)。"""
    s = salt or b64url(os.urandom(32))
    return b64url(json.dumps([s, 'tx_hash', tx_hash],
                             ensure_ascii=False).encode('utf-8'))


def sign_approval(pem, kid, issuer, approved_at, officer_id, holder,
                  session_id, txdata_hash, application_id, record_id=None):
    """公開要約と完全記録を別々の JWS に署名する(R9-6a)。"""
    record_id = record_id or str(uuid.uuid4())
    disclosure = tx_disclosure(txdata_hash) if txdata_hash else None
    summary = {
        'iss': issuer, 'jti': record_id, 'approved_at': approved_at,
        'assurance_level': 'vp',
        'agent': {'id': issuer, 'version': None},
        'tx_commitment': sha256_b64url(disclosure) if disclosure else None,
        '_sd_alg': 'sha-256',
    }
    summary_jws = _sign(summary, pem, kid, SUMMARY_TYP)
    full = {
        'iss': issuer, 'jti': record_id, 'approved_at': approved_at,
        'assurance_level': 'vp', 'summary_sha256': sha256_b64url(summary_jws),
        # 許諾の承認記録で「責任を持つ人」は決定した審査者(申請者ではない)
        'responsible': officer_id, 'approved_by': officer_id,
        'holder': holder, 'verifier_session_id': session_id,
        'agent': {'id': issuer, 'version': None, 'operator': None,
                  'stage_model': None},
        'tx_hash': txdata_hash, 'txdata_hash': txdata_hash,
        # 確かめられないことを、確かめたように書かない(R11-3、ADR-15)
        'key_custody': 'unattested',
        'tx_disclosure': disclosure, 'delegation_proof': None,
        'application_id': application_id,
    }
    return record_id, summary_jws, _sign(full, pem, kid, RECORD_TYP)


def next_log_entry(prev_jws, prev_seq, issuer, subject_id, kind, body, at):
    return {'iss': issuer, 'run_id': subject_id, 'seq': prev_seq + 1,
            'prev': sha256_b64url(prev_jws) if prev_jws else None,
            'kind': kind, 'at': at, 'body': body}


def sign_log_entry(payload, pem, kid):
    return _sign(payload, pem, kid, LOG_TYP)
