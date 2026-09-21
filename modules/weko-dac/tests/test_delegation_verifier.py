# -*- coding: utf-8 -*-
"""検証者 (Clearinghouse) 側の委任検証 — 分冊05 §11.5.3 / 分冊01 §6.3 手順1。

delegation.py は models/DB に依存しないので、WEKO の環境なしで走る:
    cd modules/weko-dac && python3 -m pytest tests/test_delegation_verifier.py -q

拒否されるべきものが拒否されることを、通るものと同じ数だけ見る。拒否は status と
code まで固定する — 「範囲外を検出した」で満足しない (分冊01 §5.8.4)。
"""
import json
import os
import sys
import time

import flask
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from weko_dac import delegation  # noqa: E402
from weko_dac.auth import AuthError  # noqa: E402

ISS = 'https://as.example/auth/realms/rdc'
HOLDER = 'urn:holder:alice'
AGENT = 'https://dg.rdc.nii.ac.jp/agents/dar-001'
TYPES = ['rdc:ResearcherStatus', 'rdc:AcceptedTerms']
PURPOSES = ['registered-access', 'data-retrieval']


def _make_as_key():
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = ECAlgorithm(ECAlgorithm.SHA256).to_jwk(priv.public_key(), as_dict=True)
    jwk.update(kid='as-1', alg='ES256', use='sig')
    return priv, jwk


AS_PRIV, AS_JWK = _make_as_key()
OTHER_PRIV, _ = _make_as_key()  # 偽造レシート用の別鍵


def _app():
    app = flask.Flask(__name__)
    app.config.update(
        WEKO_DAC_OIDC_ISSUER=ISS,
        WEKO_DAC_AS_INLINE_JWKS=[AS_JWK],
    )
    return app


def _receipt(priv=None, sub=HOLDER, agent=AGENT, cts=None, purposes=None, exp=None):
    exp = exp if exp is not None else int(time.time()) + 3600
    return jwt.encode(
        {'sub': sub, 'agent': agent, 'iss': ISS,
         'credential_types': cts or TYPES, 'purposes': purposes or PURPOSES,
         'exp': exp},
        priv or AS_PRIV, algorithm='ES256', headers={'kid': 'as-1'})


def _payload(dtype='oauth-act', cts=None, purposes=None, exp=None, raw=None,
             iat=None, ref='dt-1'):
    exp = exp if exp is not None else int(time.time()) + 3600
    deleg = {'type': dtype, 'ref': ref,
             'credential_types': cts if cts is not None else TYPES,
             'purposes': purposes if purposes is not None else PURPOSES,
             'exp': exp}
    if raw is not None:
        deleg['raw'] = raw
    return {'iat': iat if iat is not None else int(time.time()), 'delegation': deleg}


def _elements(types):
    return [{'credential_type': t, 'credential_id': 'wc', 'raw': 'r',
             'credential_format': 'ga4gh-visa+jwt'} for t in types]


def _meta(purpose='data-retrieval'):
    return {'sub': HOLDER, 'presented_by': AGENT, 'purpose': purpose,
            'jti': 'gp-1', 'iss': 'https://wallet'}


def _run(payload, elements, meta):
    with _app().app_context():
        return delegation.verify_delegation(payload, elements, meta)


# --- 通るもの -------------------------------------------------------------

def test_no_delegation_passes_through():
    """delegation 無しは移行互換で素通り (§11.5.4)。meta は変わらない。"""
    meta = _meta()
    out = _run({'iat': int(time.time())}, _elements(['rdc:ResearcherStatus']), meta)
    assert out == meta
    assert 'delegation_type' not in out


def test_oauth_act_in_scope():
    """oauth-act で範囲内 → 通る。実在は確かめられないが範囲は確かめる。"""
    out = _run(_payload('oauth-act'), _elements(['rdc:ResearcherStatus']), _meta())
    assert out['delegation_type'] == 'oauth-act'
    assert out['delegation_ref'] == 'dt-1'


def test_as_receipt_in_scope_verified():
    """as-receipt で AS 署名が通り、範囲内 → 通る (本人鍵なしで実在まで確認)。"""
    exp = int(time.time()) + 3600
    payload = _payload('as-receipt', exp=exp, raw=_receipt(exp=exp))
    out = _run(payload, _elements(['rdc:ResearcherStatus', 'rdc:AcceptedTerms']), _meta())
    assert out['delegation_type'] == 'as-receipt'


# --- 拒否されるべきもの ---------------------------------------------------

def test_type_out_of_scope_rejected():
    """委任範囲外の型 → 401 presentation_delegation_mismatch。"""
    with pytest.raises(AuthError) as ei:
        _run(_payload('oauth-act'), _elements(['rdc:DataAccessGrant']), _meta())
    assert ei.value.status == 401
    assert ei.value.code == 'presentation_delegation_mismatch'


def test_purpose_out_of_scope_rejected():
    """委任範囲外の purpose → 401 presentation_delegation_mismatch。"""
    with pytest.raises(AuthError) as ei:
        _run(_payload('oauth-act', purposes=['registered-access']),
             _elements(['rdc:ResearcherStatus']), _meta('data-retrieval'))
    assert ei.value.status == 401
    assert ei.value.code == 'presentation_delegation_mismatch'


def test_delegation_expired_rejected():
    """委任の期限より後に発行された提示物 → 401 presentation_delegation_mismatch。"""
    past = int(time.time()) - 100
    with pytest.raises(AuthError) as ei:
        _run(_payload('oauth-act', exp=past, iat=int(time.time())),
             _elements(['rdc:ResearcherStatus']), _meta())
    assert ei.value.status == 401
    assert ei.value.code == 'presentation_delegation_mismatch'


def test_forged_receipt_rejected():
    """AS でない鍵で署名したレシート → 401 invalid_presentation (実在は偽れない)。"""
    exp = int(time.time()) + 3600
    forged = _receipt(priv=OTHER_PRIV, exp=exp)
    with pytest.raises(AuthError) as ei:
        _run(_payload('as-receipt', exp=exp, raw=forged),
             _elements(['rdc:ResearcherStatus']), _meta())
    assert ei.value.status == 401
    assert ei.value.code == 'invalid_presentation'


def test_hdc_not_yet_verifiable():
    """hdc (本人署名) は Stage B。検証基盤が無いうちは fail-closed で 401。"""
    with pytest.raises(AuthError) as ei:
        _run(_payload('hdc', raw='x'), _elements(['rdc:ResearcherStatus']), _meta())
    assert ei.value.status == 401
    assert ei.value.code == 'invalid_presentation'


def test_receipt_subject_mismatch_rejected():
    """レシートの主体が提示物の sub と食い違う → 401 invalid_presentation。"""
    exp = int(time.time()) + 3600
    wrong = _receipt(sub='urn:holder:mallory', exp=exp)
    with pytest.raises(AuthError) as ei:
        _run(_payload('as-receipt', exp=exp, raw=wrong),
             _elements(['rdc:ResearcherStatus']), _meta())
    assert ei.value.status == 401
    assert ei.value.code == 'invalid_presentation'


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-q']))
