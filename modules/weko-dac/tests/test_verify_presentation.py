# -*- coding: utf-8 -*-
"""検証者の外側検証 + 委任検証の統合 — verify_presentation (分冊01 §6.3 / 分冊05 §11.5)。

verify_presentation は models(DacPresentationJti)/invenio_db に触れるが、それらは jti の
リプレイ記録のためだけで、委任・用途・署名の検証には関係しない。ここでは両者を軽い stub に
置き換え、**ウォレット署名の提示物 JWS を実際に組み立てて verify_presentation に通す**。

    cd modules/weko-dac && dacvenv/bin/python -m pytest tests/test_verify_presentation.py -q

確かめること (拒否は status と code まで固定):
  - 用途不一致 → 401 presentation_purpose_mismatch (§6.3 手順1。旧実装の 400 invalid_presentation を是正)
  - in-scope の oauth-act / as-receipt → 通り、meta に delegation_type が載る
  - 委任範囲外 → 401 presentation_delegation_mismatch (外側+委任の統合経路で)
"""
import sys
import time
import types
import uuid

import flask
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

# --- models / invenio_db を軽い stub に (jti リプレイ記録のためだけの依存) ---
_inv = types.ModuleType('invenio_db')
_inv.db = types.SimpleNamespace(session=types.SimpleNamespace(add=lambda *a, **k: None))
sys.modules.setdefault('invenio_db', _inv)

_models = types.ModuleType('weko_dac.models')


class DacPresentationJti(object):
    def __init__(self, jti=None, presented_by=None):
        self.jti = jti

    class query(object):
        @staticmethod
        def get(jti):
            return None  # リプレイなし


_models.DacPresentationJti = DacPresentationJti
sys.modules.setdefault('weko_dac.models', _models)

import os  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from weko_dac import presentation, allowlist  # noqa: E402
from weko_dac.auth import AuthError  # noqa: E402

ISS_WALLET = 'https://wallet.example'
ISS_AS = 'https://as.example/auth/realms/rdc'
AUD = 'https://data.rdc.nii.ac.jp'
HOLDER = 'urn:holder:alice'
AGENT = 'https://dg.rdc.nii.ac.jp/agents/dar-001'
TYPES = ['rdc:ResearcherStatus', 'rdc:AcceptedTerms']
PURPOSES = ['registered-access', 'data-retrieval']


def _key(kid):
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = ECAlgorithm(ECAlgorithm.SHA256).to_jwk(priv.public_key(), as_dict=True)
    jwk.update(kid=kid, alg='ES256', use='sig')
    return priv, jwk


WALLET_PRIV, WALLET_JWK = _key('wallet-1')
AS_PRIV, AS_JWK = _key('as-receipt-1')


def _app():
    app = flask.Flask(__name__)
    app.config.update(
        WEKO_DAC_ENTITY_ID=AUD,
        WEKO_DAC_PRESENTATION_AUD=AUD,
        WEKO_DAC_PRESENTATION_MAX_AGE=300,
        WEKO_DAC_PRESENTATION_TYPES={'rdc-gp+jwt': True},
        WEKO_DAC_OIDC_ISSUER=ISS_AS,
        WEKO_DAC_AS_INLINE_JWKS=[AS_JWK],
    )
    return app


def _receipt(exp):
    return jwt.encode(
        {'sub': HOLDER, 'agent': AGENT, 'iss': ISS_AS,
         'credential_types': TYPES, 'purposes': PURPOSES, 'exp': exp},
        AS_PRIV, algorithm='ES256', headers={'kid': 'as-receipt-1'})


def _presentation(purpose='data-retrieval', cred_types=('rdc:ResearcherStatus',),
                  delegation=None):
    now = int(time.time())
    claims = {
        'sub': HOLDER, 'presented_by': AGENT, 'purpose': purpose,
        'credentials': [{'credential_id': 'wc-%d' % i, 'credential_type': t,
                         'credential_format': 'ga4gh-visa+jwt', 'raw': 'raw.%d' % i}
                        for i, t in enumerate(cred_types)],
        'iss': ISS_WALLET, 'aud': AUD, 'iat': now, 'exp': now + 300,
        'jti': 'gp-' + uuid.uuid4().hex,
    }
    if delegation is not None:
        claims['delegation'] = delegation
    return jwt.encode(claims, WALLET_PRIV, algorithm='ES256',
                      headers={'kid': 'wallet-1', 'typ': 'rdc-gp+jwt'})


def _deleg(dtype='oauth-act', cts=None, purposes=None, exp=None, raw=None):
    exp = exp if exp is not None else int(time.time()) + 3600
    d = {'type': dtype, 'ref': 'dt-1',
         'credential_types': cts if cts is not None else TYPES,
         'purposes': purposes if purposes is not None else PURPOSES, 'exp': exp}
    if raw is not None:
        d['raw'] = raw
    return d


@pytest.fixture(autouse=True)
def _patch_allowlist(monkeypatch):
    """allowlist を config でなく直接差し替える (テストの独立性)。"""
    monkeypatch.setattr(allowlist, 'wallet_inline_jwks', lambda: [WALLET_JWK])
    monkeypatch.setattr(allowlist, 'wallet_entity', lambda: {'entity_id': ISS_WALLET})
    monkeypatch.setattr(allowlist, 'check_agent', lambda a: 'allowed')


def _verify(pres, expected_purpose='data-retrieval'):
    with _app().app_context():
        return presentation.verify_presentation(pres, expected_purpose=expected_purpose)


# --- 通るもの -------------------------------------------------------------

def test_oauth_act_in_scope_passes():
    meta, elements = _verify(_presentation(delegation=_deleg('oauth-act')))
    assert meta['delegation_type'] == 'oauth-act'
    assert meta['delegation_ref'] == 'dt-1'
    assert len(elements) == 1


def test_as_receipt_in_scope_passes():
    exp = int(time.time()) + 3600
    d = _deleg('as-receipt', exp=exp, raw=_receipt(exp))
    meta, _ = _verify(_presentation(delegation=d))
    assert meta['delegation_type'] == 'as-receipt'


def test_no_delegation_passes_migration():
    meta, _ = _verify(_presentation(delegation=None))
    assert 'delegation_type' not in meta


# --- 拒否されるべきもの ---------------------------------------------------

def test_purpose_mismatch_is_401():
    """用途不一致は 401 presentation_purpose_mismatch (旧: 400 invalid_presentation)。"""
    with pytest.raises(AuthError) as ei:
        # 提示物は registered-access だが、経路は data-retrieval を要求
        _verify(_presentation(purpose='registered-access', delegation=_deleg()),
                expected_purpose='data-retrieval')
    assert ei.value.status == 401
    assert ei.value.code == 'presentation_purpose_mismatch'


def test_delegation_out_of_scope_is_401_via_verify_presentation():
    """委任範囲外の型は、外側+委任の統合経路で 401 presentation_delegation_mismatch。"""
    d = _deleg('oauth-act', cts=['rdc:AcceptedTerms'])  # ResearcherStatus を許さない
    with pytest.raises(AuthError) as ei:
        _verify(_presentation(cred_types=('rdc:ResearcherStatus',), delegation=d))
    assert ei.value.status == 401
    assert ei.value.code == 'presentation_delegation_mismatch'


if __name__ == '__main__':
    sys.exit(pytest.main([__file__, '-q']))
