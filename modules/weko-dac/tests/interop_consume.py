# -*- coding: utf-8 -*-
"""相互運用の実測 — 消費者 (検証者 / weko-dac, python)。

ウォレット (node) が実 signer で発行した提示物 JWS を、weko-dac の**実検証関数**に通す:
  - 外側署名: auth.verify_jws_with_keys(jws, [wallet_jwk], audience=aud)  … §6.3 手順1
  - 委任:     delegation.verify_delegation(payload, elements, meta)       … §11.5.3

node が書いた interop.json (鍵 + 3ケースの JWS) を読む。node↔python をまたいで
「両端がワイヤ上で噛み合う」ことを、通るものと拒否されるものの両方で確かめる。

実行: dacvenv/bin/python tests/interop_consume.py <interop.json>
"""
import json
import os
import sys

import flask

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from weko_dac import delegation  # noqa: E402
from weko_dac import auth  # noqa: E402
from weko_dac.auth import AuthError  # noqa: E402

results = []


def _ok(name, detail):
    results.append(True)
    print('PASS  %s — %s' % (name, detail))


def _bad(name, detail):
    results.append(False)
    print('FAIL  %s — %s' % (name, detail))


def _verify(art, jws):
    """weko-dac の実経路: 外側署名検証 → 委任検証。meta を返す。"""
    payload = auth.verify_jws_with_keys(
        jws, [art['wallet_jwk']], audience=art['aud'])
    creds = payload.get('credentials') or []
    elements = [{'credential_id': c.get('credential_id'),
                 'credential_type': c.get('credential_type'),
                 'credential_format': c.get('credential_format') or 'ga4gh-visa+jwt',
                 'raw': c.get('raw')} for c in creds]
    meta = {'sub': payload.get('sub'), 'presented_by': payload.get('presented_by'),
            'purpose': payload.get('purpose'), 'jti': payload.get('jti'),
            'iss': payload.get('iss')}
    return delegation.verify_delegation(payload, elements, meta), payload


def main():
    art = json.load(open(sys.argv[1]))
    app = flask.Flask(__name__)
    app.config.update(WEKO_DAC_OIDC_ISSUER=art['oidc_issuer'],
                      WEKO_DAC_AS_INLINE_JWKS=[art['as_jwk']])
    cases = art['cases']

    with app.app_context():
        # A: as-receipt (in-scope) → 外側署名 OK かつ委任も通る
        try:
            meta, _ = _verify(art, cases['as_receipt'])
            if meta.get('delegation_type') == 'as-receipt':
                _ok('A as-receipt', 'ウォレット署名を検証し、AS レシートも検証。delegation_type=as-receipt')
            else:
                _bad('A as-receipt', 'delegation_type=%r' % meta.get('delegation_type'))
        except Exception as e:
            _bad('A as-receipt', '通るべきが例外: %s' % e)

        # B: oauth-act (in-scope)
        try:
            meta, _ = _verify(art, cases['oauth_act'])
            if meta.get('delegation_type') == 'oauth-act':
                _ok('B oauth-act', 'ウォレット署名を検証。delegation_type=oauth-act')
            else:
                _bad('B oauth-act', 'delegation_type=%r' % meta.get('delegation_type'))
        except Exception as e:
            _bad('B oauth-act', '通るべきが例外: %s' % e)

        # C: 範囲外の捏造提示物 → 401 presentation_delegation_mismatch
        try:
            _verify(art, cases['bad_out_of_scope'])
            _bad('C 範囲外', '検証を通ってしまった (401 で拒否されるべき)')
        except AuthError as e:
            if e.status == 401 and e.code == 'presentation_delegation_mismatch':
                _ok('C 範囲外', '401 presentation_delegation_mismatch で拒否 (実鍵署名でも範囲逸脱を検出)')
            else:
                _bad('C 範囲外', '想定と違う拒否: %s/%s' % (e.status, e.code))
        except Exception as e:
            _bad('C 範囲外', 'AuthError でない例外: %s' % e)

        # 対照1: A を 1 文字改竄 → 外側署名検証が落ちる (署名を本当に見ている)
        tampered = cases['as_receipt'][:-3] + ('AAA' if cases['as_receipt'][-3:] != 'AAA' else 'BBB')
        try:
            _verify(art, tampered)
            _bad('対照 改竄JWS', '改竄が通ってしまった')
        except AuthError as e:
            if e.status == 401 and e.code in ('invalid_token', 'token_expired'):
                _ok('対照 改竄JWS', '改竄した提示物は外側署名検証で 401 (%s)' % e.code)
            else:
                _bad('対照 改竄JWS', '想定と違う: %s/%s' % (e.status, e.code))
        except Exception as e:
            _bad('対照 改竄JWS', 'AuthError でない例外: %s' % e)

        # 対照2: 誤った鍵 (AS 鍵) で外側を検証 → 落ちる (噛むのはウォレット鍵だけ)
        try:
            auth.verify_jws_with_keys(cases['oauth_act'], [art['as_jwk']], audience=art['aud'])
            _bad('対照 誤鍵', 'AS 鍵で外側が通ってしまった')
        except AuthError:
            _ok('対照 誤鍵', 'ウォレット鍵以外では外側署名は通らない (両端が同じ鍵で噛む)')
        except Exception as e:
            _bad('対照 誤鍵', 'AuthError でない例外: %s' % e)

    n = len(results)
    p = sum(1 for r in results if r)
    print('\n%d/%d PASS' % (p, n))
    sys.exit(0 if p == n else 1)


if __name__ == '__main__':
    main()
