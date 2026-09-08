# -*- coding: utf-8 -*-
"""Shared Presentation verifier (RDC-AAP-01 §6.3 / §11.2.2, 分冊05 §11).

v0.4 で提示物は **複数クレデンシャルを 1 回で運ぶ配列形式** になった。本モジュールは
提示物の **外側 (Wallet 署名の JWS)** を検証し、内包する `credentials` 配列を取り出す
部分を、registered-access (§11.2.2) と access-token (§6.3) で **共有** する。

内包クレデンシャルの署名検証は発行者ごとに鍵源が異なる (資格系=Visa 発行者/学認、
`DataAccessGrant`=当 DAC) ため、**各要素の内側検証は呼出側が行う**。本モジュールは
外側検証と配列抽出までを担う。

判定に用いる値は必ず **原本 (`raw`)** から読むこと (分冊05 §11.3)。外側の索引
(`credential_type` 等) は署名対象外で、振り分けにのみ用いる。
"""

import time

import jwt as pyjwt
from flask import current_app

from . import allowlist
from .auth import AuthError, jwk_to_public_key, verify_jws
from .models import DacPresentationJti


def _expected_aud():
    return (current_app.config.get('WEKO_DAC_PRESENTATION_AUD')
            or current_app.config['WEKO_DAC_ENTITY_ID'])


#: GA4GH Visa type → rdc: credential_type (分冊04 §5.3.2 の写像)
_GA4GH_TO_RDC = {
    'ControlledAccessGrants': 'rdc:DataAccessGrant',
    'ResearcherStatus': 'rdc:ResearcherStatus',
    'AffiliationAndRole': 'rdc:Affiliation',
    'AcceptedTermsAndPolicies': 'rdc:AcceptedTerms',
}
#: resource を持つ (資源を対象とする) 許諾系の GA4GH type
_RESOURCE_BEARING = {'ControlledAccessGrants'}


def check_issuer_authority(ga4gh_type, source, offer_assigner):
    """発行者信頼の二段検証 (RDC-AAP-01 §3.2)。

    - 型の権限 (§3.2.1): 発行者 (``source``) が allowlist に登録され、その
      ``allowed_credential_types`` に当該型を含むこと。
    - 資源の権限 (§3.2.2): resource を持つ許諾系のみ、``source`` == Offer の
      ``odrl:assigner`` (分冊05 §3)。

    ``WEKO_DAC_ENFORCE_ISSUER_TRUST`` が False の間は未強制 (移行期。allowlist に
      ``allowed_credential_types`` が入るまで現行フローを壊さない)。不適合は
    ``AuthError(403, 'issuer_not_authorized')``。
    """
    if not current_app.config.get('WEKO_DAC_ENFORCE_ISSUER_TRUST', False):
        return
    rdc_type = _GA4GH_TO_RDC.get(ga4gh_type, ga4gh_type)
    entry = allowlist.get_entity(source) if source else None
    allowed = (entry or {}).get('allowed_credential_types')
    if not entry or not allowed or rdc_type not in allowed:
        raise AuthError(403, 'issuer_not_authorized',
                        'issuer %r is not authorized to issue %s'
                        % (source, rdc_type))
    if ga4gh_type in _RESOURCE_BEARING and source != offer_assigner:
        raise AuthError(403, 'issuer_not_authorized',
                        'issuer_ref %r != Offer assigner %r'
                        % (source, offer_assigner))


def _decode_outer(presentation):
    """Verify the Wallet-signed outer JWS. Returns the payload."""
    try:
        header = pyjwt.get_unverified_header(presentation)
    except Exception as ex:
        raise AuthError(400, 'invalid_presentation',
                        'Malformed presentation: %s' % ex)
    typ = header.get('typ')
    handlers = current_app.config['WEKO_DAC_PRESENTATION_TYPES']
    if typ not in handlers:
        raise AuthError(400, 'unsupported_presentation_type',
                        'typ %s not accepted' % typ)
    aud = _expected_aud()
    inline_keys = allowlist.wallet_inline_jwks()
    if inline_keys:
        key = None
        for k in inline_keys:
            if not header.get('kid') or k.get('kid') == header['kid']:
                key = k
                break
        try:
            return pyjwt.decode(
                presentation, jwk_to_public_key(key),
                algorithms=['ES256', 'RS256'], audience=aud)
        except AuthError:
            raise
        except Exception as ex:
            raise AuthError(401, 'invalid_presentation',
                            'Presentation verification failed: %s' % ex)
    wallet_jwks = allowlist.wallet_jwks_url()
    if not wallet_jwks:
        raise AuthError(503, 'wallet_not_configured',
                        'No wallet jwks (allowlist or '
                        'WEKO_DAC_WALLET_JWKS_URL)')
    return verify_jws(presentation, wallet_jwks, audience=aud)


def _elements_from_payload(payload):
    """§11.2 の読み順: ``credentials`` があればそれ、無ければ単数 ``credential``
    を要素1件の配列として扱う。各要素は原本 ``raw`` と索引を持つ。"""
    creds = payload.get('credentials')
    if isinstance(creds, list) and creds:
        out = []
        for c in creds:
            if not isinstance(c, dict):
                raise AuthError(400, 'invalid_presentation',
                                'credentials element is not an object')
            raw = c.get('raw')
            if not raw:
                raise AuthError(400, 'invalid_presentation',
                                'credentials element missing raw')
            out.append({
                'credential_id': c.get('credential_id'),
                'credential_type': c.get('credential_type'),
                'credential_format': c.get('credential_format')
                or 'ga4gh-visa+jwt',
                'raw': raw})
        return out
    # 単数形 (v0.3 互換) — 分冊05 §11.2
    single = payload.get('credential')
    if single:
        return [{
            'credential_id': payload.get('credential_id'),
            'credential_type': None,
            'credential_format': 'ga4gh-visa+jwt',
            'raw': single}]
    raise AuthError(400, 'invalid_presentation',
                    'neither credentials[] nor credential present')


def verify_presentation(presentation, expected_purpose=None):
    """外側検証 + 配列抽出。``(meta, elements)`` を返す。

    meta: ``{sub, presented_by, purpose, jti, iss}``。
    elements: ``[{credential_id, credential_type, credential_format, raw}]``。
    内包クレデンシャルの署名/失効/値の検証は **呼出側** が原本 ``raw`` に対して行う。
    """
    payload = _decode_outer(presentation)
    wallet_entity = allowlist.wallet_entity()
    if wallet_entity and payload.get('iss') != wallet_entity['entity_id']:
        raise AuthError(403, 'unknown_wallet',
                        'Presentation issuer %s is not the allowlisted '
                        'wallet' % payload.get('iss'))
    # 鮮度 (iat + 300 は Wallet が保証。受信側でも上限を再確認)
    max_age = current_app.config['WEKO_DAC_PRESENTATION_MAX_AGE']
    iat = payload.get('iat') or 0
    if time.time() - iat > max_age:
        raise AuthError(401, 'presentation_expired',
                        'Presentation older than %ds' % max_age)
    # リプレイ防止
    jti = payload.get('jti')
    if not jti:
        raise AuthError(400, 'invalid_presentation', 'jti missing')
    if DacPresentationJti.query.get(jti):
        raise AuthError(409, 'presentation_replayed', 'jti already used')
    # 提示エージェントの allowlist (Trust Chain 代替)
    presented_by = payload.get('presented_by')
    if allowlist.check_agent(presented_by or '') == 'denied':
        raise AuthError(403, 'agent_not_allowlisted',
                        'presented_by %s is not in the static allowlist'
                        % presented_by)
    # 用途 (§11.1 purpose)。呼出側が用途を指定した場合は一致必須
    purpose = payload.get('purpose')
    if expected_purpose is not None and purpose != expected_purpose:
        raise AuthError(400, 'invalid_presentation',
                        'presentation purpose %r != expected %r'
                        % (purpose, expected_purpose))
    elements = _elements_from_payload(payload)
    # jti を消費 (検証成功後)。呼出側の commit に含める
    from invenio_db import db
    db.session.add(DacPresentationJti(jti=jti, presented_by=presented_by))
    meta = {'sub': payload.get('sub'), 'presented_by': presented_by,
            'purpose': purpose, 'jti': jti, 'iss': payload.get('iss')}
    return meta, elements
