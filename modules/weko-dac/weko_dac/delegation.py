# -*- coding: utf-8 -*-
"""委任クレームの検証 — 検証者 (Clearinghouse) 側 (分冊05 §11.5.3 / 分冊01 §6.3 手順1)。

外側 JWS 検証済みの提示物 payload から ``delegation`` を取り出し、次を確かめる。

- **手順0 (裏づけ)**: ``as-receipt`` は AS 署名の委任レシート (``raw``) を AS の鍵で
  検証する — 本人鍵なしで委任の実在まで確かめられる (§11.5.5)。署名が通らなければ
  ``presentation-invalid`` (401) — 発行元でない主張を通さない。``hdc`` (本人署名) は
  Stage B であり、本人鍵の検証基盤が無いうちは fail-closed で拒む。``oauth-act`` は
  自己申告で裏づけの署名を持たない (実在は確かめられない)。
- **手順1-3 (範囲)**: 内包クレデンシャルの型が ``credential_types`` に含まれ、提示物の
  ``purpose`` が ``purposes`` に含まれ、提示物の ``iat`` が ``exp`` 以前であること。
  いずれかを満たさなければ ``presentation-delegation-mismatch`` (401)。

**この 401 は、ウォレットが発行を拒む 403 ``delegation-out-of-scope`` とは別事象である**
(分冊01 §5.8.4)。ここで見ているのは、受け取った提示物が **自らが載せた ``delegation`` の
範囲を超えて発行されていた** ことであり、発行時に決まる束縛の逸脱 (手順1 の 401 系と同じ
性格)。ウォレットの不具合・不正を示すため、取り直しても直らない。

``delegation`` が無い提示物は、移行期の互換のため素通りする (§11.5.4)。本モジュールは
DB / model に依存しない純関数群であり、:func:`presentation.verify_presentation` から呼ぶ。
"""

from flask import current_app

from .auth import AuthError, verify_jws, verify_jws_with_keys


def _verify_receipt(raw, expected_sub, expected_agent, expected_exp):
    """AS 署名の委任レシート (compact JWS) を AS の鍵で検証し payload を返す。

    鍵源は ``WEKO_DAC_AS_INLINE_JWKS`` (in-memory JWK 配列) を優先し、無ければ
    ``WEKO_DAC_OIDC_JWKS_URL`` から取得する (委任トークンを出す AS = 学認)。どちらも
    無ければ実在を確かめられないので 503 で断る (黙って通さない)。
    """
    issuer = current_app.config.get('WEKO_DAC_OIDC_ISSUER') or None
    inline = current_app.config.get('WEKO_DAC_AS_INLINE_JWKS')
    if inline:
        rp = verify_jws_with_keys(raw, inline, issuer=issuer)
    else:
        url = current_app.config.get('WEKO_DAC_OIDC_JWKS_URL')
        if not url:
            raise AuthError(
                503, 'delegation_verifier_unconfigured',
                'no AS key to verify the delegation receipt '
                '(set WEKO_DAC_AS_INLINE_JWKS or WEKO_DAC_OIDC_JWKS_URL)')
        rp = verify_jws(raw, url, issuer=issuer)
    # レシートは「この委任」についてのものでなければならない。主体・エージェント・
    # 期限がトークンの委任範囲と食い違うレシートは、取り違え・使い回しの疑い。
    if rp.get('sub') and expected_sub and rp['sub'] != expected_sub:
        raise AuthError(401, 'invalid_presentation',
                        'delegation receipt subject != presentation sub')
    if rp.get('agent') and expected_agent and rp['agent'] != expected_agent:
        raise AuthError(401, 'invalid_presentation',
                        'delegation receipt agent != presented_by')
    if (expected_exp is not None and rp.get('exp') is not None
            and rp['exp'] != expected_exp):
        raise AuthError(401, 'invalid_presentation',
                        'delegation receipt exp != delegation exp')
    return rp


def verify_delegation(payload, elements, meta):
    """提示物の ``delegation`` を検証し、``meta`` に裏づけ種別と ref を足して返す。

    ``delegation`` が無ければ ``meta`` をそのまま返す (移行互換 — §11.5.4)。
    逸脱時は :class:`AuthError` を送出する (呼出側で jti を消費する前に呼ぶこと)。
    """
    delegation = payload.get('delegation')
    if not isinstance(delegation, dict):
        return meta

    dtype = delegation.get('type')
    dcts = delegation.get('credential_types') or []
    dpurposes = delegation.get('purposes') or []
    dexp = delegation.get('exp')

    # --- 手順0: 裏づけ署名 ---
    if dtype == 'as-receipt':
        raw = delegation.get('raw')
        if not raw:
            raise AuthError(401, 'invalid_presentation',
                            'as-receipt delegation carries no raw receipt')
        try:
            _verify_receipt(raw, meta.get('sub'), meta.get('presented_by'), dexp)
        except AuthError as err:
            # AS 署名が通らないレシート = 実在を偽れない。presentation-invalid (401)。
            if err.code in ('invalid_token', 'token_expired'):
                raise AuthError(401, 'invalid_presentation',
                                'delegation receipt signature invalid: %s'
                                % err.detail)
            raise
    elif dtype == 'hdc':
        # Stage B。本人鍵 (holder) の検証基盤がこの Stage A 検証者には無いため、hdc の
        # 実在は確かめられない → fail-closed。ただしこれは提示物が「不正」なのではなく、
        # この検証者が当該委任種別に「未対応」であることを表す (§5.8.4)。混同しないよう
        # invalid_presentation とは別コードにする。
        raise AuthError(401, 'delegation_type_unsupported',
                        'delegation type "hdc" (holder-signed) is not verifiable by this '
                        'Stage A verifier; holder-key verification arrives in Stage B')
    elif dtype not in (None, 'oauth-act'):
        raise AuthError(401, 'delegation_type_unsupported',
                        'unknown delegation type %r' % dtype)
    # oauth-act は自己申告 (裏づけの署名なし)。実在は確かめられないが、範囲は確かめる。

    # --- 手順1-3: 範囲 (発行時の束縛の逸脱 → presentation-delegation-mismatch 401) ---
    out_types = [t for t in (e.get('credential_type') for e in elements)
                 if t not in dcts]
    if out_types:
        raise AuthError(
            401, 'presentation_delegation_mismatch',
            'credential type(s) outside the delegation: %s'
            % ', '.join(sorted({str(t) for t in out_types})))
    purpose = meta.get('purpose')
    if dpurposes and purpose not in dpurposes:
        raise AuthError(
            401, 'presentation_delegation_mismatch',
            'purpose %r is outside the delegation %r' % (purpose, dpurposes))
    iat = payload.get('iat') or 0
    if dexp is not None and iat > dexp:
        raise AuthError(
            401, 'presentation_delegation_mismatch',
            'presentation was issued after the delegation expired')

    meta = dict(meta)
    meta['delegation_type'] = dtype or 'oauth-act'
    meta['delegation_ref'] = delegation.get('ref')
    return meta
