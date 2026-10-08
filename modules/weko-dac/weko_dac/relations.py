# -*- coding: utf-8 -*-
"""⑤ Announce Relationship の受け止め(承認プロファイル §3・R3-3・R6-1、aifs ADR-25)。

DG が「このリポジトリのデータセット(主語)は、DG の承認記録の要約(目的語)から参照される」と告げる。
**通知は指すだけで、成立の根拠にしない。** リポジトリは参照先 — DG が署名した関係の資源と、承認記録の
要約 — を DG のドメインから取り直し、DG の署名を確かめてから記録する(R6-1)。関係の資源には宛先が
入っているので、別のリポジトリ宛ての関係を流用されても気づける。

HTTP にも DB にも触らない純関数にして、拒否の形を単体で固定する(取得の手段は呼び出し側が渡す)。
"""
import base64
from urllib.parse import urlparse

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

RELATION_TYP = 'rdc-approval-relation+jwt'
SUMMARY_TYP = 'rdc-approval-summary+jwt'
#: 受ける関係の語。独自の語を作らない(承認プロファイル R3-2)
IS_REFERENCED_BY = 'http://purl.org/dc/terms/isReferencedBy'


class RelationReject(Exception):
    """受けない通知。status と code で拒否の形を固定する。"""

    def __init__(self, status, code, detail=''):
        super(RelationReject, self).__init__(detail or code)
        self.status = status
        self.code = code
        self.detail = detail


def _types(v):
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)] if isinstance(v, str) else []


def same_origin(url, origin_id):
    """URL が送信者(origin)と同じスキーム・ホスト・ポートにあるか。"""
    try:
        a, b = urlparse(url), urlparse(origin_id)
    except Exception:
        return False
    return bool(a.scheme and a.netloc) and (a.scheme, a.netloc) == (b.scheme, b.netloc)


def check_envelope(body, repository_id, allowed_origins):
    """取りに行く前に、形・宛先・送信者・参照先の場所を確かめる。ここで落ちるものは参照先を取りに行かない。

    Returns (fields, origin) — origin は allowed_origins の 1 件({'id', 'jwks_uri'})。
    """
    if not isinstance(body, dict):
        raise RelationReject(400, 'not_an_announce_relationship', 'JSON オブジェクトではありません')
    types = _types(body.get('type'))
    if 'Announce' not in types or 'coar-notify:RelationshipAction' not in types:
        raise RelationReject(400, 'not_an_announce_relationship',
                             'この inbox が受けるのは Announce Relationship だけです')
    obj = body.get('object') if isinstance(body.get('object'), dict) else {}
    fields = {
        'id': body.get('id'),
        'relation_url': obj.get('id'),
        'subject': obj.get('as:subject'),
        'relationship': obj.get('as:relationship'),
        'record_url': obj.get('as:object'),
        'context': (body.get('context') or {}).get('id') if isinstance(body.get('context'), dict) else None,
    }
    if not all(isinstance(fields[k], str) and fields[k] for k in fields):
        raise RelationReject(400, 'not_an_announce_relationship',
                             'id・object(id・as:subject・as:relationship・as:object)・context が要ります')
    target = body.get('target') if isinstance(body.get('target'), dict) else {}
    if target.get('id') != repository_id:
        raise RelationReject(403, 'target_mismatch', 'このリポジトリ宛ての通知ではありません')
    origin_id = (body.get('origin') or {}).get('id') if isinstance(body.get('origin'), dict) else None
    origin = next((o for o in allowed_origins if o.get('id') == origin_id), None)
    if origin is None:
        raise RelationReject(403, 'origin_not_allowed', '許可していない送信者です')
    if not same_origin(fields['relation_url'], origin['id']) or not same_origin(fields['record_url'], origin['id']):
        raise RelationReject(403, 'object_not_on_origin', '参照先が送信者のドメインにありません')
    if fields['relationship'] != IS_REFERENCED_BY:
        raise RelationReject(400, 'unsupported_relationship', '受ける関係は dct:isReferencedBy だけです')
    if fields['context'] != fields['subject']:
        raise RelationReject(400, 'not_an_announce_relationship', 'context は主語のデータセットであること(R3-4)')
    return fields, origin


def _b64url_int(v):
    return int.from_bytes(base64.urlsafe_b64decode(v + '=' * (-len(v) % 4)), 'big')


def _ec_public_key(jwk):
    """P-256 の JWK から公開鍵を組む。WEKO の PyJWT(1.5.3)は EC の from_jwk に対応していないので、
    cryptography で直接組む(auth.jwk_to_public_key と同じやり方)。"""
    if jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256':
        raise ValueError('ES256(P-256)の鍵ではありません')
    nums = ec.EllipticCurvePublicNumbers(_b64url_int(jwk['x']), _b64url_int(jwk['y']), ec.SECP256R1())
    return nums.public_key(default_backend())


def _verify(token, keys, issuer, typ):
    header = jwt.get_unverified_header(token)
    if header.get('typ') != typ:
        raise ValueError('typ=%s' % header.get('typ'))
    kid = header.get('kid')
    cand = [k for k in keys if not kid or k.get('kid') == kid] or keys
    last = None
    for k in cand:
        try:
            key = _ec_public_key(k)
            return jwt.decode(token, key, algorithms=['ES256'], issuer=issuer,
                              options={'verify_aud': False})
        except Exception as ex:  # 次の鍵を試す
            last = ex
    raise ValueError('署名を確かめられません: %s' % last)


def verify_references(fields, origin, repository_id, fetch_text, fetch_keys):
    """参照先を DG のドメインから取り直して確かめる(R6-1)。

    fetch_text(url) -> str(JWS)、fetch_keys(jwks_uri) -> list(JWK)。どちらも失敗したら例外を投げる。
    Returns 関係の資源の中身(dict)。
    """
    try:
        keys = fetch_keys(origin['jwks_uri'])
        rel = _verify(fetch_text(fields['relation_url']).strip(), keys, origin['id'], RELATION_TYP)
    except Exception as ex:
        raise RelationReject(403, 'object_unverifiable', '関係の資源を確かめられません: %s' % ex)
    want = {'subject': fields['subject'], 'relationship': fields['relationship'],
            'object': fields['record_url'], 'target': repository_id}
    for k, v in want.items():
        if rel.get(k) != v:
            raise RelationReject(403, 'relation_mismatch',
                                 '関係の資源の %s が通知と違います' % k)
    try:
        summary = _verify(fetch_text(fields['record_url']).strip(), keys, origin['id'], SUMMARY_TYP)
    except Exception as ex:
        raise RelationReject(403, 'record_unverifiable', '承認記録の要約を確かめられません: %s' % ex)
    if summary.get('jti') != rel.get('record_id'):
        raise RelationReject(403, 'record_unverifiable', '承認記録の要約が関係の資源の記録と違います')
    return rel
