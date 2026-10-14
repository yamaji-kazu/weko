# -*- coding: utf-8 -*-
"""研究者の AI エージェントによるプレプリントの登録(aifs ADR-37)。POST /dac/v1/preprints

論文の OJS への投稿と同時に、論文とエビデンスデータを 1 件のアイテムとしてプレプリントのインデックスに登録し、公開する。
包みは SWORD v3 の SWORDBagIt(メタデータは RO-Crate を metadata/sword.json に置く)で、取り込みは WEKO の SWORD と
同じ関数で行う。既存の SWORD の入口は WEKO の OAuth のトークン(固定の鍵)を前提にしているので使わず、OJS の受け口
(ojs-rdc の rdcSubmission、aifs ADR-35 §4.3)と同じく、委任のトークンと、本人がスマホで承認した記録で受ける。

送るもの(multipart/form-data): file(bag の zip)、approval_record(承認記録の JWS)、transaction_data(スマホに載せた取引)。
ヘッダ: Authorization: Bearer <委任のトークン>、Digest: SHA-256=<zip の hex>、Content-Disposition は使わない。

断るときは PreprintReject(HTTP のステータスと固定の code)を投げる。code は試験で拒否の形まで固定するためのもの。
"""

import base64
import hashlib
import json
import os
import shutil
import tempfile
import time
import zipfile
from datetime import datetime, timedelta, timezone

import jwt
import requests
from flask import current_app, g, jsonify, request
from invenio_db import db

from .auth import _requests_verify, verify_jws, verify_jws_with_keys, AuthError
from .models import DacPreprintJti, DacIdpUser

RECORD_TYP = 'rdc-approval-record+jwt'
_ISSUER_JWKS = {}


class PreprintReject(Exception):
    def __init__(self, status, code, message):
        super(PreprintReject, self).__init__(message)
        self.status, self.code, self.message = status, code, message

    def response(self):
        return jsonify({'error': self.code, 'errorMessage': self.message}), self.status


def _cfg(name, default=None):
    return current_app.config.get('WEKO_DAC_PREPRINT_' + name, default)


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


# ───────────────────────── 確かめ(OJS の受け口と同じ決まり) ─────────────────────────

def verify_token(authorization):
    """委任のトークン(sub=本人、act=投稿エージェント、aud=weko、scope=weko:deposit)を確かめて claims を返す。"""
    if not authorization or not authorization.startswith('Bearer '):
        raise PreprintReject(401, 'token_missing', '委任のトークンがありません(Authorization: Bearer <token>)')
    token = authorization[len('Bearer '):].strip()
    issuer = current_app.config.get('WEKO_DAC_OIDC_ISSUER')
    jwks = current_app.config.get('WEKO_DAC_OIDC_JWKS_URL') or (issuer.rstrip('/') + '/protocol/openid-connect/certs')
    try:
        claims = verify_jws(token, jwks, issuer=issuer, audience=None)
    except AuthError as e:
        raise PreprintReject(401, 'token_invalid', 'トークンの署名か期限が正しくありません: %s' % e)
    aud = claims.get('aud')
    aud = aud if isinstance(aud, list) else [aud]
    if _cfg('AUDIENCE', 'weko') not in aud:
        raise PreprintReject(401, 'token_wrong_audience', 'このトークンは WEKO 宛てではありません')
    if _cfg('SCOPE', 'weko:deposit') not in (claims.get('scope') or '').split():
        raise PreprintReject(403, 'insufficient_scope', 'トークンに %s がありません' % _cfg('SCOPE', 'weko:deposit'))
    if not claims.get('sub'):
        raise PreprintReject(401, 'token_invalid', 'トークンに sub がありません')
    actor = (claims.get('act') or {}).get('sub')
    if not actor:
        raise PreprintReject(403, 'not_delegated', 'エージェントへの委任(act)のないトークンです')
    if actor not in (_cfg('AGENTS') or []):
        raise PreprintReject(403, 'agent_not_allowed', '登録された投稿エージェントではありません')
    return claims


def _issuer_keys(url):
    hit = _ISSUER_JWKS.get(url)
    if hit and time.time() - hit[0] < 300:
        return hit[1]
    resp = requests.get(url, timeout=10, verify=_requests_verify())
    resp.raise_for_status()
    keys = [k for k in resp.json().get('keys', []) if k.get('use', 'sig') == 'sig']
    _ISSUER_JWKS[url] = (time.time(), keys)
    return keys


def verify_approval(jws, sub):
    """DG の承認記録(完全記録の ES256 の JWS)を確かめる。スマホで承認したもの(txdata_hash あり)だけを受ける。"""
    if not jws or jws.count('.') != 2:
        raise PreprintReject(400, 'approval_missing', '承認記録がありません')
    try:
        header = jwt.get_unverified_header(jws)
        unverified = json.loads(_b64url_decode(jws.split('.')[1]))
    except Exception:
        raise PreprintReject(403, 'approval_invalid', '承認記録の形が違います')
    url = (_cfg('APPROVAL_ISSUERS') or {}).get(unverified.get('iss') or '')
    if not url:
        raise PreprintReject(403, 'approval_invalid', '承認記録の発行者を信頼していません')
    try:
        rec = verify_jws_with_keys(jws, _issuer_keys(url))
    except AuthError as e:
        raise PreprintReject(403, 'approval_invalid', '承認記録の署名が正しくありません: %s' % e)
    except requests.RequestException as e:
        raise PreprintReject(503, 'approval_issuer_unreachable', '承認記録の発行者の公開鍵を読めません: %s' % e)
    if header.get('alg') != 'ES256' or header.get('typ') != RECORD_TYP:
        raise PreprintReject(403, 'approval_invalid', '承認記録の形が違います(完全記録の ES256 の JWS ではない)')
    if rec.get('iss') != unverified.get('iss'):
        raise PreprintReject(403, 'approval_invalid', '承認記録の発行者が違います')
    if not rec.get('txdata_hash'):
        raise PreprintReject(403, 'approval_not_vp', 'スマホでの承認ではありません')
    if rec.get('responsible') not in (sub, 'urn:rdc:holder:%s' % sub):
        raise PreprintReject(403, 'approval_wrong_person', '承認した本人と、委任した本人が違います')
    return rec


def open_transaction(encoded, rec):
    """スマホに載せた取引を、承認記録の txdata_hash と照らして開く。プレプリントの部分が要る。"""
    if not encoded or not all(c.isalnum() or c in '-_' for c in encoded):
        raise PreprintReject(400, 'transaction_missing', '取引の中身がありません')
    if b64url(hashlib.sha256(encoded.encode('ascii')).digest()) != rec['txdata_hash']:
        raise PreprintReject(409, 'transaction_mismatch', '取引の中身が、承認されたものと違います')
    try:
        tx = json.loads(_b64url_decode(encoded))
    except Exception:
        raise PreprintReject(400, 'transaction_missing', '取引の中身が読めません')
    if not isinstance(tx, dict) or tx.get('type') not in (_cfg('TXDATA_TYPES') or []):
        raise PreprintReject(403, 'transaction_wrong_type', 'プレプリントの登録を含む取引ではありません')
    na = tx.get('not_after')
    if na:
        try:
            if datetime.fromisoformat(na.replace('Z', '+00:00')) < datetime.now(timezone.utc):
                raise PreprintReject(403, 'approval_expired', '承認の期限を過ぎています')
        except ValueError:
            raise PreprintReject(400, 'transaction_incomplete', '承認の期限が読めません')
    pre = tx.get('preprint')
    if not isinstance(pre, dict) or not isinstance(pre.get('files'), list) or not pre['files']:
        raise PreprintReject(400, 'transaction_incomplete', '取引にプレプリントの中身(preprint.files)がありません')
    return tx


def check_binding(tx, bag_dir, crate):
    """届いた包みが、承認された取引のとおりであること(登録先・インデックス・公開・ライセンス・ファイルの一式と中身)。"""
    pre = tx['preprint']
    if pre.get('repository') != _cfg('REPOSITORY'):
        raise PreprintReject(409, 'repository_mismatch', '登録先が、承認されたものと違います')
    index = str(_cfg('INDEX_ID'))
    if str(pre.get('index')) != index:
        raise PreprintReject(409, 'index_mismatch', '登録先のインデックスが、承認されたものと違います')
    if pre.get('license') != _cfg('LICENSE', 'CC-BY-4.0'):
        raise PreprintReject(409, 'license_mismatch', 'ライセンスが、この受け口で公開できるものと違います')
    graph = crate.get('@graph') or []
    root = next((e for e in graph if e.get('@id') == './'), None)
    if not root:
        raise PreprintReject(400, 'crate_invalid', 'RO-Crate のルート(./)がありません')
    if [str(x) for x in (root.get('wk:index') or [])] != [index]:
        raise PreprintReject(409, 'index_mismatch', 'RO-Crate の登録先のインデックスが、承認されたものと違います')
    if root.get('wk:publishStatus') != 'public':
        raise PreprintReject(409, 'publish_status_mismatch', 'RO-Crate の公開の状態が public ではありません')
    # ファイルの一式と中身: data/ の下の全ファイルが、承認された一覧と名前・SHA-256 で過不足なく一致すること
    want = {f.get('name'): (f.get('sha256') or '').lower() for f in pre['files']}
    data = os.path.join(bag_dir, 'data')
    got = {}
    for d, _, names in os.walk(data):
        for n in names:
            p = os.path.join(d, n)
            h = hashlib.sha256()
            with open(p, 'rb') as fh:
                for b in iter(lambda: fh.read(1 << 20), b''):
                    h.update(b)
            got[os.path.relpath(p, data)] = h.hexdigest()
    if got != want:
        raise PreprintReject(409, 'files_mismatch', '包みのファイルが、承認されたものと違います(%s)'
                             % ', '.join(sorted(set(got.items()) ^ set(want.items()), key=str)[:5]))
    files = [e for e in graph if e.get('@type') == 'File']
    if any(e.get('license') != 'license_0' for e in files):
        raise PreprintReject(409, 'license_mismatch', 'RO-Crate のファイルのライセンスが CC BY 4.0(license_0)ではありません')


def claim_approval(rec):
    """同じ承認記録での登録は 1 回だけ(登録に失敗したら release_approval で戻す)。"""
    jti = rec.get('jti')
    if not jti or DacPreprintJti.query.get(jti):
        raise PreprintReject(409, 'approval_already_used', 'この承認記録では、すでに登録しています')
    db.session.add(DacPreprintJti(jti=jti, sub=rec.get('responsible')))
    db.session.commit()


def release_approval(rec):
    DacPreprintJti.query.filter_by(jti=rec.get('jti')).delete()
    db.session.commit()


# ───────────────────────── 本人の WEKO の利用者 ─────────────────────────

def resolve_user(claims):
    """IdP の sub に結んだ WEKO の利用者。無ければトークンの氏名・メールで作り、投稿者(Contributor)の役割を付ける。
    同じメールの WEKO の利用者が別にいれば、作りも結びもせず断る(メールだけで結ぶと、他人の利用者を乗っ取れる。ADR-35 §9)"""
    from invenio_accounts.models import Role, User
    from invenio_accounts.proxies import current_datastore
    link = DacIdpUser.query.get(claims['sub'])
    if link:
        user = User.query.get(link.user_id)
        if not user or not user.active:
            raise PreprintReject(403, 'weko_account_disabled', '本人の WEKO の利用者が無効です')
        return user, False
    email = (claims.get('email') or '').strip().lower()
    if not email:
        raise PreprintReject(400, 'email_missing', 'トークンにメールアドレスがありません')
    if User.query.filter(db.func.lower(User.email) == email).first():
        raise PreprintReject(409, 'weko_account_conflict', '同じメールの WEKO の利用者が、別にあります(結びません)')
    user = current_datastore.create_user(email=email, active=True, password=None,
                                         confirmed_at=datetime.utcnow())
    role = Role.query.filter_by(name=_cfg('ROLE', 'Contributor')).first()
    if role:
        current_datastore.add_role_to_user(user, role)
    db.session.flush()
    db.session.add(DacIdpUser(sub=claims['sub'], user_id=user.id))
    db.session.commit()
    return user, True


# ───────────────────────── 口 ─────────────────────────

def deposit():
    """POST /dac/v1/preprints。確かめが全部通ったら、本人の WEKO の利用者として、SWORD の取り込みで登録する。"""
    from flask_login import login_user
    from flask_principal import Identity, identity_changed
    from weko_admin.api import TempDirInfo
    from weko_search_ui.utils import check_jsonld_import_items, import_items_to_system
    from weko_swordserver.utils import notify_about_item

    tmp = None
    rec = None
    claimed = False
    try:
        claims = verify_token(request.headers.get('Authorization'))
        rec = verify_approval(request.form.get('approval_record'), claims['sub'])
        tx = open_transaction(request.form.get('transaction_data'), rec)
        f = request.files.get('file')
        if not f:
            raise PreprintReject(400, 'package_missing', '包み(SWORDBagIt の zip)がありません')
        raw = f.read()
        digest = request.headers.get('Digest') or ''
        sha = hashlib.sha256(raw).hexdigest()
        if digest != 'SHA-256=' + sha:
            raise PreprintReject(412, 'digest_mismatch', 'Digest が包みの中身と合いません')
        if (tx['preprint'].get('package_sha256') or '').lower() != sha:
            raise PreprintReject(409, 'package_mismatch', '包みが、承認されたものと違います')
        tmp = tempfile.mkdtemp(prefix='rdc-preprint-')
        zpath = os.path.join(tmp, 'bag.zip')
        with open(zpath, 'wb') as out:
            out.write(raw)
        bag = os.path.join(tmp, 'bag')
        try:
            with zipfile.ZipFile(zpath) as z:
                for n in z.namelist():
                    if n.startswith('/') or '..' in n.split('/'):
                        raise PreprintReject(400, 'package_invalid', '包みに不正なパスがあります')
                z.extractall(bag)
            crate = json.load(open(os.path.join(bag, 'metadata', 'sword.json'), encoding='utf-8'))
        except PreprintReject:
            raise
        except Exception as e:
            raise PreprintReject(400, 'package_invalid', '包みが読めません: %s' % e)
        check_binding(tx, bag, crate)

        user, provisioned = resolve_user(claims)
        login_user(user)
        identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
        claim_approval(rec)
        claimed = True

        result = check_jsonld_import_items(zpath, 'http://purl.org/net/sword/3.0/package/SWORDBagIt',
                                           _cfg('MAPPING_ID'), ['Original'], [])
        data_path = result.get('data_path', '')
        try:
            if result.get('error'):
                raise PreprintReject(422, 'weko_validation_failed', 'WEKO の検査に通りません: %s' % result['error'])
            items = result.get('list_record') or []
            if len(items) != 1 or items[0].get('errors') or items[0].get('status') != 'new':
                errs = ', '.join((items[0].get('errors') or [])) if items else 'item_missing'
                raise PreprintReject(422, 'weko_validation_failed', 'WEKO の検査に通りません: %s' % errs)
            # SWORD の入口と同じく、一時フォルダは 1 日で消える印を付ける(下の finally でも消す)
            TempDirInfo().set(data_path, {'expire': (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')})
            item = items[0]
            item['root_path'] = os.path.join(data_path, 'data')
            out = import_items_to_system(item, request_info={
                'remote_addr': request.remote_addr, 'referrer': request.referrer,
                'hostname': request.host, 'user_id': user.id, 'action': 'IMPORT', 'workflow_id': None})
            if not out.get('success'):
                raise PreprintReject(500, 'import_failed', 'WEKO に登録できませんでした: %s' % out.get('error_id'))
            recid = str(out.get('recid'))
            try:
                notify_about_item('import', recid, user.id, shared_ids=[])
            except Exception:  # 知らせに失敗しても登録は済んでいる
                current_app.logger.warning('preprint: notify_about_item に失敗 recid=%s', recid)
        finally:
            if data_path and os.path.exists(data_path):
                shutil.rmtree(data_path, ignore_errors=True)
                try:
                    TempDirInfo().delete(data_path)
                except Exception:
                    pass
        base = (current_app.config.get('THEME_SITEURL') or request.host_url).rstrip('/')
        current_app.logger.info('preprint: 登録した recid=%s user=%s agent=%s approval=%s',
                                recid, user.id, (claims.get('act') or {}).get('sub'), rec.get('jti'))
        return jsonify({
            'recid': recid, 'url': '%s/records/%s' % (base, recid),
            'received': {'package_sha256': sha, 'approval_record': rec.get('jti'),
                         'weko_account': 'provisioned' if provisioned else 'existing',
                         'files': sorted(f['name'] for f in tx['preprint']['files'])},
        }), 201
    except PreprintReject as r:
        if claimed:
            release_approval(rec)
        return r.response()
    except Exception as e:  # 想定外。承認記録は使い済みにしない
        current_app.logger.exception('preprint: 登録に失敗')
        if claimed:
            release_approval(rec)
        return jsonify({'error': 'deposit_failed', 'errorMessage': '登録できませんでした: %s' % e}), 500
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
