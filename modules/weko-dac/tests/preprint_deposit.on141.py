#!/usr/bin/env python3
"""プレプリントの登録の口(aifs ADR-37)の試験。141 で `python3 preprint_deposit.on141.py`。

許すべきものを許し、断るべきものを決めた形(ステータスと code)で断ることを確かめる。

- IdP に一時の利用者を作り、本人のトークンを dg-portal で取り、投稿エージェント(pub-agent)が weko:deposit で交換する
- 承認記録は試験用の鍵で署名する(DG の本物の鍵は使わない — それは本物の承認記録の偽造になる)。試験のあいだだけ、
  WEKO の web のコンテナの中に公開鍵を置く小さな HTTP サーバを立て、発行者のファイルに試験用の発行者を足す
- 終わったら、作ったアイテムを消し(soft delete)、WEKO の利用者を無効にして結びつきを消し、IdP の利用者を消し、
  発行者のファイルと公開鍵の HTTP サーバを片付ける
パスワード・シークレットは画面に出さない。
"""
import base64
import hashlib
import io
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import uuid
import zipfile

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec

HOSTS = {"db.nii-rdc.mydns.jp": "10.20.116.19", "idp.nii-rdc.mydns.jp": "10.20.112.103"}
_orig = socket.getaddrinfo
socket.getaddrinfo = lambda host, *a, **k: _orig(HOSTS.get(host, host), *a, **k)

WEKO = "https://db.nii-rdc.mydns.jp"
RECV = f"{WEKO}/api/dac/v1/preprints"
IDP = "https://idp.nii-rdc.mydns.jp/auth/realms/rdc"
INDEX = "1791972117955"
TEST_ISS = f"urn:rdc:test-dg:{secrets.token_hex(3)}"
ISSUERS_FILE = "/home/mdxuser/dev/weko/scripts/rdc-preprint-test-issuers.json"  # コンテナの中では /code/scripts/…
JWKS_DIR = "/tmp/rdc-preprint-test-jwks"
JWKS_PORT = 8765
KC = "cd /opt/aifs-idp && sudo docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"
KILL_SERVER = ("docker exec weko-web-1 sh -c 'for p in /proc/[0-9]*; do c=$(tr \"\\\\0\" \" \" < $p/cmdline 2>/dev/null); "
               "case \"$c\" in \"python -m http.server %d\"*) kill ${p#/proc/};; esac; done'")  # コンテナに ps・pkill が無い。探す側の sh 自身に当たらないよう、先頭で照らす

REQ_VERIFY = False  # 141 から 140 は自己署名でない LE の証明書だが、内部 IP に向けるので名前の検査だけにしない

results = []
# 試験で登録されたアイテム(後片付けで消す)。断るはずの確かめが 201 を返した場合も控える — 2026-10-14 の変異の確かめで、
# 確かめを外した版が登録した 2 件が控えに入らず、公開されたまま残った
made_recids = []


def sh(cmd, inp=None):
    return subprocess.run(cmd, shell=True, input=inp, capture_output=True, text=True, executable="/bin/bash")


def weko(cmd, inp=None):
    return subprocess.run(["ssh", "weko140", cmd], input=inp, capture_output=True, text=True)


def psql(sql):
    return weko("docker exec -i weko-postgresql-1 psql -U invenio -d invenio -At -F '|'", sql).stdout.strip()


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def stable(v):
    if isinstance(v, list):
        return "[" + ",".join(stable(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + stable(v[k]) for k in sorted(v)) + "}"
    return json.dumps(v, ensure_ascii=False)


def check(name, resp, status, code=None):
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = {"raw": resp.text[:300]}
    if resp.status_code == 201 and body.get("recid"):
        made_recids.append(str(body["recid"]))
    ok = resp.status_code == status and (code is None or body.get("error") == code)
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: 期待 {status} {code or ''} / 実際 {resp.status_code} {body.get('error', '')}"
          + ("" if ok else f"  {body.get('errorMessage', body)}"))
    return body


def kc_login():
    r = sh("cd /opt/aifs-idp && source <(sudo cat .env) && sudo docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "
           "config credentials --server http://localhost:8080/auth --realm master "
           "--user \"$KC_BOOTSTRAP_ADMIN_USERNAME\" --password \"$KC_BOOTSTRAP_ADMIN_PASSWORD\" >/dev/null 2>&1; echo $?")
    assert r.stdout.strip().endswith("0"), "kcadm にログインできない"


def make_idp_user(prefix, email=None):
    u = f"{prefix}-{secrets.token_hex(3)}"
    pw = secrets.token_urlsafe(18) + "Aa1!"
    sh(f"bash -c '{KC} create users -r rdc -s username={u} -s enabled=true -s emailVerified=true "
       f"-s email={email or u + '@example.invalid'} -s firstName=試験 -s lastName=登録者'")
    uid = sh(f"bash -c '{KC} get users -r rdc -q username={u} -q exact=true --fields id --format csv --noquotes'").stdout.strip()
    sh(f"bash -c '{KC} update users/{uid} -r rdc -s requiredActions=[] -s attributes.researcher_link_exempt=[\\\"true\\\"]'")
    r = subprocess.run(["bash", "-c", f"{KC} set-password -r rdc --userid {uid} --new-password \"$P\""],
                       env={**os.environ, "P": pw}, capture_output=True, text=True)
    assert r.returncode == 0, f"パスワードを置けない: {r.stderr[:200]}"
    return u, pw, uid


def user_token(u, pw):
    r = requests.post(f"{IDP}/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "dg-portal", "username": u, "password": pw, "scope": "openid"})
    assert r.status_code == 200, f"本人のトークンを取れない: {r.status_code} {r.text[:200]}"
    return r.json()["access_token"]


def exchange(subject_token, secret, scope="weko:deposit", audience="weko"):
    data = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "client_id": "pub-agent",
            "client_secret": secret, "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token"}
    if scope:
        data["scope"] = scope
    if audience:
        data["audience"] = audience
    return requests.post(f"{IDP}/protocol/openid-connect/token", data=data)


# ───────── 包み(SWORDBagIt。RO-Crate は metadata/sword.json) ─────────
def crate(files, title="受け口の試験のプレプリント", index=INDEX, status="public", license_="license_0"):
    today = time.strftime("%Y-%m-%d")
    g = [
        {"@id": "ro-crate-metadata.json", "@type": "CreativeWork",
         "conformsTo": {"@id": "https://w3id.org/ro/crate/1.1"}, "about": {"@id": "./"}},
        {"@id": "./", "@type": "Dataset", "datePublished": today, "wk:index": [index], "wk:publishStatus": status,
         "dc:title": [{"@id": "#title-ja"}], "jpcoar:creator": [{"@id": "#creator0"}],
         "datacite:description": [{"@id": "#abstract-ja"}], "dc:type": {"@id": "#type"},
         "oaire:version": {"@id": "#version"}, "dcterms:accessRights": {"@id": "#access"},
         "dc:language": [{"@id": "#lang"}], "hasPart": [{"@id": n} for n in files]},
        {"@id": "#title-ja", "@type": "PropertyValue", "value": title, "language": "ja"},
        {"@id": "#creator0", "@type": "Person", "jpcoar:creatorName": [{"@id": "#creator0-name"}]},
        {"@id": "#creator0-name", "@type": "PropertyValue", "value": "登録者, 試験", "language": "ja"},
        {"@id": "#abstract-ja", "@type": "PropertyValue", "value": "試験の要旨。", "descriptionType": "Abstract", "language": "ja"},
        {"@id": "#type", "@type": "PropertyValue", "value": "preprint", "rdf:resource": "http://purl.org/coar/resource_type/c_816b"},
        {"@id": "#version", "@type": "PropertyValue", "value": "SMUR", "rdf:resource": "http://purl.org/coar/version/c_71e4c1898caa6e32"},
        {"@id": "#access", "@type": "PropertyValue", "value": "open access", "rdf:resource": "http://purl.org/coar/access_right/c_abf2"},
        {"@id": "#lang", "@type": "PropertyValue", "value": "jpn"},
    ]
    for n, (mime, size) in files.items():
        g.append({"@id": n, "@type": "File", "name": n, "dcterms:accessRights": "open_access", "license": license_,
                  "jpcoar:mimeType": mime, "datePublished": today})
    return {"@context": ["https://w3id.org/ro/crate/1.1/context", {"wk": "http://purl.org/wk/v1/wk-context.jsonld"}],
            "@graph": g}


def bag(data, crate_obj, extra_tag=None):
    """data: {名前: bytes}。BagIt 1.0(sha256)の zip のバイト列を返す"""
    sha = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
    files = {f"data/{n}": b for n, b in data.items()}
    tags = {
        "bagit.txt": b"BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n",
        "bag-info.txt": f"Bagging-Date: {time.strftime('%Y-%m-%d')}\nPayload-Oxum: {sum(len(b) for b in data.values())}.{len(data)}\n".encode(),
        "metadata/sword.json": json.dumps(crate_obj, ensure_ascii=False).encode(),
        "manifest-sha256.txt": "".join(f"{sha(b)}  {p}\n" for p, b in sorted(files.items())).encode(),
    }
    tags.update(extra_tag or {})
    tags["tagmanifest-sha256.txt"] = "".join(f"{sha(b)}  {p}\n" for p, b in sorted(tags.items())).encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p, b in {**files, **tags}.items():
            z.writestr(p, b)
    return out.getvalue()


def main():
    kc_login()
    key = ec.generate_private_key(ec.SECP256R1())
    n = key.public_key().public_numbers()
    kid = "test-" + secrets.token_hex(4)
    pub = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big")),
           "kid": kid, "alg": "ES256", "use": "sig"}
    other = ec.generate_private_key(ec.SECP256R1())
    users = []
    try:
        # 試験の公開鍵を、web のコンテナの中だけで届く HTTP サーバに置き、試験の発行者を足す
        weko(f"docker exec -i weko-web-1 sh -c 'mkdir -p {JWKS_DIR} && cat > {JWKS_DIR}/jwks.json'", json.dumps({"keys": [pub]}))
        weko(KILL_SERVER % JWKS_PORT)  # 前の回の残り(フォルダが消えたまま応答しない)を止める
        # WEKO のコンテナの Python は 3.6 で、http.server に --directory が無い(2026-10-14、それで起動していなかった)
        weko(f"docker exec -d weko-web-1 sh -c 'cd {JWKS_DIR} && exec python -m http.server {JWKS_PORT} --bind 127.0.0.1'")
        weko(f"cat > {ISSUERS_FILE}", json.dumps({TEST_ISS: f"http://127.0.0.1:{JWKS_PORT}/jwks.json"}))
        time.sleep(2)
        up = weko(f"docker exec weko-web-1 python -c \"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:{JWKS_PORT}/jwks.json').read()[:20])\"").stdout
        assert "keys" in up, f"試験の公開鍵の HTTP サーバが起動していない: {up!r}"

        u1, pw1, id1 = make_idp_user("weko-pre"); users.append(id1)
        # 同じメールの WEKO の利用者(IdP に結びつかない)を先に作り、そのメールの IdP の利用者を作る。メールだけで結ばないことを見る
        conflict = f"weko-pre-conflict-{secrets.token_hex(3)}@example.invalid"
        psql(f"insert into accounts_user (email, active) values ('{conflict}', true);")
        # 前提を確かめる(2026-10-14、列名を誤った insert が黙って失敗し、食い違いの試験の前提が崩れていた)
        assert psql(f"select count(*) from accounts_user where email='{conflict}';") == "1", "同じメールの WEKO の利用者を作れていない"
        u3, pw3, id3 = make_idp_user("weko-pre", email=conflict); users.append(id3)
        secret = json.loads(sh(f"bash -c '{KC} get clients/$({KC} get clients -r rdc -q clientId=pub-agent --fields id "
                               f"--format csv --noquotes | head -1)/client-secret -r rdc'").stdout)["value"]
        ut1 = user_token(u1, pw1)
        r = exchange(ut1, secret)
        assert r.status_code == 200, f"Token Exchange に失敗: {r.status_code} {r.text[:300]}"
        dt1 = r.json()["access_token"]
        c = jwt.decode(dt1, options={"verify_signature": False})
        print(f"委任のトークン: sub={c['sub'][:8]}… act={c.get('act')} aud={c.get('aud')} scope={c.get('scope')} email_verified={c.get('email_verified')}")
        sub1 = c["sub"]

        paper = b"%PDF-1.4\n% RDC preprint test " + secrets.token_hex(8).encode() + b"\n%%EOF\n"
        data = {"paper_ja.pdf": paper, "evidence.zip": b"PK\x05\x06" + b"\x00" * 18,
                "ro-crate_run.json": b'{"@context":"https://w3id.org/ro/crate/1.1/context","@graph":[]}',
                "review.json": b'{"Decision":"Reject"}'}
        mimes = {"paper_ja.pdf": ("application/pdf", 0), "evidence.zip": ("application/zip", 0),
                 "ro-crate_run.json": ("application/ld+json", 0), "review.json": ("application/json", 0)}
        good_bag = bag(data, crate(mimes))
        files = [{"name": k, "sha256": hashlib.sha256(v).hexdigest(), "bytes": len(v)} for k, v in data.items()]

        def tx(pkg=good_bag, **over):
            t = {"type": "urn:rdc:txdata:manuscript-submission:2",
                 "responsible": {"id": f"urn:rdc:holder:{sub1}"},
                 "not_after": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
                 "venue": {"ojs": "https://ojs.test", "journal": "rdc", "section": "ART"},
                 "manuscript": {"title": "受け口の試験のプレプリント", "language": "ja", "sha256": "x", "file_name": "paper_ja.pdf"},
                 "authors": [{"given_name": "試験", "family_name": "登録者", "email": f"{u1}@example.invalid", "corresponding": True, "is_submitter": True}],
                 "preprint": {"repository": WEKO, "index": INDEX, "license": "CC-BY-4.0",
                              "package_sha256": hashlib.sha256(pkg).hexdigest(), "files": files, "excluded": 0}}
            t.update(over)
            return t

        def enc(t):
            return b64u(stable(t).encode("utf-8"))

        def record(t_enc, signer=key, iss=TEST_ISS, responsible=None, web=False, typ="rdc-approval-record+jwt"):
            p = {"iss": iss, "jti": str(uuid.uuid4()), "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "responsible": responsible or sub1,
                 "txdata_hash": None if web else b64u(hashlib.sha256(t_enc.encode("ascii")).digest())}
            return jwt.encode(p, signer, algorithm="ES256", headers={"typ": typ, "kid": kid})

        def post(token, t_enc, rec, pkg=good_bag, digest=None):
            h = {"Digest": digest or f"SHA-256={hashlib.sha256(pkg).hexdigest()}"}
            if token:
                h["Authorization"] = f"Bearer {token}"
            return requests.post(RECV, headers=h, data={"approval_record": rec, "transaction_data": t_enc},
                                 files={"file": ("bag.zip", pkg, "application/zip")}, verify=REQ_VERIFY, timeout=120)

        good = enc(tx())
        # ── 断るべきもの ──
        check("トークンなし", post(None, good, record(good)), 401, "token_missing")
        r = exchange(ut1, secret, scope="ojs:submit", audience="ojs")
        check("OJS 宛ての委任のトークン", post(r.json()["access_token"], good, record(good)), 401, "token_wrong_audience")
        check("本人のトークン(委任でない)", post(ut1, good, record(good)), 401, "token_wrong_audience")
        check("署名を壊した委任のトークン", post(dt1[:-4] + ("AAAA" if dt1[-4:] != "AAAA" else "BBBB"), good, record(good)), 401, "token_invalid")
        check("承認記録なし", post(dt1, good, ""), 400, "approval_missing")
        check("JWKS に無い鍵で署名した承認記録", post(dt1, good, record(good, signer=other)), 403, "approval_invalid")
        check("信頼していない発行者の承認記録", post(dt1, good, record(good, iss="https://evil.example")), 403, "approval_invalid")
        check("要約(完全記録でない typ)", post(dt1, good, record(good, typ="rdc-approval-summary+jwt")), 403, "approval_invalid")
        check("ウェブでの承認(txdata_hash なし)", post(dt1, good, record(good, web=True)), 403, "approval_not_vp")
        check("別の人の承認記録", post(dt1, good, record(good, responsible="00000000-0000-0000-0000-000000000000")), 403, "approval_wrong_person")
        check("取引の中身を書き換えた", post(dt1, enc(tx(preprint={**tx()["preprint"], "license": "CC0"})), record(good)), 409, "transaction_mismatch")
        v1 = enc(tx(type="urn:rdc:txdata:manuscript-submission:1"))
        check("プレプリントを含まない型(:1)の取引", post(dt1, v1, record(v1)), 403, "transaction_wrong_type")
        exp = enc(tx(not_after="2020-01-01T00:00:00Z"))
        check("期限を過ぎた承認", post(dt1, exp, record(exp)), 403, "approval_expired")
        check("Digest が包みと合わない", post(dt1, good, record(good), digest="SHA-256=" + "0" * 64), 412, "digest_mismatch")
        other_bag = bag({**data, "review.json": b'{"Decision":"Accept"}'}, crate(mimes))
        check("承認と違う包み(中身を 1 つ替えた)", post(dt1, good, record(good), pkg=other_bag), 409, "package_mismatch")
        extra = bag({**data, "secret.csv": b"id,value\n1,2\n"}, crate({**mimes, "secret.csv": ("text/csv", 0)}))
        tx_extra = enc(tx(pkg=extra))
        check("承認に無いファイルが包みにある", post(dt1, tx_extra, record(tx_extra), pkg=extra), 409, "files_mismatch")
        wrong_idx_bag = bag(data, crate(mimes, index="1789045797567"))
        t_idx = enc(tx(pkg=wrong_idx_bag))
        check("RO-Crate の登録先のインデックスが違う", post(dt1, t_idx, record(t_idx), pkg=wrong_idx_bag), 409, "index_mismatch")
        priv_bag = bag(data, crate(mimes, status="private"))
        t_priv = enc(tx(pkg=priv_bag))
        check("RO-Crate の公開の状態が private", post(dt1, t_priv, record(t_priv), pkg=priv_bag), 409, "publish_status_mismatch")
        lic_bag = bag(data, crate(mimes, license_="license_free"))
        t_lic = enc(tx(pkg=lic_bag))
        check("RO-Crate のファイルのライセンスが CC BY 4.0 でない", post(dt1, t_lic, record(t_lic), pkg=lic_bag), 409, "license_mismatch")
        t_repo = enc(tx(preprint={**tx()["preprint"], "repository": "https://other.example"}))
        check("承認した登録先が別のリポジトリ", post(dt1, t_repo, record(t_repo)), 409, "repository_mismatch")
        # 同じメールの別の WEKO の利用者がいる本人
        dt3 = exchange(user_token(u3, pw3), secret).json()["access_token"]
        sub3 = jwt.decode(dt3, options={"verify_signature": False})["sub"]
        t3 = tx(); t3["responsible"] = {"id": f"urn:rdc:holder:{sub3}"}; t3 = enc(t3)
        check("同じメールの WEKO の利用者が別にいる", post(dt3, t3, record(t3, responsible=sub3)), 409, "weko_account_conflict")
        n3 = psql(f"select count(*) from dac_idp_user where sub='{sub3}';")
        ok = n3 == "0"; results.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  食い違いのとき、結びつきを作らない({n3} 件)")
        # IdP でメールを確かめていない本人(aifs ADR-38 §5)。realm は未確認の利用者にトークンを出さないので、確認済みで
        # 本人のトークンを取ってから未確認に戻し、交換する(交換は、その時点の利用者の状態で中身を作る)
        u4, pw4, id4 = make_idp_user("weko-pre"); users.append(id4)
        ut4 = user_token(u4, pw4)
        sh(f"bash -c '{KC} update users/{id4} -r rdc -s emailVerified=false'")
        dt4 = exchange(ut4, secret).json()["access_token"]
        c4 = jwt.decode(dt4, options={"verify_signature": False})
        sub4 = c4["sub"]
        ok = c4.get("email_verified") is False; results.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  前提: 未確認に戻した本人の委任のトークンの email_verified={c4.get('email_verified')}")
        t4 = tx(); t4["responsible"] = {"id": f"urn:rdc:holder:{sub4}"}; t4 = enc(t4)
        check("IdP でメールを確かめていない本人", post(dt4, t4, record(t4, responsible=sub4)), 403, "email_unverified")
        n4 = psql(f"select count(*) from dac_idp_user where sub='{sub4}';")
        m4 = psql(f"select count(*) from accounts_user where lower(email)='{u4}@example.invalid';")
        ok = n4 == "0" and m4 == "0"; results.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  未確認のとき、WEKO の利用者も結びつきも作らない(利用者 {m4} 件・結びつき {n4} 件)")

        # ── 許すべきもの ──
        rec = record(good)
        body = check("正しい登録", post(dt1, good, rec), 201)
        recid = body.get("recid")
        check("同じ承認記録での 2 回目", post(dt1, good, rec), 409, "approval_already_used")
        if recid:
            rcv = body.get("received") or {}
            ok = rcv.get("package_sha256") == hashlib.sha256(good_bag).hexdigest() and rcv.get("weko_account") == "provisioned" \
                and rcv.get("files") == sorted(data)
            results.append(ok)
            print(f"{'PASS' if ok else 'FAIL'}  応答の received: 包みの一致={rcv.get('package_sha256') == hashlib.sha256(good_bag).hexdigest()} "
                  f"利用者={rcv.get('weko_account')} ファイル={rcv.get('files')}")
            meta = json.loads(psql(f"select json::text from records_metadata r join pidstore_pid p on p.object_uuid=r.id "
                                   f"where p.pid_type='recid' and p.pid_value='{recid}';") or "{}")
            s = json.dumps(meta, ensure_ascii=False)
            linked = psql(f"select u.email from dac_idp_user d join accounts_user u on u.id=d.user_id where d.sub='{sub1}';")
            ok = (meta.get("publish_status") == "0" and INDEX in [str(x) for x in (meta.get("path") or [])]
                  and '"preprint"' in s and '"SMUR"' in s and s.count("license_0") >= 4 and linked == f"{u1}@example.invalid")
            results.append(ok)
            has_pre, has_smur = '"preprint"' in s, '"SMUR"' in s
            print(f"{'PASS' if ok else 'FAIL'}  登録されたアイテム recid={recid}: 公開={meta.get('publish_status')}(0=公開) "
                  f"インデックス={meta.get('path')} preprint={has_pre} SMUR={has_smur} "
                  f"CC BY 4.0 のファイル={s.count('license_0')} 本人の結びつき={linked}")
            r = requests.get(f"{WEKO}/records/{recid}", verify=REQ_VERIFY, timeout=60)
            ok = r.status_code == 200; results.append(ok)
            print(f"{'PASS' if ok else 'FAIL'}  ログインなしでアイテムの画面が見える: {r.status_code}")
    finally:
        for rid in sorted(set(made_recids)):
            out = weko("docker exec -i weko-web-1 sh -c 'cd /tmp && cat > /tmp/rdc_del.py && invenio shell /tmp/rdc_del.py 2>&1 | grep -E \"DELETED|ERR\"'",
                       "from weko_records_ui.utils import soft_delete\n"
                       f"try:\n    soft_delete('{rid}'); print('DELETED {rid}')\n"
                       "except Exception as e:\n    print('ERR', e)\n").stdout.strip()
            print("後片付け: " + (out or f"アイテム {rid} を消せたか分からない"))
        psql("update accounts_user set active=false where email like 'weko-pre-%@example.invalid';")
        psql("delete from dac_idp_user where user_id in (select id from accounts_user where email like 'weko-pre-%@example.invalid');")
        for uid in users:
            sh(f"bash -c '{KC} delete users/{uid} -r rdc'")
        weko(f"rm -f {ISSUERS_FILE}")
        weko(KILL_SERVER % JWKS_PORT)
        weko(f"docker exec weko-web-1 rm -rf {JWKS_DIR}")
        print("後片付け: WEKO の試験の利用者を無効にして結びつきを消した・IdP の利用者を消した・発行者のファイルと公開鍵を片付けた")
    n_fail = results.count(False)
    print(f"\n{len(results) - n_fail}/{len(results)} 通過")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
