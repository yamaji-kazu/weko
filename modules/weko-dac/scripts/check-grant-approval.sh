#!/usr/bin/env bash
# check-grant-approval.sh — DAC の許諾を審査者が本人の VP で署名する(aifs ADR-16)ことを実機で確かめる。
# **141 で回す。** 141 の wallet-api2(127.0.0.1:7006)で審査者として提示し、140 の weko-dac を
# ssh weko140 経由の grant_e2e_driver.py で操作する(管理画面と同じサービス関数)。
#
#   OFFICER_WALLET_ID=… OTHER_DAC_WALLET_ID=… UNTRUSTED_WALLET_ID=… PI_WALLET_ID=… \
#     bash modules/weko-dac/scripts/check-grant-approval.sh
#
# 審査者の VC は rdc_portal_proto の scripts/issue-e2e-authz-vc.py --profile dacOfficerAuthz で発行する。
# 拒否は形(code)まで固定して見る。確認専用の申請は e2e-grant-* で、driver の cleanup で消せる。
#
# 2026-10-05 の実測: シェル 10・検算 11 がすべて OK(申請 e2e-grant-874691a2)。確認の手段を疑うため、
# 別の DAC の VC の代わりにこの DAC の審査者の VC を渡すと、その行が NG(200/approved)になり、以降も
# not_under_review で NG に倒れることを確かめた(緑が嘘でない)。PI の VC は vct が違うので wallet-api2 が
# 提示を作れず HTTP 500 になる。weko-dac 自身の型の検査(not_dac_officer_credential)は単体試験で見る。
set -u
WAPI=http://127.0.0.1:7006/wallet
OFFICER=${OFFICER:-officer1@nii.ac.jp}
E2E_SUB=${E2E_SUB:-96a5caca-871e-46f3-979d-b173ac1c8377}
: "${OFFICER_WALLET_ID:?審査者の VC(この DAC)のウォレット}" "${OTHER_DAC_WALLET_ID:?別の DAC の審査者の VC のウォレット}"
: "${UNTRUSTED_WALLET_ID:?公開テスト鍵の審査者の VC のウォレット}" "${PI_WALLET_ID:?PI の認可 VC のウォレット}"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok(){ echo "  OK  $*"; PASS=$((PASS+1)); }
ng(){ echo "  NG  $*"; FAIL=$((FAIL+1)); }
drv(){ ssh -o BatchMode=yes weko140 "cd ~/dev/weko && docker compose -f docker-compose2.yml exec -T web python /code/modules/weko-dac/scripts/grant_e2e_driver.py $*" </dev/null 2>/dev/null | tail -1; }
jget(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$1" 2>/dev/null; }
present(){ # $1=wallet id $2=提示要求 URL → HTTP ステータス
  local k d; k=$(curl -s $WAPI/$1/keys | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["keyId"])')
  d=$(curl -s $WAPI/$1/dids | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["did"])')
  python3 -c 'import json,sys;print(json.dumps({"requestUrl":sys.argv[1],"keyId":sys.argv[2],"did":sys.argv[3]}))' "$2" "$k" "$d" \
    | curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d @- $WAPI/$1/credentials/present; }
# 要求 → 提示 → 確認。出力: 提示の HTTP / 確認の result / code / 申請の status / 承認記録の件数
attempt(){ # $1=wallet $2=確認する人 [$3=tamper]
  local r sid url pc c
  r=$(drv request "$APP" "$OFFICER"); sid=$(echo "$r" | jget 'd["subject_id"]'); url=$(echo "$r" | jget 'd["url"]')
  [ -n "$sid" ] && [ -n "$url" ] || { echo "request-failed $r"; return; }
  pc=$(present "$1" "$url")
  [ "${3:-}" = tamper ] && drv tamper "$sid" >/dev/null
  c=$(drv confirm "$sid" "$2" "$APP")
  echo "$pc/$(echo "$c" | jget 'd["result"]')/$(echo "$c" | jget 'd.get("code")')/$(echo "$c" | jget 'd["status"]')/$(echo "$c" | jget 'd.get("records")')"
}

echo "== 0. 確認専用の申請を under_review で作る(本物の controlled の申請から形だけ借りる。生の Passport は写さない)"
r=$(drv create-app "$E2E_SUB"); APP=$(echo "$r" | jget 'd["app_id"]')
[ -n "$APP" ] && ok "申請 $APP($(echo "$r" | jget 'd["dataset"]'))" || { ng "申請を作れない: $r"; exit 1; }

echo "== 1. 署名なしの許諾は、管理画面以外の経路(execute_decision)でも通らない"
r=$(drv bypass "$APP" "$OFFICER")
[ "$(echo "$r" | jget 'd["result"]')/$(echo "$r" | jget 'd["status"]')" = rejected/under_review ] && echo "$r" | grep -q "VP approval" \
  && ok "署名なしの approve は拒否(申請は under_review のまま)" || ng "署名なしの approve が拒否されない: $r"

echo "== 2. 審査者の VC でないもの・別の DAC・信頼しない発行者は許諾を出さない"
o=$(attempt "$OTHER_DAC_WALLET_ID" "$OFFICER")
[ "$o" = 200/rejected/dac_not_authorized/under_review/0 ] && ok "別の DAC の審査者の VC: 提示は届いた(200)が dac_not_authorized、許諾なし・承認記録なし" || ng "別の DAC の対照が想定外: $o"
o=$(attempt "$UNTRUSTED_WALLET_ID" "$OFFICER")
[ "$o" = 200/rejected/issuer_not_trusted/under_review/0 ] && ok "公開テスト鍵の審査者の VC: 提示は届いた(200)が issuer_not_trusted" || ng "公開テスト鍵の対照が想定外: $o"
o=$(attempt "$PI_WALLET_ID" "$OFFICER")
# PI の VC は型(vct)が違うので、ウォレットが提示要求に合う VC を見つけられず、提示そのものが成立しない
case "$o" in 200/*) ng "PI の VC で提示が成立した(型で止まるはず): $o";;
  */rejected/pending/under_review/0) ok "PI の認可 VC: 型が違うので提示が成立せず(HTTP ${o%%/*})、確認は pending のまま、許諾なし";;
  *) ng "PI の VC の対照が想定外: $o";; esac

echo "== 3. 本人以外の確定・署名の後の書き換えは許諾を出さない"
o=$(attempt "$OFFICER_WALLET_ID" "someone-else@nii.ac.jp")
[ "$o" = 200/rejected/approver_not_requester/under_review/0 ] && ok "要求した審査者以外の確定は approver_not_requester" || ng "本人以外の対照が想定外: $o"
o=$(attempt "$OFFICER_WALLET_ID" "$OFFICER" tamper)
[ "$o" = 200/rejected/content_changed/under_review/0 ] && ok "署名した後に理由を書き換えると content_changed(署名した中身でしか確定しない)" || ng "書き換えの対照が想定外: $o"

echo "== 4. 審査者本人の VC で署名すると、承認記録と許諾が一緒に確定する"
r=$(drv request "$APP" "$OFFICER"); SID=$(echo "$r" | jget 'd["subject_id"]'); URL=$(echo "$r" | jget 'd["url"]')
pc=$(present "$OFFICER_WALLET_ID" "$URL"); c=$(drv confirm "$SID" "$OFFICER" "$APP")
st="$pc/$(echo "$c" | jget 'd["result"]')/$(echo "$c" | jget 'd["status"]')"
[ "$st" = 200/approved/active ] && ok "許諾が確定(提示 $pc、申請は active)" || { ng "許諾が確定しない: $pc $c"; echo "結果: OK $PASS / NG $FAIL"; exit 1; }
again=$(drv confirm "$SID" "$OFFICER" "$APP" | jget 'd.get("code")')
[ "$again" = approval_not_pending ] && ok "同じ承認の再確定は approval_not_pending" || ng "再確定が想定外: $again"
again=$(drv request "$APP" "$OFFICER" | jget 'd.get("code")')
[ "$again" = not_under_review ] && ok "許諾済みの申請への新しい要求は not_under_review" || ng "許諾済みへの要求が想定外: $again"

echo "== 5. 承認記録・ログ・説明文を検算する(公開の JWKS と公開要約は 140 の API から取る)"
drv show "$APP" > "$WORK/show.json"
REC=$(jget 'd["record"]["record_id"]' < "$WORK/show.json")
ssh -o BatchMode=yes weko140 "curl -sk https://127.0.0.1/api/dac/v1/approvals/jwks.json" > "$WORK/jwks.json"
ssh -o BatchMode=yes weko140 "curl -sk https://127.0.0.1/api/dac/v1/visa-jwks.json" > "$WORK/visa-jwks.json"
ssh -o BatchMode=yes weko140 "curl -sk -w '\n%{http_code} %{content_type}' https://127.0.0.1/api/dac/v1/approvals/$REC" > "$WORK/summary.txt"
EXP_ID=$(jget 'd["explanations"][0]["id"]' < "$WORK/show.json")
ssh -o BatchMode=yes weko140 "curl -sk -D - https://127.0.0.1/api/dac/v1/approvals/explain/$EXP_ID" > "$WORK/explain.txt"
python3 - "$WORK" "$OFFICER" "$OFFICER_WALLET_ID" <<'PY'
import sys, json, base64, hashlib
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
W, officer, wallet = sys.argv[1:4]
show = json.load(open(W + "/show.json")); jwks = json.load(open(W + "/jwks.json")); vjwks = json.load(open(W + "/visa-jwks.json"))
ok_n = ng_n = 0
def ok(m):
    global ok_n; ok_n += 1; print("  OK  " + m)
def ng(m):
    global ng_n; ng_n += 1; print("  NG  " + m)
b64d = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
sha = lambda s: base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()).rstrip(b"=").decode()
def verify(jws):
    h, p, s = jws.split(".")
    hdr = json.loads(b64d(h)); k = [x for x in jwks["keys"] if x["kid"] == hdr["kid"]]
    if not k: return None, hdr
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64d(k[0]["x"]), "big"), int.from_bytes(b64d(k[0]["y"]), "big"), ec.SECP256R1()).public_key()
    raw = b64d(s); sig = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        pub.verify(sig, (h + "." + p).encode(), ec.ECDSA(hashes.SHA256())); return json.loads(b64d(p)), hdr
    except InvalidSignature:
        return None, hdr
body, status = open(W + "/summary.txt").read().rsplit("\n", 1)
summary_jws = body.strip()
if status.startswith("200") and summary_jws == show["record"]["summary_jws"]: ok("公開要約は API から誰でも取れ、DB の記録と同じ(" + status + ")")
else: ng("公開要約の取得が想定外: " + status)
s, sh = verify(summary_jws); f, fh = verify(show["record"]["full_jws"])
if s and f and sh["typ"] == "rdc-approval-summary+jwt" and fh["typ"] == "rdc-approval-record+jwt": ok("公開要約と完全記録の署名を承認記録の JWKS で検証できた(typ も別)")
else: ng("署名の検証に失敗: summary=%s full=%s" % (bool(s), bool(f)))
if {k["kid"] for k in jwks["keys"]}.isdisjoint({k["kid"] for k in vjwks["keys"]}) and {k["x"] for k in jwks["keys"]}.isdisjoint({k["x"] for k in vjwks["keys"]}):
    ok("承認記録の鍵は Visa の鍵と別(R9-10)")
else: ng("承認記録の鍵が Visa の鍵と同じ")
if s and f:
    txt = json.dumps(s, ensure_ascii=False)
    leaks = [x for x in (officer, f["holder"], f["txdata_hash"], f["verifier_session_id"]) if x and x in txt]
    ok("公開要約に審査者・holder・取引ハッシュ・セッションが出ない") if not leaks else ng("公開要約に漏れ: %s" % leaks)
    disc = json.loads(b64d(f["tx_disclosure"]))
    if f["summary_sha256"] == sha(summary_jws) and s["tx_commitment"] == sha(f["tx_disclosure"]) and disc[1:] == ["tx_hash", show["txdata_hash"]]:
        ok("完全記録は公開要約に束ねられ、開示(tx_hash)が要約のコミットメントと一致")
    else: ng("完全記録と公開要約の結び付きが崩れている")
    if f["approved_by"] == officer and f["responsible"] == officer and f["key_custody"] == "unattested" and f["assurance_level"] == "vp":
        ok("完全記録: 承認したのは審査者本人(%s)、vp、key_custody=unattested(確かめていないことを書かない)" % officer)
    else: ng("完全記録の中身が想定外: %s" % {k: f.get(k) for k in ("approved_by", "responsible", "key_custody", "assurance_level")})
logs = show["log"]; kinds = [l["kind"] for l in logs]
chain_ok = all(verify(l["jws"])[0] for l in logs)
prev_ok = all((json.loads(b64d(l["jws"].split(".")[1]))["prev"] == (sha(logs[i-1]["jws"]) if i else None)) for i, l in enumerate(logs))
if kinds == ["request", "signature", "result"] and chain_ok and prev_ok: ok("承認ログ: request→signature→result、各行の署名と prev の連鎖が正しい")
else: ng("承認ログが想定外: kinds=%s sig=%s prev=%s" % (kinds, chain_ok, prev_ok))
sig_body = json.loads(b64d(logs[1]["jws"].split(".")[1]))["body"] if len(logs) > 1 else {}
td = sig_body.get("transaction_data") or ""
entry = json.loads(b64d(td)) if td else {}
if td and sha(td) == show["txdata_hash"] and sig_body.get("evidence") == "vp" and sig_body.get("vp_token"):
    ok("ログの証拠: VP の原本があり、載った取引の文字列のハッシュが記録の txdata_hash と一致")
else: ng("ログの証拠が想定外")
d = show["decisions"][-1] if show["decisions"] else {}
if entry.get("type") == "urn:rdc:txdata:data-access-grant:1" and entry.get("decision") == d.get("decision") and entry.get("reason") == d.get("reason") and entry.get("conditions") == d.get("conditions") and d.get("by") == officer:
    ok("署名した取引(型・決定・理由・条件)と、確定した決定が一致(%s / %s)" % (d.get("decision"), d.get("conditions")))
else: ng("署名した取引と確定した決定が食い違う: %s / %s" % ({k: entry.get(k) for k in ("type", "decision", "reason", "conditions")}, d))
if show["agreements"] >= 1: ok("許諾(Agreement)が %d 件発行された" % show["agreements"])
else: ng("許諾が発行されていない")
exp = show["explanations"][0]; hdrs = open(W + "/explain.txt").read()
if entry.get("explanation", {}).get("digest") == exp["digest"] == sha(exp["body"]) and ("sha-256=" + exp["digest"]) in hdrs and " 200" in hdrs.split("\n")[0]:
    ok("説明文: 取引に載った digest = 本文のハッシュ = API の Digest ヘッダ(誰でも取れる)")
else: ng("説明文の digest が一致しない")
print("RESULT %d %d" % (ok_n, ng_n))
PY
echo "結果: シェル側 OK $PASS / NG $FAIL(検算側は上の RESULT)。申請=$APP"
[ "$FAIL" = 0 ] || exit 1
