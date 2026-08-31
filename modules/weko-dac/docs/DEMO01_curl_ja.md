# デモ01 curl 手順書 — 申請→承認→Visa発行→deposit→配信 (DEMO-21 受入条件1)

- 対象: weko-dac 0.1.x / デモ計画 DEMO-20、依頼 DEMO-21
- 前提: DEMO-10 (Keycloak)・DEMO-11 (Grant Wallet) 稼働、weko-dac セットアップ済み
  (README.rst)。**確定パラメータ (DEMO-20 §5)**:

| パラメータ | 値 |
|---|---|
| P1: 公開基盤ベース URL | `https://163.220.178.140` (API: `/api/dac/v1`) |
| P2: デモ用データセット | `https://163.220.178.140/records/2000001` |
| IdP (realm rdc) | `https://163.220.178.141/auth/realms/rdc` |
| Grant Wallet | `https://163.220.178.141/wallet/api/wallet/v1` |

以降のコマンドは、TLS が自己署名のため `-k` を付けている (正式には
`--cacert tls.crt`)。**mdx 内のサーバから実行する場合は DNAT 設定が前提**
(グローバル IP はヘアピン不可のため)。

## 0. 変数の設定

```bash
PUB=https://163.220.178.140
API=$PUB/api/dac/v1
IDP=https://163.220.178.141/auth/realms/rdc
W=https://163.220.178.141/wallet/api/wallet/v1
DATASET="https://163.220.178.140/records/2000001"
DATASET_ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$DATASET")

DG_PORTAL_SECRET=...      # dg-portal のシークレット (public+PKCE構成なら不要)
DAR_AGENT_SECRET=...      # dar-agent のシークレット
RESEARCHER=hanako
RESEARCHER_PW=...
```

## 1. デモ用データセットと Offer の登録 (WEKO サーバ、初回のみ)

```bash
docker compose -f docker-compose2.yml exec web bash -c \
  "echo 'demo restricted data for demo01' > /var/tmp/demo-restricted-001.txt"
docker compose -f docker-compose2.yml exec web invenio dac demo-offer \
  "https://163.220.178.140/records/2000001" \
  --duo DUO:0000042 --period P2Y \
  --file /var/tmp/demo-restricted-001.txt
```

DEMO-21 依頼1 のとおり `rdc:ethicsApproval` 制約は付けない (`demo-offer` の
既定で ethics_required=False)。

## 2. Policy API (依頼2 / 認証不要)

```bash
curl -sk "$API/datasets/$DATASET_ENC/policy" | jq .
```

期待: `"@type": "Offer"`, `"rdc:accessClass": "controlled"`。

## 3. 委任トークンの取得 (DEMO-24 §2)

研究者ログイン → dar-agent の token exchange で `sub=研究者 / act または
azp=dar-agent` のトークンを得る (DEMO-12 §3 と同じ流れ)。

```bash
USER_TOKEN=$(curl -sk "$IDP/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=dg-portal -d client_secret=$DG_PORTAL_SECRET \
  -d username=$RESEARCHER -d password=$RESEARCHER_PW \
  -d scope="openid rags:apply rags:retrieve" | jq -r .access_token)

DELEG_TOKEN=$(curl -sk "$IDP/protocol/openid-connect/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=dar-agent -d client_secret=$DAR_AGENT_SECRET \
  -d subject_token=$USER_TOKEN \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d scope="rags:apply rags:retrieve" | jq -r .access_token)

# 中身の確認 (sub=研究者UUID, act.sub または azp=dar-agent, scope に rags:*)
echo $DELEG_TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq '{sub,azp,act,scope}'
```

## 4. 申請の作成 (依頼3)

`application_example.json` の `requests[0].dataset_id` と
`odrl_request.target` を P2 の値に、`callback_url` を DG の受信口
(`https://163.220.178.112/api/dg/v1/rags-events`, DEMO-20 §5 P3) に
書き換えてから:

```bash
APP=$(curl -sk -X POST "$API/applications" \
  -H "Authorization: Bearer $DELEG_TOKEN" -H 'Content-Type: application/json' \
  -d @application_example.json)
echo $APP | jq .
APP_ID=$(echo $APP | jq -r .application_id)
```

期待: 201、`status: submitted` (直後に under_review へ自動遷移)。

```bash
curl -sk "$API/applications/$APP_ID" -H "Authorization: Bearer $DELEG_TOKEN" \
  | jq '{application_id,status,verification:{allowlist:.verification.allowlist}}'
```

## 5. 承認 (依頼4–5)

承認コンソール `https://163.220.178.140/admin/dac/applications/` を開き
(担当者は Shibboleth ログイン + Repository Administrator ロール)、
該当申請の「審査」→ 理由を入力して **approve**。

承認により自動で: ODRL Agreement 生成 + ES256 JWS 署名 →
ControlledAccessGrants Visa 発行 (`exp` = 許諾期間末) → **Wallet へ
deposit** → `agreement.issued` callback キュー投入 → 状態 `active`。

確認:

```bash
curl -sk "$API/applications/$APP_ID" -H "Authorization: Bearer $DELEG_TOKEN" \
  | jq '{status, visas:.artifacts.visas}'
# → status=active, visas[0].wallet_deposited=true, wallet_credential_id が入る
curl -sk "$API/applications/$APP_ID/agreement" -H "Authorization: Bearer $DELEG_TOKEN" \
  | jq '.agreements[0].uid'
JTI=$(curl -sk "$API/applications/$APP_ID" -H "Authorization: Bearer $DELEG_TOKEN" \
  | jq -r '.artifacts.visas[0].jti')
curl -sk "$API/visa-status?jti=$JTI" | jq .    # → active
```

callback は DG 未受信でも `dac_event_outbox` に残り `invenio dac pump` が
再送する (依頼3の callback 送信)。

## 6. Wallet present → データ配信 (依頼6)

```bash
# holder = 研究者の Keycloak UUID (DEMO-12 §0 — eppn/ORCID ではない)
SUB=$(echo $DELEG_TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq -r .sub)

# 6-1. Wallet の許諾一覧から credential_id を取得
WC=$(curl -sk "$W/holders/$SUB/credentials" -H "Authorization: Bearer $DELEG_TOKEN" \
  | jq -r '.[0].credential_id // .credentials[0].credential_id')

# 6-2. present (aud = 公開基盤の Entity ID = P1)
GP=$(curl -sk -X POST "$W/holders/$SUB/credentials/$WC/present" \
  -H "Authorization: Bearer $DELEG_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"aud\":\"$PUB\"}" | jq -r .presentation)

# 6-3. access-token (Presentation 検証 → 署名付きURL)
RESP=$(curl -sk -X POST "$API/datasets/$DATASET_ENC/access-token" \
  -H "Authorization: Bearer $DELEG_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"presentation\":\"$GP\"}")
echo $RESP | jq .
DL=$(echo $RESP | jq -r .download_url)

# 6-4. データ取得と checksum 検証
curl -sk -o /tmp/demo01_data.bin "$DL"
sha256sum /tmp/demo01_data.bin
echo $RESP | jq -r .checksum.value      # 一致すること
```

## 7. ネガティブ確認 (抜粋)

```bash
# 同じ Presentation の再提示 → 409 presentation_replayed
curl -sk -X POST "$API/datasets/$DATASET_ENC/access-token" \
  -H "Authorization: Bearer $DELEG_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"presentation\":\"$GP\"}" | jq .title
# トークンなし → 401
curl -sk -X POST "$API/applications" -d '{}' \
  -H 'Content-Type: application/json' | jq .title
```

## 8. 監査証跡

各イベント (application.received / decision.made / agreement.issued /
visa.issued / visa.deposited / data.accessed …) は DEMO-20 §4 のとおり
ローカル JSONL にも追記される:

```bash
docker compose -f docker-compose2.yml exec web \
  tail -5 /home/invenio/.virtualenvs/invenio/var/instance/data/dac_audit.jsonl
```
