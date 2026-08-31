#!/bin/bash
# エンドツーエンド動作確認 (分冊00 §5 の DAC 関連部分を curl で通す)
# 前提: DEMO-10 (Keycloak) が稼働し、realm rdc に hanako / dar-agent /
#       dac-service が登録済み。WEKO 側で weko-dac がセットアップ済み。
# 使い方: 変数を書き換えて bash e2e_demo.sh
set -e

IDP=https://203.0.113.10/auth/realms/rdc     # IdP (実IPに読み替え)
WEKO=https://163.220.178.140                     # WEKO サーバ
API=$WEKO/api/dac/v1
DATASET="https://doi.org/10.yyyy/data.456"
DATASET_ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$DATASET")
CA="--cacert /opt/aifs-idp/tls/tls.crt"      # 自己署名証明書 (DEMO-10 付録A)

DG_SECRET=changeme
AGENT_JWT=...   # dar-agent の private_key_jwt (client assertion)
PASSWORD=changeme

echo "== (0) 公開エンドポイント =="
curl -s "$API/datasets/$DATASET_ENC/policy" | head -c 400; echo
curl -s "$API/visa-jwks.json" | head -c 200; echo

echo "== (1) 研究者ログイン → 委任トークン (token exchange) =="
USER_TOKEN=$(curl -s $CA $IDP/protocol/openid-connect/token \
  -d grant_type=password -d client_id=dg-portal -d client_secret=$DG_SECRET \
  -d username=hanako -d password=$PASSWORD | jq -r .access_token)
DELEG_TOKEN=$(curl -s $CA $IDP/protocol/openid-connect/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=dar-agent \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion=$AGENT_JWT \
  -d subject_token=$USER_TOKEN \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d scope="rags:apply rags:retrieve" | jq -r .access_token)

echo "== (2) 申請 POST =="
APP_ID=$(curl -s -X POST "$API/applications" \
  -H "Authorization: Bearer $DELEG_TOKEN" -H 'Content-Type: application/json' \
  -d @application_example.json | tee /dev/stderr | jq -r .application_id)

echo "== (3) 担当者が WEKO 管理画面 (Admin > DAC > Applications) で決裁 =="
echo "   $WEKO/admin/dac/applications/$APP_ID を開いて approve してください"
read -p "決裁後に Enter..."

echo "== (4) 状態確認 (active になっていること) =="
curl -s "$API/applications/$APP_ID" -H "Authorization: Bearer $DELEG_TOKEN" | jq .

echo "== (5) Wallet から Grant Presentation を取得 =="
W=https://203.0.113.10/wallet/api/wallet/v1
SUB=$(python3 -c "import urllib.parse;print(urllib.parse.quote('https://orcid.org/0000-0002-1825-0097',safe=''))")
WC=$(curl -s $CA "$W/holders/$SUB/credentials" -H "Authorization: Bearer $DELEG_TOKEN" | jq -r '.[0].credential_id // .credentials[0].credential_id')
GP=$(curl -s $CA -X POST "$W/holders/$SUB/credentials/$WC/present" \
  -H "Authorization: Bearer $DELEG_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"aud\":\"$WEKO\"}" | jq -r .presentation)

echo "== (6) access-token → データ取得 =="
DL=$(curl -s -X POST "$API/datasets/$DATASET_ENC/access-token" \
  -H "Authorization: Bearer $DELEG_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"presentation\":\"$GP\"}" | tee /dev/stderr | jq -r .download_url)
curl -s -o /tmp/dac_downloaded.bin "$DL"
ls -la /tmp/dac_downloaded.bin
echo "DONE"
