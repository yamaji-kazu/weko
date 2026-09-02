# WEKO デモ環境 運用手順書 (公開基盤チーム)

- 対象サーバ: WEKO デモ環境 (mdx VM, Ubuntu 22.04, `~/dev/weko`)
- グローバル IP: `163.220.178.140` / 内部網 IP: `10.20.116.19`
- 関連: IdP/Wallet = `163.220.178.141` (内部網あり)、DG = `163.220.178.112`
- 最終更新: 2026-08-31

チャット・口頭でしか残っていなかった環境設定を集約したもの。
**環境を再構築する場合は本書の順に実施する。**

## 1. 基本構成

- WEKO3 (docker-compose2.yml 構成)。`install.sh` で初期構築
  (詳細はリポジトリ直下 INSTALL.rst / AGENTS.md)
- weko-dac モジュール (`modules/weko-dac`) を追加インストール
- nginx コンテナに Shibboleth SP を同梱 (WEKO 標準構成)。TLS は nginx が終端

## 2. 外部公開設定

### 2.1 公開ポートの絞り込み (必須・セキュリティ)

Docker は ufw を迂回するため、compose 側で 80/443 以外を 127.0.0.1 に束縛済み
(docker-compose2.yml の各 `ports:` — web 5001, pgpool 25401, redis 26301,
ES 29201/29301, rabbitmq 24301/45601, flower 5501, inbox 8080, mongo 27017)。
**新しいサービスを追加する際も同じ方針とする。**

```bash
sudo ufw allow OpenSSH; sudo ufw allow 80/tcp; sudo ufw allow 443/tcp; sudo ufw enable
```

外部からの確認: `nmap -p 80,443,5001,27017 163.220.178.140` で 443 (と80) のみ open。
(80 は mdx 側 ACL の設定次第。https での案内を徹底すれば閉でも支障なし)

### 2.2 TLS 証明書 (IP SAN 自己署名)

`nginx/keys/server.crt` / `server.key` (key は git 管理外)。
**SAN にグローバル IP と内部網 IP の両方**を含める (DG は内部網経由で検証するため)。

```bash
cd ~/dev/weko/nginx/keys
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.crt -days 730 -nodes \
  -subj "/CN=163.220.178.140" \
  -addext "subjectAltName=IP:163.220.178.140,IP:10.20.116.19"
chmod 600 server.key
cd ~/dev/weko && docker compose -f docker-compose2.yml build nginx && \
  docker compose -f docker-compose2.yml up -d nginx
```

再生成時の影響範囲: (a) `server.crt` を信頼設定している全クライアント
(DG/DR/curl/ブラウザ) に再配布、(b) Keycloak の weko-sp に SP 証明書を
取り込んでいる場合は再取り込み (Client signature required: OFF 運用なら不要)。

## 3. mdx ヘアピン NAT 対策 (DNAT)

mdx では VM 同士・自分自身へグローバル IP で折り返せない。
グローバル IP 宛の通信を OS レベルでプライベート IP へ振り替える。

```bash
# 値は現物に合わせる
IDP_PRIV=<IdPサーバの内部網IP>
DG_PRIV=<DGサーバの内部網IP>
WEKO_PRIV=$(hostname -I | awk '{print $1}')

for pair in "163.220.178.141 $IDP_PRIV" "163.220.178.140 $WEKO_PRIV" "163.220.178.112 $DG_PRIV"; do
  set -- $pair
  sudo iptables -t nat -A OUTPUT     -d $1 -j DNAT --to-destination $2
  sudo iptables -t nat -A PREROUTING -d $1 -j DNAT --to-destination $2
done
sudo apt -y install iptables-persistent && sudo netfilter-persistent save
```

- OUTPUT = ホスト自身から、PREROUTING = Docker コンテナからの通信に効く
- URL・証明書検証はグローバル IP のままでよくなる (SAN 一致)
- 確認: `curl -k https://163.220.178.141/auth/realms/rdc/.well-known/openid-configuration`

## 4. Shibboleth (Keycloak SAML) ログイン

WEKO の nginx コンテナ同梱 SP を使用。変更ファイルと要点:

| ファイル | 設定 |
|---|---|
| `nginx/shibboleth2.xml` | SP entityID `https://163.220.178.140/shibboleth-sp` / `<SSO entityID>` = IdP realm (`https://163.220.178.141/auth/realms/rdc`、discovery 削除) / `handlerSSL="true" cookieProps="https"` / **`handlerURL="https://163.220.178.140/Shibboleth.sso"` (絶対URL — ACS がホスト名検出に依存しない)** / **RequestMap の `<Host name>` = `163.220.178.140`** (不一致だと /secure/ が素通りし「Missing Shib-Session-ID!」になる) / orthros の MetadataProvider は無効化 |
| `nginx/idp-metadata.xml` | `curl -k https://163.220.178.141/auth/realms/rdc/protocol/saml/descriptor` で取得したもの |
| `nginx/weko.conf` | `server_name 163.220.178.140;` / `NO_CHECK_WEKOSOCIETYAFFILIATION TRUE` |
| `scripts/instance.cfg` (テンプレート末尾) | `WEKO_ACCOUNTS_SHIB_LOGIN_ENABLED = True` / `WEKO_ACCOUNTS_SHIB_IDP_LOGIN_ENABLED = True` / `WEKO_ACCOUNTS_SHIB_IDP_LOGIN_URL = '{}secure/login.py'` / `WEKO_ACCOUNTS_SSO_ATTRIBUTE_MAP = {'eppn': (True,'shib_eppn'), 'mail': (False,'shib_mail'), 'DisplayName': (False,'shib_user_name')}` — **重要**: entrypoint が毎起動時に本テンプレートから invenio.cfg を再生成するため、invenio.cfg への手書き追記は再起動で消える。恒久設定は必ずテンプレート側に書く |

IdP 側 (Keycloak realm rdc): SAML クライアント
(Client ID = SP entityID、redirect `https://163.220.178.140/Shibboleth.sso/*`、
Client signature required OFF、mapper: eppn/mail/displayName → urn:oid)。

nginx 設定はイメージにベイクされるため、変更時は `build nginx` → `up -d nginx`。
入口: `https://163.220.178.140/secure/login.py`。初回ログインユーザーはロールなしで
作成されるので、管理画面でロール付与。
デバッグ: `docker compose -f docker-compose2.yml exec nginx tail /var/log/shibboleth/shibd.log`

## 5. weko-dac の接続設定

docker-compose2.yml の **web と worker 両方**の environment に設定:

| 変数 | 値 (デモ) | 用途 |
|---|---|---|
| WEKO_DAC_ENTITY_ID | `https://163.220.178.140` | 自 Entity ID (Presentation の aud / Visa iss / download_url) |
| WEKO_DAC_OIDC_ISSUER | `https://163.220.178.141/auth/realms/rdc` | アクセストークンの iss 検証値 |
| WEKO_DAC_TOKEN_URL | `<ISSUER>/protocol/openid-connect/token` | dac-service の client_credentials |
| WEKO_DAC_CLIENT_ID / _SECRET | `dac-service` / Keycloak発行 | Wallet deposit・callback の送信名義 |
| WEKO_DAC_WALLET_API_BASE | `https://163.220.178.141/wallet/api/wallet/v1` | Visa deposit 先 |
| WEKO_DAC_WALLET_JWKS_URL | `https://163.220.178.141/wallet/.well-known/jwks.json` | Presentation 検証鍵 (allowlist 未設定時のフォールバック) |
| WEKO_DAC_TLS_CA_BUNDLE | `/code/tls/bundle.crt` | 自己署名証明書の信頼。**IdP・DG など通信相手の crt を連結**して置く |
| WEKO_DAC_ALLOWLIST_PATH | `/code/<配布された allowlist.json>` | DEMO-24 §3。visa_issuer / agent:requester / wallet の検証 |
| WEKO_DAC_PASSPORT_ENFORCE | (既定 true) | false で Passport 検証を記録のみに緩和 (単体試験用) |

初期化 (初回のみ): `pip install -e /code/modules/weko-dac` → `invenio dac init`
(テーブル + ES256 署名鍵 `<instance>/data/dac_es256.pem`)。
weko-dac のインストールは `scripts/entrypoint_web.sh` / `entrypoint_worker.sh`
で毎起動時に保証される (コンテナ再作成で venv が消える対策。2026-09-02 の
API 全 404 障害の再発防止)。

## 6. 定常運用

- **cron**: `*/5 * * * * cd /home/mdxuser/dev/weko && docker compose -f docker-compose2.yml exec -T web invenio dac pump >> /tmp/dac_pump.log 2>&1`
  (callback 再送・Wallet deposit リトライ・期限失効)
- **監査ログ**: DB (`dac_audit_outbox`) + JSONL (`<instance>/data/dac_audit.jsonl`)
- **デモ用 Offer**: WebUI でアイテム登録 (制限公開) → `invenio dac demo-offer "<records URL>" --file <実体>`
  (手順: `DEMO01_curl_ja.md` §1)
- **デフォルトアカウント**: `wekosoftware@nii.ac.jp` ほか、共通パスワード
  `uspass123`。**公開サーバのため変更済みであること**を確認

## 7. トラブルシュート早見表

| 症状 | 原因 → 対処 |
|---|---|
| サーバ内から自分/他VMのグローバルIPに繋がらない | mdx ヘアピン → §3 の DNAT |
| Policy API が URL 型IDで 404 | パスの %2F 正規化 → クエリ形式 `?dataset_id=` を使う |
| 申請が 400 invalid_passport | visa_issuer 鍵/iss/sub 不一致。allowlist の配布版と Visa 発行元を確認 |
| 申請が 403 agent_not_allowlisted | allowlist の agent:requester に エージェントID がない |
| Shibboleth で Missing Shib-Session-ID | RequestMap の Host 名不一致 → §4 |
| SAML で Invalid Request (Keycloak) | Client signature required ON / Client ID 不一致 / ACS ホスト名 → §4 |
| Wallet deposit 失敗のまま | dac pump が自動再送。SECRET/URL/CA バンドル確認 |
| /api/dac/v1 が全パス 404 (Werkzeug 定型文) | weko-dac 未インストール状態で起動 (コンテナ再作成後など)。entrypoint の自動インストール導入後は発生しないはずだが、発生時は `pip show weko-dac` を確認し `pip install -e` → restart |
| 再起動後に invenio.cfg の設定が消える | entrypoint が `scripts/instance.cfg` から再生成するため。恒久設定はテンプレート側に書く (§4/§5) |
