# WEKO デモ環境 運用手順書 (公開基盤チーム)

- 対象サーバ: WEKO デモ環境 (mdx VM, Ubuntu 22.04, `~/dev/weko`)
- グローバル IP: `163.220.178.140` / 内部網 IP: `10.20.116.19`
- 関連: IdP/Wallet = `163.220.178.141` (内部網あり)、DG = `163.220.178.112`
- 最終更新: 2026-09-03

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
| `nginx/attribute-map.xml` | eppn の ScopedAttributeDecoder を外し単純文字列属性に変更。Keycloak の IdP メタデータに shibmd:Scope が無く、スコープ検証で eppn が破棄されログインループになるため (**デモ環境限定の緩和**。学認本番接続時は既定に戻す) |
| `nginx/weko.conf` | `server_name 163.220.178.140;` / `NO_CHECK_WEKOSOCIETYAFFILIATION TRUE` |
| `scripts/instance.cfg` (テンプレート末尾) | `WEKO_ACCOUNTS_SHIB_LOGIN_ENABLED = True` / `WEKO_ACCOUNTS_SHIB_IDP_LOGIN_ENABLED = True` / `WEKO_ACCOUNTS_SHIB_IDP_LOGIN_URL = '{}secure/login.py'` / `WEKO_ACCOUNTS_SSO_ATTRIBUTE_MAP`（下記）/ `WEKO_ACCOUNTS_SHIB_KEEP_LOCAL_ROLES = True` — **重要**: entrypoint が毎起動時に本テンプレートから invenio.cfg を再生成するため、invenio.cfg への手書き追記は再起動で消える。恒久設定は必ずテンプレート側に書く |

**SSO 属性マップは最小化しすぎない**。`WEKO_ACCOUNTS_SSO_ATTRIBUTE_MAP` を eppn/mail/DisplayName の3つだけに絞ると、`get_relation_info()` が `shib_attr['shib_role_authority_name']` で KeyError → 例外捕捉で None を返し、**連携済みユーザーでも毎回 confirm(紐づけ)画面に落ちる**。IdP が送らなくても「キーだけ空文字で用意される」よう、下記を含める。

```python
WEKO_ACCOUNTS_SSO_ATTRIBUTE_MAP = {
    'eppn': (True,  'shib_eppn'),
    'mail': (False, 'shib_mail'),
    'DisplayName': (False, 'shib_user_name'),
    'SHIB_ATTR_ROLE_AUTHORITY_NAME': (False, 'shib_role_authority_name'),
    'SHIB_ATTR_SITE_USER_WITHIN_IP_RANGE_FLAG': (False, 'shib_ip_range_flag'),
}
WEKO_ACCOUNTS_SHIB_KEEP_LOCAL_ROLES = True
```

`WEKO_ACCOUNTS_SHIB_KEEP_LOCAL_ROLES = True` は、IdP が affiliation を送らない本構成で **SSO ログインのたびに `check_in()` がロールを全消去**して手動付与ロール(例: Repository Administrator)が消える問題を回避する (weko-accounts に追加したガード。affiliation か mAP グループ連携がある場合は従来動作)。

IdP 側 (Keycloak realm rdc) の要点:
- SAML クライアント: Client ID = SP entityID、redirect `https://163.220.178.140/Shibboleth.sso/*`、
  Client signature required OFF、mapper: eppn/mail/displayName → urn:oid。
- **Frontend URL は 141 に固定**。Realm Settings → General → Frontend URL = `https://163.220.178.141/auth`
  (旧世代 Keycloak。新世代は `KC_HOSTNAME`)。ここが 140 だと、SSO は 141 に飛ぶのに
  ログイン画面の CSS・フォーム送信先・Cookie が 140 側になり、認証セッションを見失って
  **`AuthnFailed / authentication_expired`** になる (CSS 崩れも同原因)。
  確認: `curl -sk https://163.220.178.141/auth/realms/rdc/.well-known/openid-configuration`
  の各エンドポイントが **141** を指すこと。
- **利用者を新規に作る際**は Credentials で **Temporary=OFF**、Details の
  **Required user actions を空**、**Email verified=ON**、**Enabled=ON** にする。
  仮パスワードや Verify Email が残ると追加フォームを挟み、崩れた画面で完了できず
  `authentication_expired` の原因になる。

nginx 設定はイメージにベイクされるため、変更時は `build nginx` → `up -d nginx`。
入口: `https://163.220.178.140/secure/login.py`。初回ログインは confirm(紐づけ)画面が出るので
既存 WEKO アカウントに紐づける (下記 §4.1)。

デバッグ: `docker compose -f docker-compose2.yml exec nginx tail /var/log/shibboleth/shibd.log`

### 4.1 アカウントとロール (審査担当・利用者)

デモの役割分担: **hanako = 利用者/申請者**、**officer1 = WEKO の DAC 審査担当**。
いずれも Keycloak(IdP) 経由でログインし、初回に既存 WEKO アカウントへ紐づける。

審査担当(officer1)を IdP で用意する手順:

```bash
# WEKO 側: DAC Officer ロール + admin-access + 紐づけ先アカウント
docker compose -f docker-compose2.yml exec -T web invenio roles create "DAC Officer"
docker compose -f docker-compose2.yml exec -T web \
  invenio access allow admin-access role "DAC Officer"
docker compose -f docker-compose2.yml exec -T web \
  invenio users create officer1@nii.ac.jp --password '<pw>' --active
docker compose -f docker-compose2.yml exec -T web \
  invenio roles add officer1@nii.ac.jp "DAC Officer"
```

Keycloak 側で officer1 を作成 (Email は上の WEKO アカウントと一致させる、eppn 属性は
hanako と同じ属性キーで設定、Temporary=OFF)。officer1 で `/secure/login.py` からログインし、
confirm 画面で `officer1@nii.ac.jp` + WEKO パスワードを入力して**既存アカウントに紐づけ**る
(「Create New ID」は押さない)。

- 審査コンソールに入れるロールは `WEKO_DAC_OFFICER_ROLES`
  (既定: System Administrator / Repository Administrator / DAC Officer)。
- これらのロールが管理画面(DAC タブ + 管理トップ)に入れるよう、weko-dac 拡張が起動時に
  **`WEKO_ADMIN_ACCESS_TABLE` へ `admin` / `dac/applications` / `dac/offers` を自動登録**する
  (weko-admin は全 admin ビューの `is_accessible` を `role_has_access` に上書きするため、
  DAC 独自の `is_officer` だけでは 403 になる。この登録が無いと System Administrator 以外は
  「Permission required」)。
- 連携時に WEKO アカウントのメールは Keycloak の Email に書き換わるが、ロールはユーザーに
  紐づくので残る (KEEP_LOCAL_ROLES により SSO 再ログインでも消えない)。

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
| WEKO_DAC_SCOPE_OWNER_SUB_ONLY | (既定 false / デモ true) | 申請の閲覧スコープ(§5.4)。true で「研究者本人(トークン sub)は自分の申請を、委任エージェントに依らず閲覧可」。false は仕様どおり委任ペア(sub + act.sub)厳密一致 |
| WEKO_DAC_PRESENTATION_AUD | (既定 = DAC_ID) | Presentation の `aud` 検証値。DG/Wallet と揃える。デモは `https://163.220.178.140/dacs/rdc-dac-001` |
| WEKO_DAC_DOWNLOAD_URL_TTL | (既定 300 / デモ 900) | access-token が返す署名付き download_url の有効期限(秒) |

これらは `WEKO_DAC_*` の Flask config で、`scripts/instance.cfg` テンプレート末尾に書く
(環境変数でも可)。デモでは `WEKO_DAC_SCOPE_OWNER_SUB_ONLY = True` /
`WEKO_DAC_DOWNLOAD_URL_TTL = 900` / `WEKO_DAC_PRESENTATION_AUD = "https://163.220.178.140/dacs/rdc-dac-001"` を設定している。

**callback の Bearer 認証は必須**。DG の callback 受口は認証必須 (無認証 POST は 401) のため、
WEKO は `get_service_token()` で Keycloak の client_credentials トークンを取得して Bearer で送る。
表の `WEKO_DAC_TOKEN_URL` / `WEKO_DAC_CLIENT_ID` (=dac-service) / `WEKO_DAC_CLIENT_SECRET` を
**実際に設定する** (docker-compose2.yml の web/worker 両方の environment)。未設定だと無認証で送られ
DG が 401 を返し、`dac_event_outbox.delivered_at` が永遠に空のままになる。
シークレットはコミットしないよう `.env` (`DAC_SERVICE_SECRET`) に置き、compose 側は
`- WEKO_DAC_CLIENT_SECRET=${DAC_SERVICE_SECRET}` と参照する。
dac-service クライアントは Keycloak で **Service accounts (client_credentials) を有効**にしておく。

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
| 連携済みなのに毎回 confirm(紐づけ)画面に戻る | SSO 属性マップに `shib_role_authority_name` が無く `get_relation_info` が KeyError → §4 のマップに補完 |
| SSO ログインのたびにロールが消える | `check_in()` のロール全消去。`WEKO_ACCOUNTS_SHIB_KEEP_LOCAL_ROLES = True` → §4 |
| DAC 画面/管理画面が「Permission required」(403) | ロールが `WEKO_DAC_OFFICER_ROLES` に無い、または `WEKO_ADMIN_ACCESS_TABLE` に DAC/`admin` 未登録 → §4.1 (拡張が自動登録。再起動で反映) |
| Keycloak ログインで `AuthnFailed / authentication_expired` | Frontend URL が 141 でない or 利用者の仮パスワード/Required actions 残り → §4 |
| Keycloak ログイン画面の CSS が崩れる | Frontend URL が 141 でなくリソースが 140/auth を指す → §4 (機能は通るが見た目のため要修正) |
| 状態確認 `GET /applications/{id}` が 404 (存在するのに) | 所有者スコープ不一致。トークンの `sub`/`agent` が申請時と違う → デバッグは `_own_application_or_none` にログ、緩和は `WEKO_DAC_SCOPE_OWNER_SUB_ONLY` (§5)。エージェント代理は subject=研究者の委任トークンで |
| callback の `delivered_at` が空のまま | (1) `WEKO_DAC_TOKEN_URL`/`CLIENT_SECRET` 未設定で無認証送信→DG が 401 (§5)。(2) DG の証明書が CA バンドル未登録で TLS 失敗。(3) 宛先(内部IP)へ到達不可。`docker compose exec web invenio dac pump` 後にログの `service token failed`/`callback delivery failed` を確認 |
| callback が今すぐ再送されない | バックオフ待ち。`dac_event_outbox.next_attempt_at` が未来 (naive UTC 比較)。即時再送は `UPDATE dac_event_outbox SET next_attempt_at=now(), attempts=0 WHERE delivered_at IS NULL` → `invenio dac pump` |
| Wallet deposit 失敗のまま | dac pump が自動再送。SECRET/URL/CA バンドル確認。`WEKO_DAC_WALLET_API_BASE` 未設定だと deposit されず Visa はアプリのリソース経由のみ |
| /api/dac/v1 が全パス 404 (Werkzeug 定型文) | weko-dac 未インストール状態で起動 (コンテナ再作成後など)。entrypoint の自動インストール導入後は発生しないはずだが、発生時は `pip show weko-dac` を確認し `pip install -e` → restart |
| 再起動後に invenio.cfg の設定が消える | entrypoint が `scripts/instance.cfg` から再生成するため。恒久設定はテンプレート側に書く (§4/§5) |
