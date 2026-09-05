# weko-dac 開発履歴 (feature/weko-dac ブランチ)

- 対象: WEKO フォーク (yamaji-kazu/weko) への追加開発一式
- 仕様: aifs リポジトリ `docs/rdc-aap/` (RDC-AAP-00〜05) および `docs/demo/` (DEMO-10/11/20/21/24)
- 最終更新: 2026-09-03

開発は以下の順で行われた。各段の詳細は該当ドキュメント・コミットを参照。

## 1. weko-dac モジュール新規作成 (RDC-AAP-01 Phase 1)

分冊01「DAC機能仕様書」の Phase 1 をデモプロファイル (認証は Keycloak JWT 検証、
Trust Chain/DPoP 省略) で実装した新規 WEKO モジュール。

- ポリシー管理 (§4): 条件テンプレート → ODRL Offer 生成 (管理画面 + `invenio dac demo-offer`)
- 申請受付 API (§5): applications / messages / withdraw、状態機械、callback (指数バックオフ再送)
- 審査支援 (§7): 分冊05 §8 の決定的 ODRL マッチング + DUO 階層 + リスク所見 +
  指示的文言検出 (§7.5)。LLM 不使用
- 担当者コンソール (§7.3): Admin → DAC (申請一覧・審査パッケージ・決裁・取消、Offer 管理)
- 許諾発行 (§6): Agreement JWS (ES256)、ControlledAccessGrants Visa、Grant Wallet deposit、
  visa-jwks / visa-status、Presentation 検証 (typ ディスパッチ = 分冊04 §8.3) → 署名付きURL配信
- 監査 (§9): DB outbox スプール
- CLI: `invenio dac init / pump / demo-offer`

→ 詳細: `README.rst`、動作確認: `docs/VERIFICATION_ja.md`

## 2. デモ01対応 (DEMO-20 §4 / DEMO-21 / DEMO-24 §3)

- **静的 allowlist** (`WEKO_DAC_ALLOWLIST_PATH`): Trust Chain 検証の代替。
  申請エージェント (role `agent:requester`)・Wallet (role `wallet`)・presented_by を検証。
  未設定時は全許可 + verification に `not_configured` を記録
- **Visa subject をトークン `sub` (Keycloak ユーザ UUID) に変更**:
  ホルダ識別子の確定 (DEMO-11 §6 / DEMO-12 §0) に整合。
  visa.sub == presentation.sub == token.sub の連鎖検証を成立させる
- **監査のローカル JSONL 追記** (`WEKO_DAC_AUDIT_JSONL_PATH`,
  既定 `<instance>/data/dac_audit.jsonl`): DEMO-20 §4 の監査簡略化に対応
- **aud 検証オプション** (`WEKO_DAC_OIDC_AUDIENCE`): DEMO-21 §2
- 受入条件1の curl 手順書: `docs/DEMO01_curl_ja.md`
- allowlist 形式例: `examples/allowlist.example.json`

## 3. デモ用データセットの実在化 (P2 確定)

dataset_id を WEKO に実在するアイテムのランディングページ URL
(`https://163.220.178.140/records/<RECID>`) とする運用に変更。
アイテムは WebUI で制限公開登録し、Offer をその URL で登録する。
→ 手順: `docs/DEMO01_curl_ja.md` §1

## 4. Policy / access-token API の識別子問題修正 (DR 指摘対応)

リバースプロキシがパス中の `%2F` を復号しスラッシュを正規化するため、
URL 形式の識別子がパス形式では一致しない問題への対応。

- **クエリ形式** `GET /api/dac/v1/policy?dataset_id=...` を追加 (URL型IDに推奨)
- **ボディ形式** `POST /api/dac/v1/access-token` (`dataset_id` を JSON で) を追加
- パス形式も `https:/` (スラッシュ1つ) に潰れた識別子を自動修復して照合

## 5. Passport 検証 (DG 依頼 2026-08-31 / 方式(c) → visa_issuer 方式)

`evidence.passport` の検証を実装 (分冊01 §5.2 処理4のデモ版)。

- 検証鍵: **allowlist の `role: visa_issuer` エントリの inline jwks**
  (未配布時はデモ IdP の realm JWKS にフォールバック。方式は verification に記録)
- 検証項目: 署名 / `exp` / **`iss` = visa_issuer の entity_id**
  (`https://163.220.178.141/visa-issuer`) / **`sub` = 申請トークンの `sub`**
- 形式: Visa 単体 (`ga4gh_visa_v1`) を推奨、Passport 形式 (`ga4gh_passport_v1`
  配列、内包 Visa も個別検証) も受理
- 不合格は `400 invalid_passport` で申請拒否。
  `WEKO_DAC_PASSPORT_ENFORCE=false` で記録のみに緩和可 (単体試験用)

## 6. インフラ・環境設定 (モジュール外の変更)

→ 詳細手順: `docs/OPERATIONS_ja.md`

- グローバル IP (163.220.178.140) 公開設定: 80/443 以外の公開ポートを
  127.0.0.1 に束縛 (docker-compose2.yml)、ufw 最小化
- TLS 証明書: IP SAN 入り自己署名 (グローバル + 内部網 10.20.116.19 の2 SAN)
- mdx ヘアピン NAT 対策: グローバル IP 宛通信の DNAT (IdP・自分自身・DG)
- Shibboleth (Keycloak SAML) ログイン: nginx 同梱 SP の設定
  (shibboleth2.xml / weko.conf / invenio.cfg)
- weko-dac 接続設定 (環境変数) と cron (`invenio dac pump`)

## 7. IdP SSO の実運用対応と審査権限・スコープ整備 (2026-09-03)

officer1(WEKO の DAC 審査担当) を IdP 経由で運用し、hanako の申請を承認して
Grant Wallet まで通す過程で判明した問題への対応。→ 詳細: `docs/OPERATIONS_ja.md` §4/§4.1/§5

- **weko-accounts: confirm ループ修正**。`WEKO_ACCOUNTS_SSO_ATTRIBUTE_MAP` を最小化すると
  `get_relation_info()` が `shib_role_authority_name` で KeyError → None を返し、連携済みでも
  毎回 confirm 画面に戻る。マップに `shib_role_authority_name`/`shib_ip_range_flag` を補完
- **weko-accounts: ロール保持ガード** (`WEKO_ACCOUNTS_SHIB_KEEP_LOCAL_ROLES`)。IdP が
  affiliation を送らない構成で `check_in()` の `roles.clear()` が SSO ログインのたびに
  手動付与ロールを消す問題を回避 (affiliation/mAP 連携がある場合は従来動作)
- **weko-dac: 審査コンソールのアクセス権**。weko-admin が全 admin ビューの `is_accessible` を
  `role_has_access`(=`WEKO_ADMIN_ACCESS_TABLE` 判定) に上書きするため、DAC 独自の `is_officer`
  だけでは System Administrator 以外が 403。拡張初期化(`ext.py`)で `WEKO_DAC_OFFICER_ROLES` の
  各ロールに `admin`/`dac/applications`/`dac/offers` を自動登録
- **weko-dac: 状態確認スコープ** (`WEKO_DAC_SCOPE_OWNER_SUB_ONLY`)。`GET/list applications` の
  §5.4 スコープを、デモでは「研究者本人(sub)は自分の申請を委任エージェントに依らず閲覧可」に
  緩和 (既定 false は委任ペア sub+act.sub 厳密一致)。on-behalf-of の代理確認は subject=研究者の
  委任トークンで行う旨を DG と共有
- **Keycloak(IdP) 運用メモ**: Frontend URL を 141 に固定 (140 だと CSS 崩れ + Cookie 分裂で
  `authentication_expired`)、新規利用者は Temporary=OFF / Required actions 空 / Email verified

これにより「hanako 申請 → officer1 承認 → Agreement/Visa 発行 → Wallet deposit → DG callback
(DG は写しを持たず Wallet 参照)」の一連が疎通 (DEMO-21 受入条件1: 申請〜deposit まで到達)。

## 8. callback 実配送と access-token 応答の整備 (2026-09-03, 台本4完成〜台本5準備)

DEMO-20 台本の 4 (許諾→callback) 完成と、台本5 (取得) の前提整備。
→ 詳細: `docs/OPERATIONS_ja.md` §5、`README.rst` 主要 API

- **callback の Bearer 認証**: DG の受口は認証必須 (無認証は 401)。WEKO は
  `get_service_token()` で Keycloak の client_credentials トークンを取得し Bearer で送る。
  `WEKO_DAC_TOKEN_URL` を設定、`WEKO_DAC_CLIENT_SECRET` は `.env` (`DAC_SERVICE_SECRET`) 参照。
  未設定だと無認証送信→401→`dac_event_outbox.delivered_at` が空のまま、という障害になる
- **callback 本体は平文 JSON** (`enqueue_event`)。認証はボディ署名ではなく Bearer で行う
- **再送のバックオフは naive UTC 比較**。長時間失敗後は `next_attempt_at` が先へ延びるため、
  即時再送は `UPDATE … SET next_attempt_at=now(), attempts=0` → `invenio dac pump`
- **access-token 応答に `file_name` を追加** (DG が GRDM 格納時のファイル名に使用)
- **Presentation の `aud` は受信側(DAC)の Entity ID** (`WEKO_DAC_PRESENTATION_AUD`、既定
  `https://163.220.178.140`、案B確定)。RFC7519 §4.1.3 / GA4GH AAI に従い `aud` はリライング・
  パーティ(受信者)を指す。DAC の同定は Visa `ga4gh_visa_v1.source` / Agreement `odrl:assigner`
  が保持 (§6.1/§6.2)。3者で `aud` を一致させる (当初 DAC_ID 案から Entity ID 案へ確定)
- **download_url は認証なしの期限付き URL**。`/api/dac/v1/download?token=<JWS>` は Bearer 不要で、
  URL 内の署名トークン (`exp = iat + WEKO_DAC_DOWNLOAD_URL_TTL`、デモ 900 秒) が capability。
  `checksum` は Offer に登録があれば sha256 で返す
- **Grant Wallet への預け入れ (§6.2)**: `WEKO_DAC_WALLET_API_BASE` を設定し、既発行 Visa を
  `invenio dac pump` で deposit。`POST {base}/holders/{UUID}/credentials`、holder=研究者の
  Keycloak UUID (=Visa subject=token sub)、Bearer は client_credentials。成功で
  `wallet_deposited=t`・`wallet_credential_id` が入り、DG は agreement_uid か credential_id で拾える。
  未設定だと deposit されず callback の該当フィールドが null のままになる (台本4→5 の詰まり要因)

## 既知の制約 / 本番移行時の課題

README.rst「デモ簡略化」表のとおり。特に: Trust Chain/Trust Mark/DPoP は
静的 allowlist で代替、鍵はファイル管理 (本番 KMS)、監査はローカルスプール、
renewal (§6.4)・appeal (§8.3) 未実装。
