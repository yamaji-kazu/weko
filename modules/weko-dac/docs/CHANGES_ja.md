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

## 9. 台本5 完了対応 (2026-09-05〜06)

DEMO-90 §4 の残ブロッカを消し込み、台本5 (取得) を通した際の変更。

- **callback 即時配送** (`services.flush_pending_events`): 承認コミット直後にその場配送し、
  失敗時のみ周期スイープにフォールバック。従来は 5 分周期 cron 任せで最大約5分遅延していたが、
  実測 **0.1〜0.2 秒**に短縮 (台本4 の「承認→その場で DG 画面が変わる」が成立)。
  あわせて deliver の非2xx を warning ログに出力
- **Offer の checksum 自動登録** (`demo-offer`): ローカル `--file` の sha256 を計算して
  `dac_offer.checksum` に登録 (`--checksum <hex>` で明示指定も可)。access-token 応答が
  `checksum:{algorithm:sha256,value}` を返すようになり、DG は取得後に照合してから GRDM へ格納
- **aud 確定 (案B)**: §8 の DAC_ID 案から **受信側 Entity ID** (`https://163.220.178.140`) へ
  確定 (RFC7519 §4.1.3 / GA4GH AAI)。DAC 同定は Visa `ga4gh_visa_v1.source` /
  Agreement `odrl:assigner` が保持

台本5 の通しで確認された公開基盤側の証跡: 承認 callback が秒単位配送、access-token が
checksum (`5fcf…`) を返し DG のダウンロード実体と一致、`data.accessed` が Agreement `uid`
紐づけ・`presentation_absent:false` で記録、旧 `aud`/リプレイ/`presented_by` 不在の
異常系はいずれも拒否 (401/403/409)。

## 10. 第2段階 — アクセス区分 open / registered (2026-09-06, RDC-AAP-01 §11)

「同じ研究計画から 3 件のデータが 3 通りの経路で来る」を実装。同一コホートの 3 層
(controlled=個票 `records/2000001`、registered=コードブック `records/2000002`、
open=集計サマリ `records/2000003`) を、待ち時間 **数日 / 数秒 / ゼロ** で見せる。

- **`registered` 自動許諾** (`weko_dac/registered.py`, `POST /registered-access`, scope
  `rags:apply`): Passport の資格 Visa (`ResearcherStatus` / `AcceptedTermsAndPolicies`) を
  **決定的ルール評価のみ**で検証 (§11.2.1 認証・§12.2 認可)。`ga4gh_passport_v1` (内側 Visa 束)
  と単体 `ga4gh_visa_v1` の両形式に対応。充足なら controlled の承認分岐 (§6) を再利用して
  Agreement + Visa を即時発行→Wallet 預け入れ→callback。LLM も `needs_human` も通さない
  (§11.2.2-4)。不充足は `403 requirements_not_met` に `unmet_requirements` を添えて返す。
  判定表 `_REQ_TO_VISA` は leftOperand→Visa type (分冊05 §12.2)。`researcherStatus` は
  **有無判定** (rightOperand True)、`acceptedTerms` は **rightOperand `@id` と Visa `value` の
  文字列一致** (到達性は見ない)。
- **`open` 直接取得** (認証なし, §11.1): `GET /open-access` は **access-token と同形の JSON**
  (`download_url`(署名付き `/download`) + `file_name` + `checksum{algorithm,value}`) を返す
  (DG 照会 O-1/O-3。区分に依らず checksum を同じ場所・同じ形で読める)。`GET /open-data` は
  実体を直接配信 (MCP 向け、checksum は `X-Checksum-Sha256`)。`access-token`/`/download` の
  検証経路 (リプレイ/aud/presented_by) には一切触れない。`data.accessed` は
  `access_route:open`・`presentation_absent:true` で記録、Wallet 提示履歴には残さない (O-4)。
- **Offer テンプレート** (`services.offer_from_template` + `demo-offer`): `--access-class
  open|registered` を追加。registered は資格 constraint (researcherStatus/acceptedTerms) と
  `WEKO_DAC_REGISTERED_TERMS_URI` (既定 `https://rdc.nii.ac.jp/terms/registered-access/v1`)、
  open は義務=引用のみ。`--terms` で規約 URI を上書き可。
- **修正**: `cli.py` に `from flask import current_app` を追加 (`demo-offer --access-class
  registered` が `current_app` 未 import で `NameError` になっていた)。

通しで確認した証跡: open は `open-access`→`download_url`→実体で sha 一致
(`a01f194b…`、認証なし)。registered は委任トークン (dg-portal password grant→dar-agent
token-exchange、`sub=hanako`/`act.sub=dar-001`/`scope rags:apply`) → passport 決定的検証
(`unmet []`) → `201 granted` → Agreement (`agr-app-2026-3cfdbc90`) → Visa → Wallet 預け入れ
(`wc-…`) → hanako の「マイ許諾」掲載。open は許諾を持たないので提示履歴に出ず、台本5 の
「監査ログ3件・提示履歴2件」の対比が成立。

## 11. v0.4 対応 — Credential Wallet 一般化 (rdc-aap-v0.4/v0.4.1, 2026-09-07〜08)

Grant Wallet を Credential Wallet に一般化した v0.4 に追従。提示物が **複数クレデンシャルの
配列**になり、資格も許諾と同じ「ウォレットからの提示」に乗る (分冊04 §5.3 / 分冊05 §11)。
仕様先行で RCOS へ確認 (`weko_confirm_v04.md`) → 回答 (v0.4.1) を反映。K-1〜K-5 を段階配備。

- **提示物検証器の共有化** (`weko_dac/presentation.py` 新設): 外側 (Wallet 署名 JWS) の検証
  (typ / `aud`=自 Entity ID / `iss`=allowlist の wallet / 鮮度 / `jti` リプレイ /
  `presented_by` allowlist / `purpose`) と `credentials` 配列抽出を、registered-access と
  access-token で**共有**。§11.2 の読み順 (`credentials[]` 優先、無ければ単数 `credential` を
  1 件配列) を内包。**判定値は必ず原本 `raw` から読む** (分冊05 §11.3。外側の索引は署名対象外)。
  旧 `views._verify_presentation` は撤去。
- **K-1 `registered-access` の入力を `presentation` に** (`registered.py` / `views.py`):
  提示物を §6.3 手順1〜3・5〜6 で検証 (手順4=対象一致は資格系に `resource` が無いため非適用)、
  `purpose=='registered-access'` を確認し、内包する資格クレデンシャルを §12.2 で決定的突合。
  **移行期は `passport` も受理**し `presentation_absent` を記録。**両方来た場合は `presentation`
  を優先** (passport はフォールバック)。
- **K-2 body の利用目的を `intended_use` に改称** (提示物の `purpose` クレームとの名前衝突回避)。
  旧 `purpose` も移行期は受理 (`intended_use` 優先)。
- **K-3 §6.3 (access-token / data-retrieval) を配列前提に**: 共有検証器を用い、`credentials[]` の
  各要素を `credential_format` ごとに検証、原本の `ga4gh_visa_v1` から当該 dataset の
  `DataAccessGrant` (`ControlledAccessGrants`, `value==dataset_id`) を探す。**一部だけ見て受理
  しない**。単一 `visa` 直接提示の移行経路は `presentation_absent` で保持。
- **K-4 発行者信頼 (§3.2) 二段検証** (`presentation.check_issuer_authority`): **型の権限** =
  発行者 (`source`) が allowlist に登録され `allowed_credential_types` に当該型を含むこと
  (GA4GH→rdc 写像: `ControlledAccessGrants`→`rdc:DataAccessGrant` 等)。**資源の権限** =
  `resource` を持つ許諾系のみ `source == Offer の assigner`。不適合は `403 issuer-not-authorized`。
  **強制は `WEKO_DAC_ENFORCE_ISSUER_TRUST` (既定 false) で段階化** — allowlist に
  `allowed_credential_types` が入るまで未強制で現行フローを壊さない。`allowed_credential_types`
  は**設定として**持つ (ハードコード禁止。Stage B で Trust Chain 解決に差し替わるため)。
- **K-5 監査 `data.accessed` に代理元と区分** (04 §6.1): `actor.on_behalf_of` (エージェント時=
  研究者 sub)・`access_class` (open/registered/controlled)・`credential_types`・`purpose` を追加。
  `presentation_absent` は**移行フォールバック検出専用**に降格 (区分は `access_class`。O-6 解決)。
  `registered.granted`/`denied` にも同項目。
- **Problem Details `type` の自動生成** (§5.8.2): 先行して `type=<WEKO_DAC_PROBLEM_TYPE_BASE>/
  <code の `_`→`-`>` を自動生成、`title` は人間可読ラベル (生コードは出さない)、
  `application/problem+json` を付与。新コード `access-class-mismatch` / `purpose-not-permitted` /
  `issuer-not-authorized` を追加 (§5.8.1 登録済み)。

通しで確認した証跡 (2026-09-08): **presentation 経路**で W-2 (`POST /holders/{sub}/presentations`,
`credential_ids:[ResearcherStatus, AcceptedTerms]`, `purpose:registered-access`) → registered-access
→ `201 granted`。ResearcherStatus 1 件のみの提示 → `403 requirements_not_met`
(`unmet=[rdc:acceptedTerms]`。配列を読み 2 要件を判定=L1 解決)。A-3 対象外 Visa の流用は
`403 visa_dataset_mismatch`。Wallet 併記停止 (`LEGACY_SINGLE_CLAIMS=false`) 後も a3/台本5 が無回帰
=公開基盤が `credentials[]` を実際に読んでいる確認 (C14 型サイレントギャップの解消)。passport 移行
経路も同一挙動を維持。W-6 (hanako に資格 3 種) 確認済み。

## 既知の制約 / 本番移行時の課題

README.rst「デモ簡略化」表のとおり。特に: Trust Chain/Trust Mark/DPoP は
静的 allowlist で代替、鍵はファイル管理 (本番 KMS)、監査はローカルスプール、
renewal (§6.4)・appeal (§8.3) 未実装。
