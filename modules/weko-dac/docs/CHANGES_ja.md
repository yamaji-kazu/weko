# weko-dac 開発履歴 (feature/weko-dac ブランチ)

- 対象: WEKO フォーク (yamaji-kazu/weko) への追加開発一式
- 仕様: aifs リポジトリ `docs/rdc-aap/` (RDC-AAP-00〜05) および `docs/demo/` (DEMO-10/11/20/21/24)
- 最終更新: 2026-08-31

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

## 既知の制約 / 本番移行時の課題

README.rst「デモ簡略化」表のとおり。特に: Trust Chain/Trust Mark/DPoP は
静的 allowlist で代替、鍵はファイル管理 (本番 KMS)、監査はローカルスプール、
renewal (§6.4)・appeal (§8.3) 未実装。
