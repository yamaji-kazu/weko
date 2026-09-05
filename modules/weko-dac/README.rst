==========
 weko-dac
==========

DAC (Data Access Committee) 機能 — NII RDC 公開基盤 (WEKO) 向け実装。

仕様書 `RDC-AAP-01 (分冊01: DAC機能仕様書)` の **Phase 1 / デモプロファイル** を実装する
WEKO3 モジュール。前提文書: RDC-AAP-00/04/05 (aifs リポジトリ docs/rdc-aap/)。

実装済み機能
============

1. **ポリシー管理 (§4)**: 管理画面 (Admin → DAC → Dataset Policies) の条件テンプレートから
   ODRL Offer (分冊05 §3) を生成・登録。``GET /api/dac/v1/datasets/{id}/policy`` で公開。
2. **申請受付 API (§5)**: ``POST/GET /api/dac/v1/applications``、照会対話 ``…/messages``、
   ``…/withdraw``、状態機械 (§5.3)、DG への署名付き callback (§5.7、指数バックオフ再送)。
3. **審査支援 (§7, ルールエンジン)**: 分冊05 §8 の決定的マッチング (ODRL 制約単位判定 +
   DUO 階層包含 + 語彙表) による審査パッケージ生成。自由記述の指示的文言検出 (§7.5)。
   LLM は使用しない (審査案の decision/rationale はルール由来)。
4. **担当者コンソール (§7.3)**: Admin → DAC → Applications。申請一覧・審査パッケージ表示・
   決裁 (approve / approve_with_conditions / reject / request_info、理由必須、AI 推奨との
   相違を記録)・許諾取消。
5. **許諾発行 (§6)**: ODRL Agreement 生成 + ES256 JWS 署名、ControlledAccessGrants Visa
   (GA4GH Passport v1) 発行、Grant Wallet への deposit (DEMO-11 実装と接続)、
   ``visa-jwks.json`` / ``visa-status`` 公開。
6. **データ配信 (§6.3)**: ``POST …/datasets/{id}/access-token`` — Grant Presentation
   (``typ: rdc-gp+jwt``、typ ディスパッチで将来形式に拡張可能 = 分冊04 §8.3) の検証
   (署名 / aud / exp / jti リプレイ / Visa 有効性 / sub 一致 / presented_by)、
   署名付きダウンロード URL の発行。移行期の Visa 直接提示も受理 (監査に
   ``presentation_absent`` を記録)。
7. **監査証跡 (§9)**: 全イベントを ``dac_audit_outbox`` にスプールし、
   ローカル JSONL (DEMO-20 §4) にも追記。
8. **Passport 検証 (§5.2 処理4)**: ``evidence.passport`` (Visa 単体 /
   Passport 形式) を allowlist の ``visa_issuer`` エントリの inline jwks で
   検証 (署名 / exp / iss=visa_issuer entity_id / sub=申請トークン sub)。
   不合格は 400 invalid_passport で申請拒否。

セットアップ
============

.. code-block:: console

   # 1. インストール (WEKO の virtualenv 内)
   $ pip install -e modules/weko-dac

   # 2. テーブル作成 + 署名鍵生成
   $ invenio dac init

   # 3. 設定 (環境変数または invenio config)
   $ export WEKO_DAC_ENTITY_ID=http://203.0.113.20          # WEKO サーバの URL
   $ export WEKO_DAC_OIDC_ISSUER=https://203.0.113.10/auth/realms/rdc
   $ export WEKO_DAC_TOKEN_URL=https://203.0.113.10/auth/realms/rdc/protocol/openid-connect/token
   $ export WEKO_DAC_CLIENT_ID=dac-service
   $ export WEKO_DAC_CLIENT_SECRET=...
   $ export WEKO_DAC_WALLET_API_BASE=https://203.0.113.10/wallet/api/wallet/v1
   $ export WEKO_DAC_WALLET_JWKS_URL=https://203.0.113.10/wallet/.well-known/jwks.json
   $ export WEKO_DAC_TLS_CA_BUNDLE=/path/to/tls.crt         # DEMO-10 の自己署名証明書
   $ export WEKO_DAC_ALLOWLIST_PATH=/path/to/allowlist.json # DEMO-24 §3 (静的allowlist)
   # 形式は examples/allowlist.example.json を参照。未設定時は全許可 (verification に記録)
   $ export WEKO_DAC_SCOPE_OWNER_SUB_ONLY=true   # デモ: 研究者本人(sub)は自分の申請を閲覧可
   # 既定 false は §5.4 の委任ペア(sub + act.sub)厳密一致。デモは true 推奨

   # 4. デモ用 Offer の登録 (管理画面からも可)
   $ invenio dac demo-offer "https://doi.org/10.yyyy/data.456" \
       --file /var/tmp/restricted/data456.zip

   # 5. callback / wallet 再送・期限スイープ (cron か celery beat で定期実行)
   $ invenio dac pump

celery beat を使う場合 (任意)::

   CELERY_BEAT_SCHEDULE = {
       'dac-pump-events': {'task': 'weko_dac.tasks.pump_events',
                           'schedule': 60.0},
       'dac-wallet-retry': {'task': 'weko_dac.tasks.retry_wallet_deposits',
                            'schedule': 300.0},
       'dac-expire': {'task': 'weko_dac.tasks.expire_grants',
                      'schedule': 3600.0},
   }

デモ簡略化 (本番仕様との差分)
=============================

DEMO-10/11 と同じ整理。RDC-ATF (Trust Anchor 等) 構築時に置き換える。

========================================  =============================================
分冊01/04 の要件                           本モジュールでの扱い
========================================  =============================================
OpenID Federation Trust Chain 検証         静的 allowlist で代替 (DEMO-20 §4 / DEMO-24 §3)
Trust Mark (agent:requester) 失効照会      省略 (allowlist の role に含意)
DPoP 束縛検証                              未実装 (Bearer/DPoP ヘッダの JWT 検証のみ)
act クレーム (RFC 8693 委任)               act.sub があれば使用、なければ azp を委任エージェントとみなす
GA4GH Passport の Visa 束検証              JWT 署名検証のみ (結果を verification に記録、非致命)
renewal (§6.4) / appeal (§8.3)             未実装 (Phase 1 対象外として除外)
署名鍵の KMS/HSM 管理                      ファイル鍵 (0600)。本番は KMS へ
監査ログサービス送信                        ローカル outbox + JSONL 追記 (DEMO-20 §4)
Entity Configuration                       自己署名のみ (authority_hints / Trust Mark なし)
申請閲覧スコープ (§5.4)                     WEKO_DAC_SCOPE_OWNER_SUB_ONLY=true で本人(sub)閲覧可に緩和
========================================  =============================================

審査担当のロールと管理画面アクセス
==================================

審査コンソール(Admin → DAC)に入れる WEKO ロールは ``WEKO_DAC_OFFICER_ROLES``
(既定: System Administrator / Repository Administrator / DAC Officer)。
weko-admin は全 admin ビューの ``is_accessible`` を ``WEKO_ADMIN_ACCESS_TABLE``
判定に上書きするため、拡張初期化時に各 officer ロールへ ``admin`` /
``dac/applications`` / ``dac/offers`` を自動登録する (これが無いと System
Administrator 以外は「Permission required」)。IdP(Keycloak) 経由の審査担当
アカウント作成手順は ``docs/OPERATIONS_ja.md`` §4.1。

主要 API (§5–6)
===============

::

   GET  /api/dac/v1/datasets/{dataset_id}/policy      ODRL Offer (公開)
   GET  /api/dac/v1/policy?dataset_id=...             同上 (クエリ形式。URL型IDに推奨)
   GET  /api/dac/v1/visa-jwks.json                    Visa/Agreement 検証鍵
   GET  /api/dac/v1/visa-status?jti=...               Visa 失効照会
   POST /api/dac/v1/applications                      申請 (scope rags:apply, 委任必須)
   GET  /api/dac/v1/applications[?status=&madmp=]     自分の申請一覧
   GET  /api/dac/v1/applications/{id}                 状態・成果物
   GET  /api/dac/v1/applications/{id}/agreement       署名付き Agreement
   GET/POST /api/dac/v1/applications/{id}/messages    照会対話
   POST /api/dac/v1/applications/{id}/withdraw        取下げ
   POST /api/dac/v1/datasets/{id}/access-token        Presentation → 署名付きURL (scope rags:retrieve)
   POST /api/dac/v1/access-token                      同上 (dataset_id をボディで渡す形式。URL型IDに推奨)
   GET  /.well-known/openid-federation                Entity Configuration (自己署名)

dataset_id は URL エンコードして渡す (例: ``https%3A%2F%2Fdoi.org%2F10.yyyy%2Fdata.456``)。

access-token の応答と callback (§6.3 / §5.7)
============================================

``POST /access-token`` の応答::

   { "download_url": "https://<entity_id>/api/dac/v1/download?token=<JWS>",
     "file_name": "data456.zip",
     "expires_in": 900,
     "checksum": { "algorithm": "sha256", "value": "<hex>" } }   // 無登録時 null

- ``download_url`` は **認証なしの期限付き URL**。``/download`` は Bearer 不要で、
  URL 内の署名トークン (``exp = iat + WEKO_DAC_DOWNLOAD_URL_TTL``) が capability。
  取得側はこの URL を GET するだけ (委任トークンは不要)。ホストは ``WEKO_DAC_ENTITY_ID``
  なので、取得側がそのホストに到達できること。
- Presentation の ``aud`` は ``WEKO_DAC_PRESENTATION_AUD`` (既定 = ``WEKO_DAC_ENTITY_ID``)
  を検証 — 受信側(DAC)の Entity ID (RFC7519 §4.1.3 / GA4GH AAI)。Wallet の ``present`` は
  この値を ``aud`` に入れる。どの DAC が発行したかは Visa ``ga4gh_visa_v1.source`` /
  Agreement ``odrl:assigner`` が保持 (§6.1/§6.2)。
- **callback** (``§5.7``, 状態遷移・agreement.issued 等) は DG の ``callback_url`` へ
  平文 JSON を POST。認証は Keycloak client_credentials の Bearer
  (``WEKO_DAC_TOKEN_URL`` / ``WEKO_DAC_CLIENT_ID`` / ``WEKO_DAC_CLIENT_SECRET``)。
  再送は指数バックオフ (``invenio dac pump`` / celery beat)。
- **Grant Wallet 預け入れ** (``§6.2``): 許諾発行時に Visa を
  ``POST {WEKO_DAC_WALLET_API_BASE}/holders/{holder}/credentials`` で登録
  (holder = Visa subject = 研究者の Keycloak UUID、Bearer = client_credentials)。
  未設定だと deposit されず callback の ``wallet_deposited``/``wallet_credential_id`` が null。
  再送は ``invenio dac pump`` (``retry_wallet_deposits``)。

ドキュメント
============

- `docs/CHANGES_ja.md <docs/CHANGES_ja.md>`_ — 開発履歴 (何を・どの仕様に
  基づいて・どの順で実装したか)
- `docs/VERIFICATION_ja.md <docs/VERIFICATION_ja.md>`_ — インストール後の
  動作確認手順 (ステップ1〜3は WEKO 単体、ステップ4は IdP/Wallet 構築後)
- `docs/DEMO01_curl_ja.md <docs/DEMO01_curl_ja.md>`_ — デモ01 curl 手順書
  (DEMO-21 受入条件1: 申請→承認→Visa→deposit→配信)
- `docs/OPERATIONS_ja.md <docs/OPERATIONS_ja.md>`_ — デモ環境の運用手順書
  (公開設定・DNAT・証明書・Shibboleth 連携・環境変数・トラブルシュート)
