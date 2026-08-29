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
7. **監査証跡 (§9)**: 全イベントを ``dac_audit_outbox`` にスプール
   (監査ログサービス構築後にフラッシュ)。

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
OpenID Federation Trust Chain 検証         未実装 ([DEMO] verification に not_verified_demo を記録)
Trust Mark (agent:requester) 失効照会      未実装 (IdP のクライアント登録・scope で代替)
DPoP 束縛検証                              未実装 (Bearer/DPoP ヘッダの JWT 検証のみ)
act クレーム (RFC 8693 委任)               act.sub があれば使用、なければ azp を委任エージェントとみなす
GA4GH Passport の Visa 束検証              JWT 署名検証のみ (結果を verification に記録、非致命)
renewal (§6.4) / appeal (§8.3)             未実装 (Phase 1 対象外として除外)
署名鍵の KMS/HSM 管理                      ファイル鍵 (0600)。本番は KMS へ
監査ログサービス送信                        ローカル outbox にスプールのみ
Entity Configuration                       自己署名のみ (authority_hints / Trust Mark なし)
========================================  =============================================

主要 API (§5–6)
===============

::

   GET  /api/dac/v1/datasets/{dataset_id}/policy      ODRL Offer (公開)
   GET  /api/dac/v1/visa-jwks.json                    Visa/Agreement 検証鍵
   GET  /api/dac/v1/visa-status?jti=...               Visa 失効照会
   POST /api/dac/v1/applications                      申請 (scope rags:apply, 委任必須)
   GET  /api/dac/v1/applications[?status=&madmp=]     自分の申請一覧
   GET  /api/dac/v1/applications/{id}                 状態・成果物
   GET  /api/dac/v1/applications/{id}/agreement       署名付き Agreement
   GET/POST /api/dac/v1/applications/{id}/messages    照会対話
   POST /api/dac/v1/applications/{id}/withdraw        取下げ
   POST /api/dac/v1/datasets/{id}/access-token        Presentation → 署名付きURL (scope rags:retrieve)
   GET  /.well-known/openid-federation                Entity Configuration (自己署名)

dataset_id は URL エンコードして渡す (例: ``https%3A%2F%2Fdoi.org%2F10.yyyy%2Fdata.456``)。
