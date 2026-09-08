# デモ01 第1段階 実施記録 — 公開基盤(WEKO)側の修正一覧

- 対象: WEKO フォーク (yamaji-kazu/weko) / `feature/weko-dac` ブランチ
- 期間: 2026-08〜09（台本1〜5 の通し）
- 位置づけ: デモ遂行中に判明した問題と対処を、DEMO-90 §4 ブロッカ単位で棚卸ししたもの。
  仕様・手順の詳細は `README.rst` / `docs/OPERATIONS_ja.md` / `docs/CHANGES_ja.md` を参照。
- 到達点: **台本1〜5 を実データで通し済み**（承認→秒単位 callback、許可トークンで取得→GRDM 格納、
  checksum 照合、監査記録）。異常系（旧 aud / リプレイ / 代理でない提示）も拒否を実測。

---

## 0. 一覧（症状 → 対処 → 該当）

| # | 症状 / 背景 | 対処 | 該当ファイル |
|---|---|---|---|
| 1 | 連携済みでも毎回 confirm 画面に戻る | SSO 属性マップに `shib_role_authority_name`/`shib_ip_range_flag` を補完 | `scripts/instance.cfg` |
| 2 | SSO ログインのたびに手動付与ロールが消える | `WEKO_ACCOUNTS_SHIB_KEEP_LOCAL_ROLES` ガード追加 | `weko-accounts/{api,config}.py` / `instance.cfg` |
| 3 | DAC 審査画面が「Permission required」(System 管理者以外) | `WEKO_ADMIN_ACCESS_TABLE` に `admin`/`dac/applications`/`dac/offers` を自動登録 | `weko-dac/ext.py` |
| 4 | Keycloak ログインが `authentication_expired`・CSS 崩れ | Keycloak Frontend URL を 141 に固定、新規利用者は Temporary=OFF | (IdP 側運用) `OPERATIONS_ja.md` §4 |
| 5 | 状態確認 `GET /applications/{id}` が 404 | 研究者本人(sub)は自分の申請を閲覧可に緩和 `WEKO_DAC_SCOPE_OWNER_SUB_ONLY` | `weko-dac/{views,config}.py` / `instance.cfg` |
| 6 | Presentation が `Invalid audience` | `aud` を受信側 Entity ID に確定(案B) `WEKO_DAC_PRESENTATION_AUD=https://163.220.178.140` | `weko-dac/{views,config}.py` / `instance.cfg` |
| 7 | callback の `delivered_at` が空(DG が 401) | client_credentials の Bearer を付与 (`WEKO_DAC_TOKEN_URL`/`CLIENT_SECRET`) | `docker-compose2.yml` / `.env` |
| 8 | callback が最大5分遅延(周期スイープ任せ) | 承認コミット直後に即時配送 `flush_pending_events`、cron は保険 | `weko-dac/services.py` |
| 9 | 許諾が Wallet に入らない(`wallet_deposited:null`) | `WEKO_DAC_WALLET_API_BASE` 設定 → 再送。holder=研究者 UUID | `docker-compose2.yml` |
| 10 | access-token の `checksum` が null | `demo-offer` が配信ファイルの sha256 を自動登録 (`--checksum` 上書き可) | `weko-dac/cli.py` |
| 11 | 配信物が 32byte プレースホルダ | 合成 CSV に差し替え + checksum 再登録 (M6 体裁) | Offer データ (`nii_cohort_2020_2024.csv`) |
| 12 | (基盤) グローバル IP 公開・mdx ヘアピン・自己署名 | 公開ポート束縛 / DNAT / IP-SAN 証明書 / weko-dac 自動インストール | `docker-compose2.yml` / `nginx/*` / `scripts/entrypoint_*.sh` |

---

## 1. 認証(IdP SSO)まわり

- **confirm ループ (#1)**: `WEKO_ACCOUNTS_SSO_ATTRIBUTE_MAP` を eppn/mail/DisplayName の3つに
  絞ると `get_relation_info()` が `shib_attr['shib_role_authority_name']` で KeyError → None を
  返し、連携済みでも confirm 画面に戻る。`SHIB_ATTR_ROLE_AUTHORITY_NAME`/
  `SHIB_ATTR_SITE_USER_WITHIN_IP_RANGE_FLAG` を追加（IdP が送らなくても空文字でキーを用意）。
- **ロール消失 (#2)**: `check_in()` が SSO ログインのたびに `roles.clear()` で全消去。IdP が
  affiliation を送らない本構成では手動付与ロール(例: Repository Administrator)が毎回消える。
  `WEKO_ACCOUNTS_SHIB_KEEP_LOCAL_ROLES=True` で、affiliation 無し・mAP 連携無しのとき
  ロール操作をスキップするガードを追加。
- **審査画面の 403 (#3)**: weko-admin が全 admin ビューの `is_accessible` を
  `role_has_access`(=`WEKO_ADMIN_ACCESS_TABLE` 判定)に上書きするため、DAC 独自の `is_officer`
  だけでは System Administrator 以外が弾かれる。拡張初期化(`ext.py`)で
  `WEKO_DAC_OFFICER_ROLES` の各ロールへ `admin`/`dac/applications`/`dac/offers` を自動登録。
- **Keycloak ログイン不成立 (#4)**: Frontend URL が 140 だと、SSO は 141 に飛ぶのに画面の
  リソース・フォーム・Cookie が 140 側になり `AuthnFailed / authentication_expired`。141 に固定。
  新規利用者は Credentials で Temporary=OFF・Required actions 空・Email verified。
- 審査担当 officer1 は「DAC Officer」ロールで IdP 連携（手順: `OPERATIONS_ja.md` §4.1）。

## 2. DAC 申請〜取得の実挙動

- **状態確認スコープ (#5)**: `GET/list applications` の §5.4 スコープを、デモでは
  「研究者本人(sub)は委任エージェントに依らず自分の申請を閲覧可」に緩和
  (`WEKO_DAC_SCOPE_OWNER_SUB_ONLY`、既定 False は委任ペア厳密一致)。別 sub は従来どおり拒否。
- **aud 確定 (#6, 案B)**: Presentation の `aud` は受信側(DAC)の Entity ID
  `https://163.220.178.140`（RFC7519 §4.1.3 / GA4GH AAI）。DAC の同定は Visa
  `ga4gh_visa_v1.source` / Agreement `odrl:assigner` が保持。`WEKO_DAC_PRESENTATION_AUD` の
  既定を `WEKO_DAC_ENTITY_ID` に変更。検証は完全一致(前方一致・正規化なし)。
- **access-token 応答 (#10)**: `file_name` を追加、`checksum` は Offer 登録があれば
  `{algorithm:sha256,value}`、`expires_in` は `WEKO_DAC_DOWNLOAD_URL_TTL`(デモ 900)。
  `download_url` は認証なしの期限付き capability URL。
- **checksum 自動登録 (#10)**: `demo-offer` がローカル `--file` の sha256 を計算して
  `dac_offer.checksum` に登録（`--checksum <hex>` 上書き可）。既存 Offer は
  `UPDATE dac_offer SET checksum=…`。
- **jti リプレイ防止 / 手順2・4**: `dac_presentation_jti`(jti PK)で使用済み管理→409、
  `ga4gh_visa_v1.value != dataset_id`→403、`presented_by != act.sub`→403。拒否コードは distinct。

## 3. callback / Wallet 連携

- **Bearer 認証 (#7)**: DG の callback 受口は認証必須(無認証は 401)。WEKO は
  `get_service_token()`(client_credentials)で Bearer を付与。`WEKO_DAC_TOKEN_URL`/
  `WEKO_DAC_CLIENT_ID(=dac-service)`/`WEKO_DAC_CLIENT_SECRET` を設定。シークレットは `.env`
  (`DAC_SERVICE_SECRET`)に置き compose は `${DAC_SERVICE_SECRET}` 参照(コミットしない)。
- **即時配送 (#8)**: 承認コミット直後に `flush_pending_events` でその場配送し、失敗時のみ周期
  スイープ(`invenio dac pump`)へフォールバック。実測 0.1〜0.2 秒(従来 最大5分)。非2xx を warning ログ。
- **Wallet 預け入れ (#9)**: `WEKO_DAC_WALLET_API_BASE` 未設定で deposit がスキップされていた。
  設定後、`POST {base}/holders/{UUID}/credentials`(holder=研究者 Keycloak UUID、Bearer=
  client_credentials)で登録。DAC トークンは deposit 専用(一覧 GET は 403 で正常)。
- **証明書 (#12 / DEMO-90 §4-1)**: DG の証明書(SAN に内部 IP `10.20.112.102`)を
  `WEKO_DAC_TLS_CA_BUNDLE`(=`/code/tls/bundle.crt`、DG+IdP を連結)に登録。更新時は差し替え+
  バンドル再作成。

## 4. 基盤・運用 (#12)

- グローバル IP(163.220.178.140)公開: 80/443 以外を 127.0.0.1 束縛、ufw 最小化。
- mdx ヘアピン NAT 対策: グローバル IP 宛通信の DNAT(IdP/自分/DG)。
- TLS: IP-SAN 入り自己署名(グローバル + 内部網)。
- weko-dac をコンテナ再作成後も使えるよう `scripts/entrypoint_{web,worker}.sh` で毎起動時に
  `pip install -e` を保証。
- 恒久設定は entrypoint が再生成する `scripts/instance.cfg` テンプレートに書く
  (invenio.cfg への手書きは再起動で消える)。

## 5. デモ用データ (#11)

- `records/2000001` の配信物を、体裁を整えた**合成 CSV**(`nii_cohort_2020_2024.csv`、実在の
  個人・調査に基づかない架空データ)に差し替え。差し替え時は sha256 を checksum に再登録し、
  新値を DG/RCOS と共有(突き合わせ基準が変わるため)。**最終通しの後**に実施すること。

---

## 台本5 完了の証跡(実測値)

- 承認 callback: `app-2026-d864bc71` の遅延 0.12〜0.21 秒(即時配送)。
- checksum: access-token が sha256 を返し、DG のダウンロード実体と一致。
- 監査: `data.accessed` が Agreement `uid` 紐づけ・`presentation_absent:false`・
  `credential_format:ga4gh-visa+jwt` で記録。
- 異常系: 旧 aud → 401、同一 jti → 409、`presented_by` 不在 → 403。

---

## 第2段階 実施記録 — open / registered (2026-09-06)

同一コホート 3 層 (controlled=`records/2000001` / registered=`records/2000002` /
open=`records/2000003`) を、待ち時間 数日 / 数秒 / ゼロ で通した際に判明した問題と対処。
実装内容は `CHANGES_ja.md` §10、運用は `OPERATIONS_ja.md` §8。

| # | 症状 / 背景 | 対処 | 該当 |
|---|---|---|---|
| 13 | `demo-offer --access-class registered` が `NameError: current_app` | `cli.py` に `from flask import current_app` を追加 | `weko-dac/cli.py` |
| 14 | open の checksum がヘッダのみ (DG が区分ごとに読み方を変える) | `open-access` を **access-token と同形の JSON** (`download_url`+`checksum`) に (O-1/O-3) | `weko-dac/views.py` |
| 15 | registered 用 `issue-visa.mjs` が `SyntaxError: Unexpected token '?'` | ホスト node v12 が古い。wallet コンテナ(node22)内で `--passport` 実行 | (Trust基盤) |
| 16 | password grant が `Client not allowed for direct access grants` | dar-agent は direct access grants 無効。**dg-portal (public, secret不要)** で取得→dar-agent で token-exchange | (IdP 運用) |
| 17 | `.140/.141/.112` へ両方タイムアウト | mdx ヘアピン DNAT が未保存で再起動時に消失。§3 再適用＋`netfilter-persistent save` | (基盤) `OPERATIONS §3` |
| 18 | registered 発行で `wallet_credential_id:null` | 発行時にコンテナ→Wallet(.141) 未到達 (DNAT 落ち)。`invenio dac pump` で再送→`wc-…` | `weko-dac/services.py` |
| 19 | 大きな貼り付けで SSH 端末が行を落とす | コード/データは tar でホスト `~/` へ scp→`git apply`/`docker cp`。base64 直貼りは不可 | (受け渡し手順) |
| 20 | マイ許諾に 2000001 の許諾が重複十数件 | Wallet `DELETE …/holders/{sub}/credentials/{id}` で1件残して disposed。小道具は残す (D-2) | (Wallet) |

到達点(実測): **open** = `open-access`→`download_url`→実体で sha 一致 (`a01f194b…`、認証なし)。
**registered** = 委任トークン(`sub=hanako`/`act.sub=dar-001`/`scope rags:apply`)→passport 決定的
検証 (`unmet []`) → `201 granted` → Agreement `agr-app-2026-3cfdbc90` → Visa → Wallet
`wc-beefde6d…` → マイ許諾掲載。**controlled** = 第1段階完了・マイ許諾も1件に整理。

## v0.4 実施記録 — presentation 経路 (2026-09-07〜08, rdc-aap-v0.4/v0.4.1)

Credential Wallet 一般化 (提示物が配列) に追従。K-1〜K-5 を段階配備し、passport 移行経路と
presentation 経路の両方で実測。詳細な変更点は `CHANGES_ja.md` §11。

| # | 確認 | 実測 |
|---|---|---|
| K-3 配列読み | 併記停止 (`LEGACY_SINGLE_CLAIMS=false`) 後の無回帰 | a3=`visa_dataset_mismatch PASS`、台本5=監査3件/取得3経路200。`credentials[]` のみでも通る (C14 型ギャップ解消) |
| K-1 presentation 経路 | W-2 で資格2件を1提示→registered-access | `201 granted` (passport ではなく提示物で自動許諾) |
| L1 解決 (配列+2要件) | ResearcherStatus 1件のみ提示 | `403 requirements_not_met` / `unmet=[rdc:acceptedTerms]` |
| A-3 対象外流用 | 2000002 の Visa を 2000001 に提示 | `403 visa_dataset_mismatch` |
| K-5 監査 | `data.accessed` の新項目 | `access_class` / `on_behalf_of`(=研究者sub) / `credential_types` / `purpose` が3経路で記録 (open は on_behalf_of=None) |
| W-6 | hanako のウォレット | `rdc:ResearcherStatus` / `rdc:Affiliation` / `rdc:AcceptedTerms` の3資格を確認 |

実測コマンド: `reg_v04_presentation.sh` (W-2 で `credential_ids:[ResearcherStatus, AcceptedTerms]`,
`purpose:registered-access` → `POST /registered-access` に `presentation` で載せる)、
`a3_visa_mismatch.sh`、`scene5_evidence.sh` (監査は `dac_audit_outbox` を weko-web-1 内 psycopg2 で読む)。

未了 (他チーム調整): K-4 発行者信頼の強制 (allowlist に `allowed_credential_types` 追加 →
`WEKO_DAC_ENFORCE_ISSUER_TRUST=true`)、格納ノード (scve9=GRDM) の同一性確認 (DG)。

## 既知の制約 / 本番移行時の課題

`README.rst`「デモ簡略化」表のとおり(Trust Chain/Trust Mark/DPoP は静的 allowlist で代替、
鍵はファイル管理、監査はローカルスプール、renewal/appeal 未実装)。加えて第1段階固有:
`WEKO_DAC_SCOPE_OWNER_SUB_ONLY`・`WEKO_DAC_PASSPORT_ENFORCE` 等のデモ緩和は本番で見直す。
jti の保持期間はプルーニング未実装(実効窓は freshness 300 秒)。
