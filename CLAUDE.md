# weko — 公開基盤 (WEKO3 + DAC)

RCOSDP/weko の fork。**このリポジトリで書くのは `modules/weko-dac`** — NII RDC AIfS の
**DAC** (Data Access Committee) 機能で、Policy API (Offer の公開)、申請の受付と審査、
提示物の検証、access-token の発行、DG への callback、Credential Wallet への預け入れ、
監査ログを担う。仕様は [aifs](https://github.com/yamaji-kazu/aifs) の分冊01 (公開基盤) と
分冊05 (ODRL)。

**実体は `feature/weko-dac`。`main` は上流 RCOSDP の v2.0.3 のまま**で、`modules/weko-dac` を
含まない。上流の `AGENTS.md` (PEP8 / Black / `python manage.py test`) は WEKO 本体の約束事で、
weko-dac には自動テストが無い — 確認は `modules/weko-dac/docs/VERIFICATION_ja.md` の curl で行う。

**リポジトリは public。** `docker-compose2.yml` の `WEKO_DAC_CLIENT_SECRET` などは
`${DAC_...}` の変数置換で、値は 140 の `.env` にしか無い。**値を直書きしない。**

## weko-dac の文書 (`modules/weko-dac/docs/`)

| | |
|---|---|
| `OPERATIONS_ja.md` | **運用の正本。** 公開ポート、TLS、DNAT、Shibboleth ログイン、接続設定、定常運用、トラブルシュート、第2段階 |
| `VERIFICATION_ja.md` | インストール後の動作確認 (curl) |
| `DEMO01_curl_ja.md` | デモ01 の手順 (Offer 登録、委任トークン、申請、審査、取得) |
| `REHEARSAL_ja.md` | 稽古前の pre-flight (DNAT の再適用、3 経路の通し、go/no-go) |
| `CHANGES_ja.md` | 開発履歴 |

## 設計の要点

| | |
|---|---|
| **エラーは RFC 9457 Problem Details** | `type` URI は自動生成 (分冊01 §5.8.2)。`code` の語彙: `invalid_presentation` `subject_mismatch` `invalid_passport` `invalid_token` `issuer_not_authorized` `agent_not_allowlisted` `requirements_not_met` `purpose_not_permitted` `presentation_required` `delegation_required` `access_class_mismatch` `ethics_required` ほか |
| **目的違いは `purpose_not_permitted`** | `requirements_not_met` に混ぜない (§11.2.2、v0.4.6)。`unmet_requirements[].reason` は閉じた語彙 + 任意の `remediation_url` (§5.8.3、v0.4.5) |
| **提示物の `aud` は受信側 (DAC) の Entity ID** | 案 B (2026-09-05、RFC 7519 §4.1.3)。発行者は資格の中で識別する |
| **発行者信頼は二段** | allowlist の `visa_issuer` 鍵で署名を検証し、`source` が許された発行者かを別に見る (K-4) |
| **callback は承認コミット直後に即時配送** | 実測 0.1〜0.2 秒。cron の `invenio dac pump` (5 分) は**取りこぼしの保険**であって周期に依存しない |
| **registered は提示で通る** | `researcherStatus` の有無と `acceptedTerms` の値一致。`@id` は Visa の `value` と**文字列一致** (`WEKO_DAC_REGISTERED_TERMS_URI`) |
| **`checksum` は demo-offer が自動登録** | `--file` から sha256 を計算。`null` のまま取得が成功していた (C14) のを防ぐ |

## Python 3.6

**web コンテナは `python:3.6-slim-buster`。** walrus、`dataclasses`、f-string の `=`、
`dict | dict`、`typing` の `Literal`/`Protocol` は使えない。手元の 3.12 で通っても
コンテナで `SyntaxError` になる。Flask 1.0.4 / Invenio 3。

## 配備 (140)

サーバは `163.220.178.140` の `/home/mdxuser/dev/weko` (`docker-compose2.yml`)。TLS は nginx が
終端し、Shibboleth SP を同梱。`/opt/aifs-idp` は**無い** (あるのは 141)。

```bash
git pull --ff-only origin feature/weko-dac
docker compose -f docker-compose2.yml restart web worker   # ルートは起動時読み込み
docker compose -f docker-compose2.yml exec web invenio dac --help   # CLI は都度新プロセス (即反映)
```

- **`invenio.cfg` に手書きしない。** entrypoint が毎起動 `scripts/instance.cfg` から再生成するので
  再起動で消える。恒久設定はテンプレート側 (`scripts/instance.cfg`) に書く
- weko-dac は entrypoint が `pip install -e` する。`/api/dac/v1` が全パス 404 (Werkzeug の定型文)
  なら未インストールで起動している — `pip show weko-dac`
- 設定は **web と worker の両方**の `environment` に。片方だけだと pump や callback が無認証で
  飛んで DG に 401 を食らう
- **mdx はヘアピン NAT が無い。** 自分や隣のグローバル IP へは OS の DNAT で内部 IP に振り替える
  (`OPERATIONS_ja.md` §3)。再起動で消えていないかを稽古前に見る (`REHEARSAL_ja.md`)
- 140 の証明書は IP SAN の自己署名で、SAN に内部 IP `10.20.116.19` も入れてある。
  外向き (IdP・DG) の検証は `tls/bundle.crt`

## 確認は拒否まで見る

自動テストが無いぶん、**正常系と同じ数だけ拒否を見る**。`VERIFICATION_ja.md` と
`REHEARSAL_ja.md` §3.1 (K-4 `issuer_not_authorized`) の形で、**ステータスと `code` まで固定**
して判定する。403 と 404 を両方 PASS にした確認スクリプトが不適合を緑で通した (共通
CLAUDE.md の #3) — 同じ形を作らない。

## 変更の範囲

このブランチが上流に対して触っているのは `modules/weko-dac` のほか、`modules/weko-accounts`
(Shibboleth ログインの 2 ファイル)、`nginx/`、`scripts/entrypoint_*.sh`、`scripts/instance.cfg`、
`docker-compose2.yml`、`conf/allowlist.json`、`tls/`。**それ以外の上流モジュールは触らない。**
WEKO 本体を直す必要が出たら、weko-dac 側で吸収できないかを先に考える。

## コミット

**著者は `Kazu YAMAJI <yamaji@nii.ac.jp>`** (9/16 の 1 件だけ `Kazu Yamaji` 表記。以後は
大文字に統一)。件名は `type(weko-dac): 日本語`。本文には**なぜ
そうしたか**と、**その判断の根拠になった実測**を書く。分冊01 や ODRL プロファイルの変更を
伴うときは aifs 側も更新し、コミットメッセージで相互に参照する。

## 秘密情報

`nginx/keys/server.key` は 2026-08-31 に追跡から外した。`.env`、`*.key` はサーバにしか無い。
`tls/*.pem` `conf/allowlist.json` は公開鍵・証明書のみ。デフォルトアカウントの共通パスワード
(`uspass123`) は**公開サーバなので変更済みであること**を前提にする。
