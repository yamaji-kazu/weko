# WEKO デモ01 第2段階 稽古(リハーサル)手順書 — 公開基盤側

通し稽古の当日、公開基盤(WEKO)側が **最初に回す事前チェック** と、3経路の通し手順、
Go/No-go 判定をまとめる。前提: v0.4 コード(K-1〜K-5)適用済み、および registered 発行時の
**deposit flush 修正** 適用済み(201 が `wallet_credential_id` を確実に載せる)。

実測スクリプトはサーバ `~/` に配置済み(`chain_demo.sh` / `scene5_evidence.sh` /
`wallet_cleanup.sh` / `a3_visa_mismatch.sh` / `reg_v04_presentation.sh`)。

---

## 1. 事前チェック(当日・上から順に)— ここが本丸

### 1.1 VM の同定(両 VM とも hostname=ubuntu-2204)

`docker ps` の頭で **どちらの VM にいるか**を必ず確認する(ホスト名が同じで取り違えやすい)。

```bash
docker ps --format '{{.Names}}' | head
```

- **WEKO VM**: `weko-*`(web/worker/nginx/…)。内部 `10.20.116.19`、floating `.140`。iptables-persistent 導入済み。
- **IdP/Wallet VM**: `aifs-idp-*`(keycloak, grant-wallet)。内部 `10.20.112.103`、floating `.141`。Visa 署名鍵はこちら。

### 1.2 DNAT の再適用(reboot で消えていないか)— 最優先

mdx はグローバル IP で自分/他 VM に折り返せないため DNAT で内部 IP に振り替える(運用手順書 §3)。
`netfilter-persistent save` 済みだが、**reboot 後や rule 消失時に `.140/.141/.112` がタイムアウトする**。
冪等(`-C || -A`)に入れ直す。**各 VM で自分の分を実施**する。

**WEKO VM:**
```bash
IDP_PRIV=10.20.112.103
WEKO_PRIV=$(hostname -I | awk '{print $1}')      # =10.20.116.19
DG_PRIV=""                                        # .112 callback を出すときだけ内部IPを設定
for pair in "163.220.178.141 $IDP_PRIV" "163.220.178.140 $WEKO_PRIV" ${DG_PRIV:+"163.220.178.112 $DG_PRIV"}; do
  set -- $pair
  for chain in OUTPUT PREROUTING; do
    sudo iptables -t nat -C $chain -d $1 -j DNAT --to-destination $2 2>/dev/null \
      || sudo iptables -t nat -A $chain -d $1 -j DNAT --to-destination $2
  done
done
sudo netfilter-persistent save
```

**IdP/Wallet VM**(こちらも自分の DNAT を持つ):
```bash
WEKO_PRIV=10.20.116.19
IDP_PRIV=$(hostname -I | awk '{print $1}')        # =10.20.112.103
for pair in "163.220.178.141 $IDP_PRIV" "163.220.178.140 $WEKO_PRIV"; do
  set -- $pair
  for chain in OUTPUT PREROUTING; do
    sudo iptables -t nat -C $chain -d $1 -j DNAT --to-destination $2 2>/dev/null \
      || sudo iptables -t nat -A $chain -d $1 -j DNAT --to-destination $2
  done
done
sudo netfilter-persistent save
```

- `OUTPUT` = ホスト自身から、`PREROUTING` = Docker コンテナからの通信に効く(両方必要)。
- `-C || -A` なので既存 rule があれば何もしない。重複 rule は同一 target なら無害(先頭一致)。
- `.112`(DG)は callback を実配送するときだけ。稽古で callback を見せないなら省略可。

### 1.3 到達性の確認(数字で)

```bash
# WEKO 自身が生きている(reachable=404 が正常、DNAT 落ち=000)
DS=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("https://163.220.178.140/records/2000002"))')
curl -sk -o /dev/null -w 'weko /policy      = %{http_code}\n' "https://163.220.178.140/api/dac/v1/policy?dataset_id=$DS"
# WEKO コンテナ → .141(Wallet/IdP)到達(deposit・提示検証の経路)
docker exec -i weko-web-1 curl -sk -o /dev/null -w 'container→.141 jwks = %{http_code}\n' \
  https://163.220.178.141/wallet/.well-known/jwks.json
# IdP realm
curl -sk -o /dev/null -w 'idp oidc-config   = %{http_code}\n' \
  https://163.220.178.141/auth/realms/rdc/.well-known/openid-configuration
```

期待値: `/policy=404`(到達できている意味)、`container→.141 jwks=200`、`idp=200`。
**`000` が出たら §1.2 に戻る**(その VM の DNAT が落ちている)。

### 1.4 コード反映の確認(deposit flush 修正が乗っているか)

```bash
cd ~/dev/weko && git log --oneline -3      # flush 修正 commit があること
docker ps --format '{{.Names}}\t{{.Status}}' | grep -E 'weko-web|weko-worker'   # Up であること
```

flush 修正を直前に当てたなら `docker restart weko-web-1` 済みであること(コードは起動時読込)。

### 1.5 ウォレット整理(D-2)— 提示履歴/マイ許諾を綺麗に見せる

稽古のたびに `records/2000002` の許諾が積み上がる。台本の締め(**マイ許諾2件/提示履歴3行**)を
綺麗に出すため、直前に重複を最新1件へ寄せる。物語の小道具(HPCI 計算資源/クライオ電顕/
医用イメージング/別リポジトリ・コホート)は保持される。

```bash
export RESEARCHER_PW='...'          # hanako 本人パスワード(実値。プレースホルダ厳禁)
DRY_RUN=1 bash ~/wallet_cleanup.sh  # まず対象を確認
bash ~/wallet_cleanup.sh            # 実行(dispose は本人トークンで)
```

---

## 2. 通し(3経路)

先に実値を export:`export RESEARCHER_PW='...'; export DAR_AGENT_SECRET='...'`
(私が例示に使う `<...>` を**リテラルで入れない**。トークンが空になり全経路が落ちる)。

| 区分 | 手続き | 待ち時間 | 確認 |
|---|---|---|---|
| open (2000003) | 無認証。`GET /open-access` → `download_url` → 実体 | ゼロ | HTTP 200、checksum 一致 |
| registered (2000002) | `chain_demo.sh`(W-2 提示→`201`→**201 の `wallet_credential_id` で取得**) | 数秒 | **flush 修正後は `201` が `wc-` を直接載せ、pump ブランチに入らず PASS** |
| controlled (2000001) | 審査済み許諾で `access-token` → download | 数日(稽古は既存許諾) | 200、checksum 一致 |

締めの対比は `scene5_evidence.sh`:**監査ログ3件 / マイ許諾2件 / 提示履歴3行**
(open は無認証で提示なし=提示履歴に残らない。分冊04 §7.2)。

---

## 3. Go / No-go(公開基盤側)

- [ ] §1.3 の3つが `404 / 200 / 200`
- [ ] `chain_demo.sh` が **pump ブランチ無し**で PASS(`201` に `wallet_credential_id`)
- [ ] `scene5_evidence.sh` が 監査3 / 許諾2 / 提示履歴3
- [ ] `a3_visa_mismatch.sh` が `visa_dataset_mismatch`(異常系の芯)
- [ ] (任意)K-4 強制の異常系を見せるなら:allowlist 反映済み + `WEKO_DAC_ENFORCE_ISSUER_TRUST=true` + restart で `issuer_not_authorized`(403)を1本

**No-go 時の戻り先**:`000`→§1.2 DNAT。`201` が null→flush 修正の反映(§1.4)+`docker restart weko-web-1`。
トークン空→export に実値(プレースホルダ厳禁)。

---

## 4. 稽古後(順に反映)

1. §2 purpose 不一致の 401 化(`v04_s2.tar.gz`)を適用 → commit → **push** → `docker restart weko-web-1`。
2. K-4 発行者信頼:allowlist に `allowed_credential_types` 反映済みを確認のうえ
   `WEKO_DAC_ENFORCE_ISSUER_TRUST=true` へ(異常系を見せた後、運用値へ戻すかは要判断)。
3. 実施記録を `DEMO01_EXECUTION_ja.md` に追記。
