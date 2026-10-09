# -*- coding: utf-8 -*-
"""DAC の画面・エラー文言の英語化 (ロンドンでのデモ、2026-10)。

原文 (日本語) をそのままキーにする。日本語のときはキーをそのまま返すので、
日本語の出力は英語化の前とバイト単位で同じになる (gettext の msgid と同じ考え方)。

言語の決め方は二通り:

- :func:`ui_lang` — 管理画面 (DAC 審査者の画面)。WEKO の言語切替と同じ
  ``flask_babelex.get_locale()`` (invenio-i18n のセレクタ: セッション → 利用者設定 →
  Accept-Language → BABEL_DEFAULT_LOCALE) に従う。``ja`` 以外は英語にする。
- :func:`api_lang` — API の Problem Details の ``title``。DG / DR がサーバ間で呼ぶ
  (Accept-Language を付けない) ので、WEKO の既定ロケール (``en``) には従わず、
  **Accept-Language で英語を明示したときだけ**英語にする。無指定は従来どおり日本語。
  ``code`` と応答の形は言語によらず変えない。

Babel のカタログ (translations/ + invenio_i18n.translations の entry point) を
使わないのは、weko-dac が develop install で、entry point を足すと 140 のコンテナ内で
``pip install -e`` の再実行と .mo のコンパイルが要るため (.mo は .gitignore の対象外だが
バイナリをリポジトリに置くことになる)。辞書なら git pull と再起動だけで済む。
"""

# 管理画面 (templates/weko_dac/admin/*.html) と表示時に訳す既知の文言。
UI_EN = {
    # 共通
    '一覧へ戻る': 'Back to list',
    '状態': 'Status',
    '状態:': 'Status:',
    '審査区分': 'Access class',
    'タイトル': 'Title',
    # applications.html
    'DAC 申請一覧': 'DAC applications',
    '絞り込み': 'Filter',
    '研究者': 'Researcher',
    'エージェント': 'Agent',
    '受付日時': 'Received',
    'AI推奨': 'AI recommendation',
    '審査': 'Review',
    '申請はありません。': 'No applications.',
    # application_detail.html
    '申請': 'Application',
    '申請内容 (エンベロープ)': 'Application content (envelope)',
    '審査パッケージ (Assessment)': 'Assessment package',
    '再生成': 'Regenerate',
    '推奨判定:': 'Recommendation:',
    '根拠:': 'Rationale:',
    '推奨付帯条件:': 'Recommended conditions:',
    '照会メッセージ': 'Inquiry messages',
    'メッセージなし': 'No messages',
    '決裁履歴': 'Decision history',
    'AI推奨と相違': 'Differs from AI recommendation',
    '理由:': 'Reason:',
    '決裁なし': 'No decisions',
    '許諾の署名(審査者の VP)': 'Grant signature (officer VP)',
    '署名用の QR コード': 'QR code for signing',
    'スマホの学認ウォレット(GakuNin WALLET)でこの QR コードを読み取り、'
    '審査者の VC で取引に署名してください。':
        'Scan this QR code with GakuNin WALLET on your phone and sign the '
        'transaction with your DAC officer VC.',
    'ウォレットで次の提示要求に応え、審査者の VC で取引に署名してください'
    '(スマホでこの画面を開いているときは、タップするとウォレットが開きます):':
        'Answer the following presentation request in your wallet and sign '
        'the transaction with your DAC officer VC (if this page is open on '
        'your phone, tap the link to open the wallet):',
    '署名を確認して許諾を確定': 'Verify signature and confirm grant',
    '承認記録:': 'Approval record:',
    '決裁': 'Decision',
    '判定': 'Verdict',
    'approve (承認)': 'approve',
    'approve_with_conditions (条件付き承認)':
        'approve_with_conditions (approve with conditions)',
    'reject (却下)': 'reject',
    'request_info (照会)': 'request_info (ask the applicant)',
    '理由 (必須)': 'Reason (required)',
    '付帯条件 (1行1件 / 条件付き承認時)':
        'Conditions (one per line; for approve_with_conditions)',
    '照会文 (request_info時。空なら理由を送信)':
        'Inquiry text (for request_info; the reason is sent if empty)',
    'この判定を確定しますか?': 'Confirm this decision?',
    '決裁を確定': 'Confirm decision',
    '取消理由 (必須)': 'Reason for revocation (required)',
    '許諾を取り消しますか? 発行済みVisaは失効します。':
        'Revoke this grant? Issued Visas will be invalidated.',
    '許諾を取消 (revoke)': 'Revoke grant',
    '状態 %(s)s では決裁操作はできません。':
        'No decision can be made in status %(s)s.',
    # assessment.py が付ける推奨付帯条件 (保存済みデータなので表示時に訳す)
    '利用終了時の削除報告を義務化':
        'Mandatory report of data deletion at the end of use',
    # offers.html
    'データセット利用条件 (ODRL Offer)': 'Dataset access conditions (ODRL Offer)',
    '新規登録': 'New Offer',
    'データ': 'Data',
    '更新日': 'Updated',
    '登録あり': 'Registered',
    '編集': 'Edit',
    'Offer は登録されていません。': 'No Offers registered.',
    # offer_edit.html
    'Offer 編集': 'Edit Offer',
    'Offer 新規登録': 'New Offer',
    'Dataset ID (DOI 等の URI) *': 'Dataset ID (URI such as a DOI) *',
    'タイトル (管理用)': 'Title (internal)',
    '許容 DUO コード (カンマ区切り。例: DUO:0000042)':
        'Permitted DUO codes (comma-separated, e.g. DUO:0000042)',
    '利用期間上限 (xsd:duration 例 P2Y、または終了日 YYYY-MM-DD)':
        'Maximum period of use (xsd:duration, e.g. P2Y, or end date '
        'YYYY-MM-DD)',
    '保管先要件 (例: rdc:certified-storage。空欄で制約なし)':
        'Storage requirement (e.g. rdc:certified-storage; empty = none)',
    '地理的制約 (ISO 3166。例: JP。空欄で制約なし)':
        'Geographic restriction (ISO 3166, e.g. JP; empty = none)',
    '倫理審査承認を要求する': 'Require ethics review approval',
    '義務 (duty)': 'Duties',
    '禁止 (prohibition)': 'Prohibitions',
    'データ実体 (サーバ上のファイルパス、または配信 URL)':
        'Data file (path on the server, or distribution URL)',
    '制限公開データの配信 (§6.3) に使用。ローカルパスの場合は保存時に sha256 を計算します。':
        'Used to deliver restricted data (§6.3). For a local path, the '
        'sha256 is computed when saving.',
    '保存 (ODRL Offer を生成)': 'Save (generate ODRL Offer)',
    'キャンセル': 'Cancel',
    '生成済み ODRL Offer': 'Generated ODRL Offer',
}

_SUPPORTED = ('ja', 'en')


def ui_lang():
    """管理画面の言語 ('ja' / 'en')。WEKO の言語切替 (get_locale) に従う。

    リクエストの外 (CLI・単体試験) やロケールが取れないときは 'ja' (従来の表示)。
    """
    try:
        from flask_babelex import get_locale
        loc = get_locale()
    except Exception:  # Babel 未初期化 / アプリ文脈の外
        loc = None
    if loc is None:
        return 'ja'
    return 'ja' if str(loc.language) == 'ja' else 'en'


def api_lang():
    """API の人間向け文言の言語。Accept-Language で英語を明示したときだけ 'en'。

    ja と en のうち、品質値の高い順で最初に現れた主言語タグ (en-GB → en) を採る。
    ヘッダが無い・どちらも無い・リクエストの外なら 'ja' (従来どおり)。
    """
    try:
        from flask import request
        accept = request.accept_languages
    except Exception:  # リクエストの外
        return 'ja'
    for value, _quality in accept:
        primary = (value or '').replace('_', '-').split('-')[0].lower()
        if primary in _SUPPORTED:
            return primary
    return 'ja'


def translate(msg, lang, **kw):
    """``msg`` (日本語の原文) を ``lang`` に訳す。未登録の文言は原文のまま返す。"""
    text = msg if lang == 'ja' else UI_EN.get(msg, msg)
    return text % kw if kw else text


def template_helpers(lang=None):
    """テンプレートに渡す ``tr`` (1 件) と ``trl`` (リスト) を返す。"""
    if lang is None:
        lang = ui_lang()

    def tr(msg, **kw):
        return translate(msg, lang, **kw)

    def trl(seq):
        return [translate(m, lang) if isinstance(m, str) else m
                for m in (seq or [])]

    return {'tr': tr, 'trl': trl, 'dac_lang': lang}
