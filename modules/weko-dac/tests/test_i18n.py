# -*- coding: utf-8 -*-
"""DAC 管理画面と Problem Details の英語化 (i18n.py)。

WEKO の web イメージ (Python 3.6 / Flask-BabelEx / invenio-i18n) で走る:
    cd modules/weko-dac && python -m pytest tests/test_i18n.py -q

見ること:
- 4 つの管理画面を、分岐をすべて通す文脈で ja と en の両方で描く。en に日本語が
  1 文字も残らないこと (訳し漏れ・辞書の綴り違いはここで落ちる)。ja には原文が出ること。
- 言語は WEKO の言語切替 (invenio-i18n のセッション) に従うこと。対照として
  逆の言語も同じ試験の中で見る (どちらの言語でも同じ出力なら、切替を見ていない)。
- API の title は Accept-Language で英語を明示したときだけ英語。無指定は日本語のまま。
  code・type は言語で変わらないこと。
"""
import datetime
import io
import os
import re
import sys
from types import SimpleNamespace as NS

import pytest
from flask import Flask, render_template, session
from jinja2 import ChoiceLoader, DictLoader, FileSystemLoader

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from weko_dac import auth, i18n  # noqa: E402

TPL_ROOT = os.path.join(os.path.dirname(__file__), '..', 'weko_dac',
                        'templates')
ADMIN_DIR = os.path.join(TPL_ROOT, 'weko_dac', 'admin')
JA_CHAR = re.compile(u'[぀-ヿ㐀-鿿＀-￯]')
T0 = datetime.datetime(2026, 10, 9, 12, 34)


def make_app(template_root=TPL_ROOT):
    app = Flask('dac_i18n_test')
    app.config['SECRET_KEY'] = 'test-only'
    app.jinja_loader = ChoiceLoader([
        DictLoader({'admin/master.html':
                    '{% block body %}{% endblock %}'}),
        FileSystemLoader(template_root)])
    return app


def _url_for(endpoint, **kw):
    return '/' + endpoint + ''.join('/%s' % kw[k] for k in sorted(kw))


def _application(status):
    return NS(application_id='app-1', status=status,
              madmp_id='https://example.org/dmp/1')


def _grant(state):
    return NS(decision='approve', officer_id='officer@example.org',
              state=state, created_at=T0, subject_id='subj-' + state,
              authorization_request_url='openid4vp://?request_uri=x',
              record_id='rec-1' if state != 'pending' else None)


def contexts():
    """(template, context) — 各テンプレートの分岐をすべて通す組。"""
    assessment = NS(assessment={'recommendation': {
        'decision': 'approve_with_conditions', 'confidence': 0.85,
        'rationale': 'All ODRL constraints satisfied.',
        'conditions': ['利用終了時の削除報告を義務化']}})
    detail_base = dict(
        assessment=assessment, assessment_json='{}', payload_json='{}',
        messages=[NS(sender='dg', author_kind='agent', type='inquiry',
                     sent_at=T0, body='hello')],
        decisions=[NS(decision='approve', decided_by='officer',
                      decided_at=T0, diverges_from_ai=True,
                      reason='ok')],
        grant_approvals=[_grant('pending'), _grant('approved')],
        grant_qr_urls={'subj-pending': 'https://example.org/r/1'},
        csrf_token=lambda: 'tok')
    empty_detail = dict(detail_base, messages=[], decisions=[],
                        grant_approvals=[], grant_qr_urls={})
    offer = NS(id=1, dataset_id='https://doi.org/10.1/x', title='T',
               access_class='registered', distribution_uri='/x.zip',
               updated_at=T0, template={'duties': ['rdc:cite']},
               offer={'uid': 'o-1'})
    out = []
    for st in ('under_review', 'active', 'rejected'):
        out.append(('application_detail.html',
                    dict(detail_base, application=_application(st))))
    out.append(('application_detail.html',
                dict(empty_detail, application=_application('submitted'))))
    out.append(('applications.html', dict(
        applications=[NS(application_id='app-1', status='active',
                         researcher_sub='r', agent_id='a', received_at=T0)],
        recos={'app-1': 'approve'}, status='active')))
    out.append(('applications.html', dict(applications=[], recos={},
                                          status='')))
    out.append(('offers.html', dict(offers=[offer])))
    out.append(('offers.html', dict(offers=[])))
    choices = dict(duty_choices=['rdc:cite'],
                   prohibition_choices=['distribute'])
    out.append(('offer_edit.html', dict(choices, offer=offer)))
    out.append(('offer_edit.html', dict(choices, offer=None)))
    return out


def render(app, name, ctx, helpers=None):
    ctx = dict(ctx, url_for=_url_for)
    if helpers is not None:
        ctx.update(helpers)
    with app.test_request_context('/'):
        return render_template('weko_dac/admin/' + name, **ctx)


def test_every_template_string_has_english():
    keys = set()
    for name in os.listdir(ADMIN_DIR):
        src = io.open(os.path.join(ADMIN_DIR, name), encoding='utf-8').read()
        keys.update(re.findall(r"tr\('([^']*)'", src))
    assert keys, 'tr() が 1 件も無い — 走査の手段を疑う'
    missing = sorted(k for k in keys if k not in i18n.UI_EN)
    assert missing == []


@pytest.mark.parametrize('idx', range(len(contexts())))
def test_template_en_has_no_japanese_and_ja_keeps_original(idx):
    app = make_app()
    name, ctx = contexts()[idx]
    en = render(app, name, ctx, i18n.template_helpers('en'))
    ja = render(app, name, ctx, i18n.template_helpers('ja'))
    left = sorted(set(JA_CHAR.findall(en)))
    assert left == [], '%s に日本語が残った: %s' % (name, ''.join(left))
    assert JA_CHAR.search(ja), '%s の ja に日本語が出ていない' % name
    assert en != ja


def test_english_strings_are_safe_inside_js_confirm():
    # confirm('...') の中に埋めるので、英訳に ' があると JS が壊れる
    for ja in ('この判定を確定しますか?',
               '許諾を取り消しますか? 発行済みVisaは失効します。'):
        assert "'" not in i18n.UI_EN[ja]


def test_ui_lang_follows_weko_language_selector():
    from invenio_i18n import InvenioI18N
    app = make_app()
    app.config.update(BABEL_DEFAULT_LOCALE='en',
                      I18N_LANGUAGES=[('ja', 'Japanese')])
    InvenioI18N(app)
    seen = {}
    for lang in ('ja', 'en'):
        with app.test_request_context('/'):
            session['language'] = lang  # invenio-i18n の I18N_SESSION_KEY 既定
            seen[lang] = i18n.ui_lang()
    assert seen == {'ja': 'ja', 'en': 'en'}
    # 外 (CLI 等) は従来の日本語
    assert i18n.ui_lang() == 'ja'


@pytest.mark.parametrize('header,expected', [
    (None, 'ja'),                       # DG / DR のサーバ間呼び出し
    ('en-GB,en;q=0.9', 'en'),
    ('ja,en;q=0.8', 'ja'),
    ('en;q=0.5,ja;q=0.9', 'ja'),
    ('fr-FR', 'ja'),
])
def test_api_lang_needs_explicit_english(header, expected):
    app = make_app()
    headers = {'Accept-Language': header} if header else {}
    with app.test_request_context('/', headers=headers):
        assert i18n.api_lang() == expected


def test_problem_title_localized_but_code_and_type_unchanged():
    assert set(auth.PROBLEM_TITLES_EN) == set(auth.PROBLEM_TITLES)
    app = make_app()
    code = 'presentation_purpose_mismatch'
    with app.test_request_context('/'):
        ja_title, ja_type = auth.problem_title(code), auth.problem_type(code)
        ja_body = auth.AuthError(401, code, 'd').as_response().get_json()
    with app.test_request_context('/', headers={'Accept-Language': 'en'}):
        en_title, en_type = auth.problem_title(code), auth.problem_type(code)
        en_body = auth.AuthError(401, code, 'd').as_response().get_json()
    assert ja_title == '提示の用途が経路と一致しません'
    assert en_title == 'Presentation purpose does not match the route'
    assert ja_type == en_type
    assert sorted(ja_body) == sorted(en_body)
    assert dict(ja_body, title=None) == dict(en_body, title=None)
    for c in auth.PROBLEM_TITLES_EN:
        assert not JA_CHAR.search(auth.PROBLEM_TITLES_EN[c]), c
