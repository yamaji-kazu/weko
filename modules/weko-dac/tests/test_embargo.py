# -*- coding: utf-8 -*-
"""分冊05 §2.7 / §8.1a・分冊01 §6.3 手順7 — エンバーゴ (公開猶予) の判定。

エンバーゴは Request と突き合わせるのではなく現在時刻と突き合わせる (§8.1a)。
matching.py は Flask に依存しないので、この試験は WEKO の環境なしで走る:
    cd modules/weko-dac && python3 -m pytest tests -q
拒否されるべきもの (エンバーゴ中) が拒否されることを、通るもの (明け済み) と同じ
数だけ見る。
"""
import os
import sys
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from weko_dac import matching  # noqa: E402


def _offer(constraints):
    return {'permission': [{'constraint': constraints}]}


# --- 絶対日 (odrl:dateTime gteq) ---

def test_absolute_future_is_embargoed():
    o = _offer([{'leftOperand': 'odrl:dateTime', 'operator': 'odrl:gteq',
                 'rightOperand': '2099-01-01'}])
    embargoed, lift, _ = matching.evaluate_embargo(o)
    assert embargoed and lift and lift.year == 2099


def test_absolute_past_is_not_embargoed():
    o = _offer([{'leftOperand': 'dateTime', 'operator': 'gteq',
                 'rightOperand': '2000-01-01'}])
    embargoed, _lift, _ = matching.evaluate_embargo(o)
    assert not embargoed


# --- 相対期間 (rdc:embargoPeriod + rdc:embargoAnchor) ---

def test_relative_unknown_anchor_is_embargoed():
    # 起点日時が未確定 → まだ明けていない扱い (不確定を公開に倒さない、§2.7)。
    o = _offer([{'leftOperand': 'rdc:embargoAnchor', 'operator': 'eq',
                 'rightOperand': 'publication'},
                {'leftOperand': 'rdc:embargoPeriod', 'operator': 'gteq',
                 'rightOperand': 'P12M'}])
    embargoed, lift, _ = matching.evaluate_embargo(o)
    assert embargoed and lift is None


def test_relative_past_anchor_is_lifted():
    o = _offer([{'leftOperand': 'rdc:embargoAnchor', 'operator': 'eq',
                 'rightOperand': 'publication'},
                {'leftOperand': 'rdc:embargoPeriod', 'operator': 'gteq',
                 'rightOperand': 'P1M'}])
    embargoed, _lift, _ = matching.evaluate_embargo(
        o, anchor_dates={'publication': date(2000, 1, 1)})
    assert not embargoed


def test_no_embargo_constraint_is_not_embargoed():
    o = _offer([{'leftOperand': 'dateTime', 'operator': 'lteq',
                 'rightOperand': '2028-03-31'}])
    embargoed, _lift, _ = matching.evaluate_embargo(o)
    assert not embargoed


# --- マッチング側: gteq は Request と突き合わせず素通し (§8.1a) ---

def test_matching_gteq_is_not_matched_against_request():
    # Request に対応値が無くても needs_human / not_satisfied に倒れない。
    v = matching.evaluate_constraint(
        {'leftOperand': 'dateTime', 'operator': 'gteq',
         'rightOperand': '2099-01-01'}, {'constraint': []})
    assert v['result'] == 'satisfied'


def test_matching_lteq_still_enforced():
    # 利用期間 (lteq) は従来どおり Request と突き合わせる (回帰防止)。
    v = matching.evaluate_constraint(
        {'leftOperand': 'dateTime', 'operator': 'lteq',
         'rightOperand': '2028-03-31'},
        {'constraint': [{'leftOperand': 'dateTime', 'operator': 'lteq',
                         'rightOperand': '2027-01-01'}]})
    assert v['result'] == 'satisfied'
    v2 = matching.evaluate_constraint(
        {'leftOperand': 'dateTime', 'operator': 'lteq',
         'rightOperand': '2028-03-31'},
        {'constraint': [{'leftOperand': 'dateTime', 'operator': 'lteq',
                         'rightOperand': '2030-01-01'}]})
    assert v2['result'] == 'not_satisfied'
