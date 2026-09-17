# -*- coding: utf-8 -*-
"""分冊05 §12.2.2 — purpose は許容集合への所属判定。

matching.py は Flask に依存しないので、この試験は WEKO の環境なしで走る:
    cd modules/weko-dac && python3 -m pytest tests -q
拒否されるべきものが拒否されることを、通るものと同じ数だけ見る。
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from weko_dac import matching  # noqa: E402

GRU, HMB, DS, NRES, POA = ('DUO:0000042', 'DUO:0000006', 'DUO:0000007',
                           'DUO:0000004', 'DUO:0000011')
NPUNCU, NMDS, IRB = 'DUO:0000018', 'DUO:0000015', 'DUO:0000021'


def _iri(code):
    return {'@id': 'http://purl.obolibrary.org/obo/DUO_' + code.split(':')[1]}


def _offer_c(code):
    return {'leftOperand': 'purpose', 'operator': 'isA', 'rightOperand': _iri(code)}


def _req(code):
    return {'constraint': [_offer_c(code)]}


# --- 通るもの -------------------------------------------------------------

def test_gru_permits_hmb():
    v = matching.purpose_verdict([GRU], [HMB])
    assert v['permitted'] and v['primary'] == GRU and v['rejected'] == []


def test_gru_permits_ds_transitively():
    assert matching.purpose_verdict([GRU], [DS])['permitted']


def test_nres_permits_everything_known():
    for code in (GRU, HMB, DS, POA):
        assert matching.purpose_verdict([NRES], [code])['permitted'], code


def test_same_code_permits_itself():
    assert matching.purpose_verdict([DS], [DS])['permitted']


def test_modifiers_on_offer_are_not_used_for_verdict():
    v = matching.purpose_verdict([GRU, NPUNCU, NMDS], [HMB])
    assert v['permitted']
    assert v['modifiers'] == [NPUNCU, NMDS] and v['primary'] == GRU


def test_offer_without_purpose_constraint_permits():
    assert matching.purpose_verdict([], [HMB])['permitted']


def test_request_side_modifier_is_ignored_not_rejected():
    # 申請側が修飾子を混ぜても目的とは扱わない (宣言するものではない)
    assert matching.purpose_verdict([GRU], [HMB, NPUNCU])['permitted']


# --- 拒否されるもの (同じ数だけ) ---------------------------------------------

def test_hmb_does_not_permit_gru():
    v = matching.purpose_verdict([HMB], [GRU])
    assert not v['permitted'] and v['rejected'] == [GRU]


def test_ds_does_not_permit_hmb():
    assert not matching.purpose_verdict([DS], [HMB])['permitted']


def test_poa_and_hmb_are_siblings():
    assert not matching.purpose_verdict([POA], [HMB])['permitted']
    assert not matching.purpose_verdict([HMB], [POA])['permitted']


def test_unknown_request_code_is_rejected():
    assert not matching.purpose_verdict([NRES], ['DUO:9999999'])['permitted']


def test_every_declared_code_must_be_permitted():
    v = matching.purpose_verdict([HMB], [DS, POA])
    assert not v['permitted'] and v['rejected'] == [POA]


def test_only_modifiers_declared_is_not_a_purpose():
    v = matching.purpose_verdict([GRU], [NPUNCU])
    assert not v['permitted'] and v['rejected'] == []


def test_unknown_offer_code_permits_only_itself():
    assert matching.purpose_verdict(['DUO:9999999'], ['DUO:9999999'])['permitted']
    assert not matching.purpose_verdict(['DUO:9999999'], [GRU])['permitted']


# --- evaluate_constraint (controlled 経路の評価器) ---------------------------

def test_evaluate_constraint_modifier_is_carried_over():
    res = matching.evaluate_constraint(_offer_c(IRB), _req(DS))
    assert res['result'] == 'satisfied' and 'modifier' in res['detail']


def test_evaluate_constraint_primary_still_judges():
    assert matching.evaluate_constraint(_offer_c(GRU), _req(HMB))['result'] == 'satisfied'
    assert matching.evaluate_constraint(_offer_c(HMB), _req(GRU))['result'] == 'not_satisfied'


def test_match_ds_plus_irb_offer_accepts_ds_request():
    # 140 の controlled Offer に実在する組み合わせ (DS + IRB)。以前は IRB の行が
    # not_satisfied になり、DS の申請が原理的に通らなかった
    offer = {'permission': [{'action': 'use',
                             'constraint': [_offer_c(DS), _offer_c(IRB)]}]}
    req = {'permission': [{'action': 'use', 'constraint': [_offer_c(DS)]}]}
    report = matching.match(offer, req)
    assert report['overall'] == 'satisfied', report
    assert report['duo_snapshot_version'] == 'demo-2026-09'


def test_snapshot_classifies_modifiers():
    for code in (NPUNCU, NMDS, IRB, 'DUO:0000044', 'DUO:0000046'):
        assert matching.duo_is_modifier(code), code
    for code in (GRU, HMB, DS, NRES, POA, 'DUO:0000001'):
        assert not matching.duo_is_modifier(code), code
