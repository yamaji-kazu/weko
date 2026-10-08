# -*- coding: utf-8 -*-
"""aifs ADR-25 — ⑤ Announce Relationship の受け止め(relations.py の純関数)。

WEKO の環境なしで走る:
    cd modules/weko-dac && python3 -m pytest tests/test_relations.py -q
通るものと同じだけ、拒否されるべきもの(他所宛て・許可していない送信者・別ドメインの参照先・署名の
無い/別の鍵の資源・中身の食い違い・別の記録の要約)が、拒否の code まで決まって拒否されることを見る。
"""
import json
import os
import sys

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from weko_dac import relations as rl  # noqa: E402

DG = 'https://dg.example'
REPO = 'https://db.example'
DS = 'https://db.example/records/2000052'
REL_URL = DG + '/api/approvals/relations/r1'
REC_URL = DG + '/api/approvals/rec-1'
JWKS = DG + '/api/approvals/jwks'
ALLOWED = [{'id': DG, 'jwks_uri': JWKS}]


def _key():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


DG_KEY = _key()
OTHER_KEY = _key()


def _jwk(k, kid='dg-1'):
    d = json.loads(ECAlgorithm.to_jwk(k.public_key()))
    d.update(kid=kid, alg='ES256')
    return d


def _sign(payload, typ, key=DG_KEY, kid='dg-1'):
    return jwt.encode(payload, key, algorithm='ES256', headers={'typ': typ, 'kid': kid})


def _rel(**over):
    p = {'iss': DG, 'jti': 'r1', 'subject': DS, 'relationship': rl.IS_REFERENCED_BY,
         'object': REC_URL, 'record_id': 'rec-1', 'target': REPO}
    p.update(over)
    return p


def _note(**over):
    b = {'@context': ['https://www.w3.org/ns/activitystreams', 'https://coar-notify.net'],
         'id': 'urn:uuid:n1', 'type': ['Announce', 'coar-notify:RelationshipAction'],
         'origin': {'id': DG, 'type': 'Service'}, 'target': {'id': REPO, 'type': 'Service'},
         'object': {'id': REL_URL, 'type': 'Relationship', 'as:subject': DS,
                    'as:relationship': rl.IS_REFERENCED_BY, 'as:object': REC_URL},
         'context': {'id': DS}}
    b.update(over)
    return b


def _fetchers(resources):
    def fetch_text(url):
        if url not in resources:
            raise IOError('404 %s' % url)
        return resources[url]

    def fetch_keys(uri):
        assert uri == JWKS
        return [_jwk(DG_KEY)]
    return fetch_text, fetch_keys


GOOD = {REL_URL: _sign(_rel(), rl.RELATION_TYP), REC_URL: _sign({'iss': DG, 'jti': 'rec-1'}, rl.SUMMARY_TYP)}


def _run(body, resources=None):
    fields, origin = rl.check_envelope(body, REPO, ALLOWED)
    ft, fk = _fetchers(GOOD if resources is None else resources)
    return rl.verify_references(fields, origin, REPO, ft, fk)


def _code(body, resources=None):
    try:
        _run(body, resources)
        return 'passed'
    except rl.RelationReject as e:
        return '%d %s' % (e.status, e.code)


def test_good_relation_is_accepted():
    rel = _run(_note())
    assert rel['record_id'] == 'rec-1' and rel['subject'] == DS


@pytest.mark.parametrize('label,body,want', [
    ('Endorsement を送る(推薦と誤記録される)', _note(type=['Announce', 'coar-notify:EndorsementAction']),
     '400 not_an_announce_relationship'),
    ('object の欠け', _note(object={'id': REL_URL}), '400 not_an_announce_relationship'),
    ('他所宛て', _note(target={'id': 'https://other.example'}), '403 target_mismatch'),
    ('許可していない送信者', _note(origin={'id': 'https://evil.example'}), '403 origin_not_allowed'),
    ('関係の資源が別ドメイン', _note(object={'id': 'https://evil.example/r', 'as:subject': DS,
                                         'as:relationship': rl.IS_REFERENCED_BY, 'as:object': REC_URL}),
     '403 object_not_on_origin'),
    ('承認記録が別ドメイン', _note(object={'id': REL_URL, 'as:subject': DS,
                                       'as:relationship': rl.IS_REFERENCED_BY,
                                       'as:object': 'https://evil.example/rec'}), '403 object_not_on_origin'),
    ('受けない関係の語', _note(object={'id': REL_URL, 'as:subject': DS,
                                     'as:relationship': 'http://purl.org/dc/terms/relation', 'as:object': REC_URL}),
     '400 unsupported_relationship'),
    ('context が主語でない', _note(context={'id': 'https://db.example/records/1'}), '400 not_an_announce_relationship'),
])
def test_envelope_rejections(label, body, want):
    assert _code(body) == want, label


@pytest.mark.parametrize('label,resources,want', [
    ('関係の資源が無い', {REC_URL: GOOD[REC_URL]}, '403 object_unverifiable'),
    ('関係の資源が別の鍵の署名', {REL_URL: _sign(_rel(), rl.RELATION_TYP, OTHER_KEY), REC_URL: GOOD[REC_URL]},
     '403 object_unverifiable'),
    ('関係の資源の typ 違い(要約を関係として)', {REL_URL: _sign(_rel(), rl.SUMMARY_TYP), REC_URL: GOOD[REC_URL]},
     '403 object_unverifiable'),
    ('関係の資源の発行者違い', {REL_URL: _sign(_rel(iss='https://evil.example'), rl.RELATION_TYP),
                              REC_URL: GOOD[REC_URL]}, '403 object_unverifiable'),
    ('別のリポジトリ宛ての関係の流用', {REL_URL: _sign(_rel(target='https://other.example'), rl.RELATION_TYP),
                                      REC_URL: GOOD[REC_URL]}, '403 relation_mismatch'),
    ('別のデータセットの関係', {REL_URL: _sign(_rel(subject='https://db.example/records/1'), rl.RELATION_TYP),
                              REC_URL: GOOD[REC_URL]}, '403 relation_mismatch'),
    ('承認記録が無い', {REL_URL: GOOD[REL_URL]}, '403 record_unverifiable'),
    ('承認記録が別の鍵の署名', {REL_URL: GOOD[REL_URL],
                              REC_URL: _sign({'iss': DG, 'jti': 'rec-1'}, rl.SUMMARY_TYP, OTHER_KEY)},
     '403 record_unverifiable'),
    ('承認記録が別の記録', {REL_URL: GOOD[REL_URL], REC_URL: _sign({'iss': DG, 'jti': 'rec-2'}, rl.SUMMARY_TYP)},
     '403 record_unverifiable'),
])
def test_reference_rejections(label, resources, want):
    assert _code(_note(), resources) == want, label


def test_envelope_rejections_do_not_fetch():
    """形・宛先・送信者で落ちるものは参照先を取りに行かない(外向きの取得を誘発させない)。"""
    with pytest.raises(rl.RelationReject):
        rl.check_envelope(_note(origin={'id': 'https://evil.example'}), REPO, ALLOWED)
