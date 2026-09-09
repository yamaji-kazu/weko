# -*- coding: utf-8 -*-
"""registered / open アクセス区分 (RDC-AAP-01 §11, 分冊05 §12).

- ``registered``: 資格提示による**自動許諾**。Triple-A(認証/誓約/認可)を
  すべて**決定的なルール評価**で処理し、人間の審査を経ずに Agreement + Visa を
  発行して Wallet に格納する。LLM は判定に使わない (§11.2.2-4)。
- ``open``: 認証なしの直接取得 (§11.1)。
- ``controlled`` は既存の §5〜§8 (申請→審査) を使う。

取得経路 (Grant Presentation → access-token → download) は区分で変えない
(§11.2.3)。open のみ許諾が存在しないため直接取得になる。
"""
from datetime import datetime
from urllib.parse import quote
import uuid

from flask import current_app, jsonify
from invenio_db import db

from . import allowlist, audit, presentation, services
from .auth import (problem_title, problem_type, verify_jws,
                   verify_jws_with_keys)
from .models import DacApplication, DacOffer


#: leftOperand → GA4GH Visa type (分冊05 §12.2)
_REQ_TO_VISA = {
    'rdc:researcherStatus': 'ResearcherStatus',
    'rdc:affiliation': 'AffiliationAndRole',
    'rdc:acceptedTerms': 'AcceptedTermsAndPolicies',
}


class RegError(Exception):
    """Problem Details を返すためのエラー (§11.2.2 / §6.6)。"""

    def __init__(self, status, code, detail, unmet=None):
        self.status = status
        self.code = code
        self.detail = detail
        self.unmet = unmet
        super().__init__(detail)

    def as_response(self):
        # type/title は code から自動生成 (RDC-AAP-01 §5.8.2)。title に
        # 生のエラーコードは入れない。
        body = {'type': problem_type(self.code),
                'title': problem_title(self.code),
                'status': self.status, 'detail': self.detail,
                'code': self.code}
        if self.unmet is not None:
            body['unmet_requirements'] = self.unmet
        resp = jsonify(body)
        resp.status_code = self.status
        resp.headers['Content-Type'] = 'application/problem+json'
        return resp


def _verifier():
    """(verify_fn, method) — services._verify_passport と同じ鍵ソース。

    allowlist の ``visa_issuer`` の inline jwks / jwks_uri、無ければデモ IdP の
    realm JWKS へフォールバック。
    """
    vi = allowlist.visa_issuer_entity()
    if vi is not None:
        expected_iss = vi.get('entity_id')
        inline = allowlist.entity_inline_jwks(vi)

        def verify_fn(token):
            if inline:
                return verify_jws_with_keys(token, inline, issuer=expected_iss)
            if vi.get('jwks_uri'):
                return verify_jws(token, vi['jwks_uri'], issuer=expected_iss)
            raise RegError(500, 'allowlist_misconfigured',
                           'visa_issuer entry has neither jwks nor jwks_uri')
        return verify_fn, 'allowlist_visa_issuer'

    issuer = current_app.config.get('WEKO_DAC_OIDC_ISSUER') or None
    jwks = current_app.config.get('WEKO_DAC_OIDC_JWKS_URL')
    if not jwks and issuer:
        jwks = issuer.rstrip('/') + '/protocol/openid-connect/certs'
    if not jwks:
        raise RegError(503, 'visa_issuer_unconfigured',
                       'no visa_issuer in allowlist and IdP JWKS not '
                       'configured')

    def verify_fn(token):
        return verify_jws(token, jwks, issuer=issuer)
    return verify_fn, 'idp_jwks_fallback'


def verify_passport_visas(passport_jwt, researcher_sub):
    """Passport/Visa を検証し、``ga4gh_visa_v1`` オブジェクトの列を返す。

    (§11.2.1 Authentication)。sub は access-token の sub と一致必須。
    """
    if not passport_jwt:
        raise RegError(403, 'invalid_passport', 'passport is empty')
    verify_fn, method = _verifier()
    try:
        payload = verify_fn(passport_jwt)
    except RegError:
        raise
    except Exception as ex:
        raise RegError(403, 'invalid_passport',
                       'passport not verifiable with visa_issuer keys: %s'
                       % ex)
    if researcher_sub and payload.get('sub') \
            and payload['sub'] != researcher_sub:
        raise RegError(403, 'subject_mismatch',
                       'passport sub does not match the access-token sub')

    visas = []
    if payload.get('ga4gh_visa_v1'):
        visas.append(payload['ga4gh_visa_v1'])
    elif isinstance(payload.get('ga4gh_passport_v1'), list) \
            and payload['ga4gh_passport_v1']:
        for vjwt in payload['ga4gh_passport_v1']:
            try:
                vp = verify_fn(vjwt)
            except Exception as ex:
                raise RegError(403, 'invalid_passport',
                               'inner Visa not verifiable: %s' % ex)
            if researcher_sub and vp.get('sub') \
                    and vp['sub'] != researcher_sub:
                raise RegError(403, 'subject_mismatch',
                               'inner Visa sub does not match token sub')
            v = vp.get('ga4gh_visa_v1')
            if v:
                visas.append(v)
    else:
        raise RegError(403, 'invalid_passport',
                       'neither ga4gh_visa_v1 nor ga4gh_passport_v1 present')
    return visas, method


def _duo_code_from_iri(iri):
    if not iri:
        return None
    tail = str(iri).rstrip('/').split('/')[-1]
    if tail.startswith('DUO_'):
        return 'DUO:' + tail.split('_', 1)[1]
    return tail if str(tail).startswith('DUO:') else None


def _remediation_url(requirement, dataset_id):
    """その要件を解消する手続きの入口 URL (分冊01 §5.8.3, SHOULD)。

    ``WEKO_DAC_REMEDIATION_URLS`` (requirement→URL の dict) に設定がある要件だけ
    付与する。dataset_id があれば ``?dataset=`` を付ける。未設定なら None (省略)。
    """
    mapping = current_app.config.get('WEKO_DAC_REMEDIATION_URLS') or {}
    base = mapping.get(requirement)
    if not base:
        return None
    if dataset_id:
        sep = '&' if '?' in base else '?'
        return '%s%sdataset=%s' % (base, sep, quote(dataset_id, safe=''))
    return base


def _unmet_entry(requirement, reason, detail, dataset_id):
    """未充足要件の1件 (分冊01 §5.8.3)。

    ``reason`` は閉じた語彙 (``absent`` / ``value-mismatch`` / ``invalid``) のみ。
    人間向けの文言は ``detail`` に載せる (呼出側は未知メンバを無視する)。
    ``remediation_url`` は設定がある場合のみ付く (SHOULD)。
    """
    entry = {'requirement': requirement, 'reason': reason, 'detail': detail}
    url = _remediation_url(requirement, dataset_id)
    if url:
        entry['remediation_url'] = url
    return entry


def unmet_requirements(offer_doc, visas, purpose, dataset_id=None):
    """決定的ルール評価 (§11.2.1 / 分冊05 §12.2)。

    Offer の資格 constraint を要求者の Visa と突合し、**未充足の要件**を返す
    (空リスト = すべて充足)。判定不能は不充足として扱い、``needs_human`` は
    生じない。LLM は使わない。各要素は ``{requirement, reason, detail,
    remediation_url?}`` (分冊01 §5.8.3、``reason`` は閉じた語彙)。
    """
    by_type = {}
    for v in visas:
        by_type.setdefault(v.get('type'), []).append(v)
    unmet = []
    constraints = []
    for p in offer_doc.get('permission') or []:
        constraints.extend(p.get('constraint') or [])
    requested_duo = set((purpose or {}).get('duo_codes') or [])

    for c in constraints:
        lo = c.get('leftOperand')
        vtype = _REQ_TO_VISA.get(lo)
        if vtype:
            present = by_type.get(vtype) or []
            if not present:
                unmet.append(_unmet_entry(
                    lo, 'absent', '%s Visa がありません' % vtype, dataset_id))
                continue
            if lo == 'rdc:acceptedTerms':
                ro = c.get('rightOperand')
                want = ro.get('@id') if isinstance(ro, dict) else ro
                if want and not any(v.get('value') == want for v in present):
                    unmet.append(_unmet_entry(
                        lo, 'value-mismatch',
                        '指定の規約 (%s) への同意 Visa がありません' % want,
                        dataset_id))
        elif lo == 'purpose':
            ro = c.get('rightOperand') or {}
            iri = ro.get('@id') if isinstance(ro, dict) else ro
            code = _duo_code_from_iri(iri)
            if code and requested_duo and code not in requested_duo:
                unmet.append(_unmet_entry(
                    'purpose', 'value-mismatch',
                    '要求 purpose が Offer の許容 (%s) に含まれません' % code,
                    dataset_id))
    return unmet


def _visas_from_elements(elements, researcher_sub):
    """提示物 (§11) の各要素の **原本 (raw)** を資格 Visa として検証し、
    ``ga4gh_visa_v1`` オブジェクトの列を返す (分冊05 §11.3: 判定は原本から)。"""
    verify_fn, method = _verifier()
    visas = []
    for el in elements:
        fmt = el.get('credential_format') or 'ga4gh-visa+jwt'
        if fmt != 'ga4gh-visa+jwt':
            # デモの資格系は ga4gh-visa+jwt。他形式 (sd-jwt-vc/vc+jwt) は
            # 検証器の形式分岐として後続段で対応する。
            raise RegError(400, 'unsupported_presentation_type',
                           'credential_format %s not yet supported' % fmt)
        try:
            vp = verify_fn(el['raw'])
        except RegError:
            raise
        except Exception as ex:
            raise RegError(403, 'invalid_passport',
                           'inner credential not verifiable: %s' % ex)
        if researcher_sub and vp.get('sub') \
                and vp['sub'] != researcher_sub:
            raise RegError(403, 'subject_mismatch',
                           'inner credential sub does not match token sub')
        v = vp.get('ga4gh_visa_v1')
        if v:
            visas.append(v)
    return visas, 'presentation:' + method


def grant_registered(dataset_id, researcher_sub, agent_id,
                     presentation_jws=None, passport_jwt=None,
                     intended_use=None, callback_url=None):
    """registered 資源への自動許諾 (§11.2)。

    入力は Credential Wallet の **提示物** (``presentation_jws``、v0.4)。移行期は
    GA4GH Passport (``passport_jwt``) も受理し、監査に ``presentation_absent`` を
    立てる。充足時: 即時自動承認の申請を1件作り、既存の許諾発行 (§6) を再利用して
    Agreement + Visa を発行・Wallet 格納し、callback を即時配送する。
    不充足時: RegError(403, requirements_not_met) を送出する。
    """
    offer_row = DacOffer.query.filter_by(dataset_id=dataset_id).first()
    if offer_row is None:
        raise RegError(404, 'unknown_dataset',
                       'No policy registered for %s' % dataset_id)
    ac = offer_row.access_class
    if ac == 'controlled':
        raise RegError(409, 'access_class_mismatch',
                       'controlled dataset; use POST /applications (§5.2)')
    if ac != 'registered':
        raise RegError(409, 'access_class_mismatch',
                       'dataset accessClass is "%s", not "registered"' % ac)
    if allowlist.check_agent(agent_id or '') == 'denied':
        raise RegError(403, 'agent_not_allowlisted',
                       'agent %s is not in the static allowlist' % agent_id)

    # Authentication + Attestation (§11.2.1 / §6.3 手順1〜3・5〜6)
    if presentation_jws:
        meta, elements = presentation.verify_presentation(
            presentation_jws, expected_purpose='registered-access')
        if researcher_sub and meta['sub'] and meta['sub'] != researcher_sub:
            raise RegError(403, 'subject_mismatch',
                           'presentation.sub != token.sub')
        if meta['presented_by'] != agent_id:
            raise RegError(403, 'agent_mismatch',
                           'presented_by != token act.sub')
        visas, method = _visas_from_elements(elements, researcher_sub)
        presentation_absent = False
        pres_purpose = meta.get('purpose')
    elif passport_jwt:
        # 移行期: 生 Passport 入力 (分冊01 §11.2.2)
        visas, method = verify_passport_visas(passport_jwt, researcher_sub)
        presentation_absent = True
        pres_purpose = None
    else:
        raise RegError(400, 'presentation_required',
                       'presentation (移行期は passport) が必要です')
    # 発行者の権限 (§3.2 / §6.3 手順3)。未強制の間は素通り (移行期)。
    assigner = (offer_row.offer or {}).get('assigner')
    for v in visas:
        presentation.check_issuer_authority(
            v.get('type'), v.get('source'), assigner)
    # Authorization (§12.2 決定的突合)
    unmet = unmet_requirements(offer_row.offer, visas, intended_use,
                               dataset_id=dataset_id)
    if unmet:
        audit.record('registered.denied',
                     subject={'dataset_id': dataset_id},
                     actor={'kind': 'agent', 'id': agent_id,
                            'on_behalf_of': researcher_sub},
                     payload={'unmet': unmet, 'method': method,
                              'access_class': 'registered',
                              'credential_types': [presentation.rdc_type(
                                  v.get('type')) for v in visas],
                              'purpose': pres_purpose or 'registered-access',
                              'intended_use': intended_use or {},
                              'presentation_absent': presentation_absent})
        db.session.commit()
        raise RegError(403, 'requirements_not_met',
                       '資格要件が満たされていません', unmet=unmet)

    application = DacApplication(
        application_id='app-{0}-{1}'.format(
            datetime.utcnow().strftime('%Y'), uuid.uuid4().hex[:8]),
        status='under_review',
        resource_type='dataset',
        researcher_sub=researcher_sub,
        agent_id=agent_id,
        callback_url=callback_url,
        payload={'resource_type': 'dataset', 'access_route': 'registered',
                 'requests': [{'dataset_id': dataset_id,
                               'intended_use': intended_use or {}}]},
        verification={'trust_chain': 'static_allowlist',
                      'access_route': 'registered',
                      'visa_method': method,
                      'presentation_absent': presentation_absent,
                      'visa_types': [v.get('type') for v in visas],
                      'visa_sources': [v.get('source') for v in visas]})
    db.session.add(application)
    # §11.2.4 事後の説明責任: registered.granted を記録 (発行者・jti・判定)
    audit.record('registered.granted',
                 subject={'dataset_id': dataset_id,
                          'application_id': application.application_id},
                 actor={'kind': 'agent', 'id': agent_id,
                        'on_behalf_of': researcher_sub},
                 payload={'visa_types': [v.get('type') for v in visas],
                          'visa_sources': [v.get('source') for v in visas],
                          'method': method, 'decision': 'granted',
                          'access_class': 'registered',
                          'credential_types': [presentation.rdc_type(
                              v.get('type')) for v in visas],
                          'purpose': pres_purpose or 'registered-access',
                          'intended_use': intended_use or {},
                          'presentation_absent': presentation_absent})
    db.session.commit()

    # 許諾発行 (§6) — controlled の承認分岐と同一手順を再利用
    services.transition(application, 'approved')
    issued = services.issue_grants(application)
    services.transition(application, 'agreement_issued')
    # visa.issued_at 等の Python 側デフォルト (default=_now) は flush 時に確定する。
    # deposit の body は issued_at/expires_at を参照するため、預け入れ前に flush して
    # おく (未 flush だと issued_at=None で strftime に失敗し同期預け入れが落ちる)。
    db.session.flush()
    for agreement, visa in issued:
        try:
            # 発行→即取得の台本のため、201 応答に wallet_credential_id を確実に
            # 載せる短時間リトライ (恒久失敗は invenio dac pump が後追い再送)。
            services.deposit_visa_to_wallet_retry(visa)
        except Exception:
            current_app.logger.exception(
                'weko-dac: wallet deposit error (registered) for %s', visa.jti)
        services.enqueue_event(application, 'agreement.issued', {
            'agreement_uid': agreement.uid,
            'dataset_id': agreement.dataset_id,
            'visa_jti': visa.jti,
            'wallet_credential_id': visa.wallet_credential_id,
            'wallet_deposited': visa.wallet_deposited,
            'access_route': 'registered',
        })
    services.transition(application, 'active')
    db.session.commit()
    services.flush_pending_events(application.application_id)
    return application, issued
