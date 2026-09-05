# -*- coding: utf-8 -*-
"""Configuration for weko-dac (RDC-AAP-01, Phase 1 demo profile).

All values can be overridden via instance config / environment.
Demo simplifications vs. the production spec (RDC-AAP-01/04) are marked
with ``[DEMO]`` and mirror docs/demo/10_demo_idp_keycloak_setup.md and
11_demo_grant_wallet_impl.md of the aifs spec set.
"""

import os

# --- Identity of this DAC / RAGS entity -----------------------------------

#: Entity ID of the publication platform (aud of Grant Presentations).
#: In the demo this is the WEKO server base URL (e.g. "http://203.0.113.20").
WEKO_DAC_ENTITY_ID = os.environ.get('WEKO_DAC_ENTITY_ID',
                                    'http://weko3.example.org')

#: DAC identifier (odrl:assigner of Offers/Agreements).
WEKO_DAC_DAC_ID = os.environ.get(
    'WEKO_DAC_DAC_ID', WEKO_DAC_ENTITY_ID + '/dacs/rdc-dac-001')

#: Expected ``aud`` of a Grant Presentation (§6.3). Per RFC 7519 §4.1.3 and
#: GA4GH AAI, ``aud`` identifies the RELYING PARTY that receives and verifies
#: the presentation — i.e. this DAC service's Entity ID (WEKO_DAC_ENTITY_ID).
#: Which DAC issued the grant is carried by the credential itself: the Visa
#: ``ga4gh_visa_v1.source`` and the Agreement ``odrl:assigner`` hold the DAC id
#: (§6.1/§6.2). Defaults to WEKO_DAC_ENTITY_ID; override only if a deployment
#: fronts the DAC under a different receiver identifier.
WEKO_DAC_PRESENTATION_AUD = os.environ.get(
    'WEKO_DAC_PRESENTATION_AUD', WEKO_DAC_ENTITY_ID)

#: ODRL profile URI (spec vol.05).
WEKO_DAC_ODRL_PROFILE = 'https://rdc.nii.ac.jp/ns/odrl-profile/v1'

#: Estimated review period returned on application intake (ISO 8601).
WEKO_DAC_ESTIMATED_REVIEW = 'P14D'

# --- OIDC verification (RDC-ATF Authorization Server) ---------------------
# [DEMO] Bearer JWT from Keycloak realm `rdc` verified via JWKS.
# Trust Chain resolution, Trust Mark status checks and DPoP proof
# verification are NOT performed (production items, RDC-AAP-01 §5.1).

#: Issuer of access tokens (e.g. "https://203.0.113.10/auth/realms/rdc").
WEKO_DAC_OIDC_ISSUER = os.environ.get('WEKO_DAC_OIDC_ISSUER', '')

#: JWKS URL. Default derives from the issuer (Keycloak layout). May be an
#: internal URL when the issuer is only reachable via a proxy.
WEKO_DAC_OIDC_JWKS_URL = os.environ.get('WEKO_DAC_OIDC_JWKS_URL', '')

#: Path to a CA bundle for TLS verification of IdP/Wallet endpoints
#: (self-signed demo certificate). Empty string disables verification
#: ([DEMO] only; never disable in production).
WEKO_DAC_TLS_CA_BUNDLE = os.environ.get('WEKO_DAC_TLS_CA_BUNDLE', '')

#: JWKS cache TTL in seconds (spec: <= 300).
WEKO_DAC_JWKS_CACHE_TTL = 300

#: Optional expected ``aud`` of access tokens (DEMO-21 §2). Empty
#: disables the aud check (Keycloak default tokens carry aud=account
#: unless an audience mapper is configured — align with DEMO-24 §2).
WEKO_DAC_OIDC_AUDIENCE = os.environ.get('WEKO_DAC_OIDC_AUDIENCE', '')

#: Path to the static allowlist JSON (DEMO-24 §3, distributed as
#: aifs docs/demo/config/allowlist.json). Demo substitute for Trust
#: Chain verification (DEMO-20 §4). Empty = accept all callers and
#: record 'allowlist: not_configured' in the verification snapshot.
WEKO_DAC_ALLOWLIST_PATH = os.environ.get('WEKO_DAC_ALLOWLIST_PATH', '')

#: Scope required for application endpoints.
WEKO_DAC_SCOPE_APPLY = 'rags:apply'
#: Scope required for the clearinghouse (access-token) endpoint.
WEKO_DAC_SCOPE_RETRIEVE = 'rags:retrieve'

#: [DEMO] When the token carries no ``act`` claim, the ``azp`` claim is
#: accepted as the requesting agent id if listed here (empty = accept any
#: azp as agent — matching the demo IdP's standard token exchange).
WEKO_DAC_AGENT_AZP_ALLOWLIST = []

# --- DAC service account (outbound calls: wallet deposit, callbacks) ------

#: Token endpoint of the demo IdP (client_credentials).
WEKO_DAC_TOKEN_URL = os.environ.get('WEKO_DAC_TOKEN_URL', '')
#: Client id/secret of this DAC service ([DEMO] client_secret allowed;
#: production uses private_key_jwt + DPoP).
WEKO_DAC_CLIENT_ID = os.environ.get('WEKO_DAC_CLIENT_ID', 'dac-service')
WEKO_DAC_CLIENT_SECRET = os.environ.get('WEKO_DAC_CLIENT_SECRET', '')

# --- Grant Wallet ---------------------------------------------------------

#: Base URL of the Grant Wallet API,
#: e.g. "https://203.0.113.10/wallet/api/wallet/v1".
WEKO_DAC_WALLET_API_BASE = os.environ.get('WEKO_DAC_WALLET_API_BASE', '')

#: JWKS URL of the wallet (verification of Grant Presentations),
#: e.g. "https://203.0.113.10/wallet/.well-known/jwks.json".
WEKO_DAC_WALLET_JWKS_URL = os.environ.get('WEKO_DAC_WALLET_JWKS_URL', '')

#: Accepted JWS ``typ`` values for presentations, mapped to a handler name.
#: Extensible per RDC-AAP-04 §8.3 (future: "vp+jwt", SD-JWT VC types).
WEKO_DAC_PRESENTATION_TYPES = {
    'rdc-gp+jwt': 'ga4gh_visa_presentation',
}

#: Max age of a presentation in seconds (spec vol.05 §11).
WEKO_DAC_PRESENTATION_MAX_AGE = 300

#: [DEMO] Accept direct Visa presentation ({"visa": "..."}) as the
#: transitional fallback of RDC-AAP-01 §6.3. Logged with
#: ``presentation_absent`` in the audit trail.
WEKO_DAC_ALLOW_DIRECT_VISA = True

# --- Signing keys ---------------------------------------------------------

#: Path to the ES256 private key (PEM, PKCS#8) used to sign Agreements,
#: Visas and the Entity Configuration. Created by ``invenio dac init``.
#: Default: <instance_path>/data/dac_es256.pem
WEKO_DAC_SIGNING_KEY_PATH = os.environ.get('WEKO_DAC_SIGNING_KEY_PATH', '')

#: Key id advertised in the JWKS.
WEKO_DAC_SIGNING_KID = 'dac-key-1'

# --- Data delivery --------------------------------------------------------

#: Lifetime (seconds) of issued download URLs.
WEKO_DAC_DOWNLOAD_URL_TTL = 300

# --- Review / assessment --------------------------------------------------

#: WEKO role names allowed to operate the officer console
#: (spec role ``dac_officer``; mapped to WEKO roles in the demo).
WEKO_DAC_OFFICER_ROLES = [
    'System Administrator', 'Repository Administrator', 'DAC Officer',
]

#: [DEMO] Relax application read/list scope (§5.4) so that the researcher
#: (token ``sub``) may always see their own application, regardless of
#: which delegated agent/portal presents the token. Default False keeps
#: the strict delegation-pair (sub + act.sub) check required by the spec.
WEKO_DAC_SCOPE_OWNER_SUB_ONLY = False

#: Maximum negotiation round trips before forced human escalation
#: (RDC-AAP-01 §5.5).
WEKO_DAC_MAX_NEGOTIATION_ROUNDS = 5

#: Directive-language patterns (prompt-injection detector, §7.5).
WEKO_DAC_INJECTION_PATTERNS = [
    r'承認\s*(せよ|しろ|してください)',
    r'許可\s*(せよ|しろ|してください)',
    r'(この申請|本申請)を(必ず|直ちに)?(承認|許可)',
    r'ignore\s+(all\s+)?(previous|prior)\s+instructions',
    r'you\s+must\s+approve',
    r'approve\s+this\s+(application|request)',
    r'system\s*prompt',
]

# --- Callbacks ------------------------------------------------------------

#: Retry schedule (seconds) for callback delivery. Spec: exponential
#: backoff up to 24h; the demo uses a shortened schedule.
WEKO_DAC_CALLBACK_RETRY_SCHEDULE = [60, 300, 1800, 7200, 21600, 43200, 86400]

# --- Audit ----------------------------------------------------------------

#: Base URL of the audit log service (RDC-AAP-04 §6). Empty = spool to
#: the local outbox table only ([DEMO], same as the wallet demo impl).
WEKO_DAC_AUDIT_API_BASE = os.environ.get('WEKO_DAC_AUDIT_API_BASE', '')

#: Local JSONL audit sink (DEMO-20 §4: 各サービスのローカル JSONL 追記).
#: Empty = <instance_path>/data/dac_audit.jsonl. Events use the common
#: schema of RDC-AAP-04 §6.1 and are written in addition to the DB
#: outbox. Set to '-' to disable the file sink.
WEKO_DAC_AUDIT_JSONL_PATH = os.environ.get('WEKO_DAC_AUDIT_JSONL_PATH', '')

#: Enforce evidence.passport verification at intake (policy (c) of the
#: DG inquiry: only demo-IdP-signed Visa/Passport JWTs are accepted;
#: failures reject the application with 400 invalid_passport). Set to
#: False to fall back to record-only verification.
WEKO_DAC_PASSPORT_ENFORCE = os.environ.get(
    'WEKO_DAC_PASSPORT_ENFORCE', 'true').lower() != 'false'
