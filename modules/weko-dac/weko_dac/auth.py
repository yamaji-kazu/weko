# -*- coding: utf-8 -*-
"""Access-token verification for RDC-AAP endpoints (demo profile).

[DEMO] Bearer JWTs issued by the RDC-ATF Authorization Server (Keycloak
realm ``rdc``, DEMO-10) are verified against its JWKS: signature,
``iss`` and ``exp``. The production-only steps of RDC-AAP-01 §5.1 —
OpenID Federation Trust Chain resolution, Trust Mark status checks and
DPoP proof verification — are intentionally NOT implemented here and
must be added when the RDC-ATF Trust Anchor exists (see README).

Delegation: the spec requires ``act.sub`` (agent) on top of ``sub``
(researcher). The demo IdP produces delegation via standard token
exchange, where the agent appears as ``azp``; this module abstracts the
difference behind :func:`resolve_delegation` (RDC-AAP-04 §8.3(b)).
"""

import base64
import json
import time
from functools import wraps

import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from flask import current_app, g, jsonify, request

_JWKS_CACHE = {'url': None, 'keys': None, 'fetched_at': 0}


class AuthError(Exception):
    """Authentication / authorization failure (RFC 7807 style)."""

    def __init__(self, status, title, detail=''):
        super(AuthError, self).__init__(detail or title)
        self.status = status
        self.title = title
        self.detail = detail

    def as_response(self):
        """Problem Details response."""
        resp = jsonify({
            'type': 'about:blank', 'title': self.title,
            'status': self.status, 'detail': self.detail})
        resp.status_code = self.status
        return resp


def _b64url_decode(data):
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64url_to_int(data):
    return int.from_bytes(_b64url_decode(data), 'big')


def jwk_to_public_key(jwk):
    """Build a cryptography public key object from a JWK dict."""
    kty = jwk.get('kty')
    if kty == 'RSA':
        numbers = rsa.RSAPublicNumbers(
            _b64url_to_int(jwk['e']), _b64url_to_int(jwk['n']))
        return numbers.public_key(default_backend())
    if kty == 'EC':
        curves = {'P-256': ec.SECP256R1(), 'P-384': ec.SECP384R1(),
                  'P-521': ec.SECP521R1()}
        curve = curves.get(jwk.get('crv'))
        if curve is None:
            raise AuthError(401, 'unsupported_key',
                            'Unsupported EC curve: %s' % jwk.get('crv'))
        numbers = ec.EllipticCurvePublicNumbers(
            _b64url_to_int(jwk['x']), _b64url_to_int(jwk['y']), curve)
        return numbers.public_key(default_backend())
    raise AuthError(401, 'unsupported_key', 'Unsupported kty: %s' % kty)


def _requests_verify():
    ca = current_app.config.get('WEKO_DAC_TLS_CA_BUNDLE') or ''
    if ca:
        return ca
    # [DEMO] with a self-signed IdP certificate and no bundle configured,
    # TLS verification is disabled. Configure WEKO_DAC_TLS_CA_BUNDLE.
    return False


def fetch_jwks(url, force=False):
    """Fetch (and cache) a JWKS document."""
    ttl = current_app.config.get('WEKO_DAC_JWKS_CACHE_TTL', 300)
    now = time.time()
    if (not force and _JWKS_CACHE['url'] == url and _JWKS_CACHE['keys']
            and now - _JWKS_CACHE['fetched_at'] < ttl):
        return _JWKS_CACHE['keys']
    resp = requests.get(url, timeout=10, verify=_requests_verify())
    resp.raise_for_status()
    keys = resp.json().get('keys', [])
    _JWKS_CACHE.update(url=url, keys=keys, fetched_at=now)
    return keys


def _find_key(keys, kid, alg=None):
    for k in keys:
        if kid and k.get('kid') == kid:
            return k
    # No kid match: fall back to the first signature key of a fitting kty.
    for k in keys:
        if k.get('use', 'sig') == 'sig':
            if not alg or not k.get('alg') or k.get('alg') == alg:
                return k
    return None


def verify_jws(token, jwks_url, issuer=None, audience=None):
    """Verify a JWS/JWT against a JWKS. Returns the payload dict."""
    try:
        header = jwt.get_unverified_header(token)
    except Exception as ex:
        raise AuthError(401, 'invalid_token', 'Malformed JWT: %s' % ex)
    keys = fetch_jwks(jwks_url)
    key = _find_key(keys, header.get('kid'), header.get('alg'))
    if key is None:
        # key rotation: force refresh once
        keys = fetch_jwks(jwks_url, force=True)
        key = _find_key(keys, header.get('kid'), header.get('alg'))
    if key is None:
        raise AuthError(401, 'invalid_token', 'No matching JWK')
    public_key = jwk_to_public_key(key)
    options = {'verify_aud': audience is not None}
    try:
        payload = jwt.decode(
            token, public_key,
            algorithms=['RS256', 'ES256', 'ES384', 'PS256'],
            audience=audience, issuer=issuer, options=options)
    except jwt.ExpiredSignatureError:
        raise AuthError(401, 'token_expired', 'Token has expired')
    except Exception as ex:
        raise AuthError(401, 'invalid_token', 'JWT verification failed: %s'
                        % ex)
    return payload


def _bearer_token():
    header = request.headers.get('Authorization', '')
    for scheme in ('DPoP ', 'Bearer '):
        if header.startswith(scheme):
            return header[len(scheme):].strip()
    raise AuthError(401, 'missing_token',
                    'Authorization header with Bearer/DPoP token required')


def resolve_delegation(payload):
    """Return (researcher_sub, agent_id) from a verified token payload.

    Abstracted delegation verifier (RDC-AAP-04 §8.3(b)):
    - production tokens: ``act.sub`` (RFC 8693 delegation chain)
    - [DEMO] token-exchange tokens: fall back to ``azp``.
    """
    sub = payload.get('sub')
    act = payload.get('act') or {}
    agent = act.get('sub')
    if not agent:
        azp = payload.get('azp')
        allow = current_app.config.get('WEKO_DAC_AGENT_AZP_ALLOWLIST') or []
        if azp and (not allow or azp in allow):
            agent = azp
    return sub, agent


def _has_scope(payload, required):
    scopes = (payload.get('scope') or '').split()
    return required in scopes


def require_rags_token(scope=None, require_agent=True):
    """Decorator: verify the access token and stash claims on ``g``."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                token = _bearer_token()
                issuer = current_app.config.get('WEKO_DAC_OIDC_ISSUER') or None
                jwks = current_app.config.get('WEKO_DAC_OIDC_JWKS_URL')
                if not jwks and issuer:
                    jwks = issuer.rstrip('/') + \
                        '/protocol/openid-connect/certs'
                if not jwks:
                    raise AuthError(500, 'server_misconfigured',
                                    'WEKO_DAC_OIDC_ISSUER/JWKS_URL not set')
                payload = verify_jws(token, jwks, issuer=issuer)
                if scope and not _has_scope(payload, scope):
                    raise AuthError(403, 'insufficient_scope',
                                    'Scope "%s" required' % scope)
                sub, agent = resolve_delegation(payload)
                if not sub:
                    raise AuthError(401, 'invalid_token', 'sub claim missing')
                if require_agent and not agent:
                    # Spec §5.1: agent-less direct applications are refused.
                    raise AuthError(
                        403, 'delegation_required',
                        'act.sub (delegated agent) is required')
                g.dac_token = payload
                g.dac_sub = sub
                g.dac_agent = agent
                g.dac_token_jti = payload.get('jti')
            except AuthError as err:
                return err.as_response()
            return fn(*args, **kwargs)
        return wrapper
    return decorator
