# -*- coding: utf-8 -*-
"""Signing utilities: DAC ES256 key, Visa JWTs, Agreement JWS, JWKS.

The Visa issuance is abstracted as an *issuer* so a future VC issuer
(SD-JWT VC / JOSE) can be dual-run next to the GA4GH Visa issuer
(forward-compat requirement, RDC-AAP-04 §8.3 "DAC" row).
"""

import base64
import json
import os
import time

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import current_app

from .utils import new_id


def _key_path():
    path = current_app.config.get('WEKO_DAC_SIGNING_KEY_PATH') or ''
    if not path:
        path = os.path.join(current_app.instance_path, 'data',
                            'dac_es256.pem')
    return path


def generate_key(path=None):
    """Generate an ES256 (P-256) private key at ``path`` if missing."""
    path = path or _key_path()
    if os.path.exists(path):
        return path
    dirname = os.path.dirname(path)
    if dirname and not os.path.isdir(dirname):
        os.makedirs(dirname)
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    with open(path, 'wb') as fp:
        fp.write(pem)
    os.chmod(path, 0o600)
    return path


def load_private_key_pem():
    """Return the PEM bytes of the DAC signing key."""
    path = _key_path()
    if not os.path.exists(path):
        raise RuntimeError(
            'DAC signing key not found at %s — run "invenio dac init"'
            % path)
    with open(path, 'rb') as fp:
        return fp.read()


def _load_private_key():
    return serialization.load_pem_private_key(
        load_private_key_pem(), password=None, backend=default_backend())


def _b64url_uint(value, size):
    return base64.urlsafe_b64encode(
        value.to_bytes(size, 'big')).rstrip(b'=').decode('ascii')


def public_jwks():
    """JWKS document for Visa / Agreement verification (§6.2)."""
    pub = _load_private_key().public_key().public_numbers()
    return {'keys': [{
        'kty': 'EC', 'crv': 'P-256', 'use': 'sig', 'alg': 'ES256',
        'kid': current_app.config['WEKO_DAC_SIGNING_KID'],
        'x': _b64url_uint(pub.x, 32),
        'y': _b64url_uint(pub.y, 32),
    }]}


def _sign(payload, typ=None, headers=None):
    hdrs = {'kid': current_app.config['WEKO_DAC_SIGNING_KID']}
    if typ:
        hdrs['typ'] = typ
    if headers:
        hdrs.update(headers)
    token = jwt.encode(payload, load_private_key_pem(),
                       algorithm='ES256', headers=hdrs)
    if isinstance(token, bytes):
        token = token.decode('ascii')
    return token


def issue_visa(subject, dataset_id, agreement_uid, valid_until_ts):
    """Issue a GA4GH ControlledAccessGrants Visa JWT (§6.2).

    Returns (jti, visa_jwt).
    """
    now = int(time.time())
    jti = new_id('visa')
    payload = {
        'iss': current_app.config['WEKO_DAC_ENTITY_ID'],
        'sub': subject,
        'iat': now,
        'exp': int(valid_until_ts),
        'jti': jti,
        'ga4gh_visa_v1': {
            'type': 'ControlledAccessGrants',
            'asserted': now,
            'value': dataset_id,
            'source': current_app.config['WEKO_DAC_DAC_ID'],
            'by': 'dac',
        },
        'rdc_agreement': agreement_uid,
    }
    return jti, _sign(payload, typ='vnd.ga4gh.visa+jwt')


def sign_agreement(agreement_jsonld):
    """Sign an ODRL Agreement JSON-LD as a compact JWS (§6.1)."""
    return _sign(agreement_jsonld)


def sign_download_token(dataset_id, subject, agreement_uid):
    """Short-lived token embedded in the signed download URL (§6.3)."""
    ttl = current_app.config.get('WEKO_DAC_DOWNLOAD_URL_TTL', 300)
    now = int(time.time())
    payload = {
        'iss': current_app.config['WEKO_DAC_ENTITY_ID'],
        'sub': subject,
        'aud': 'dac-download',
        'iat': now, 'exp': now + ttl,
        'jti': new_id('dl'),
        'dataset': dataset_id,
        'agreement': agreement_uid,
    }
    return _sign(payload, typ='rdc-dl+jwt')


def verify_download_token(token):
    """Verify a download token with our own key. Returns payload."""
    pub = _load_private_key().public_key()
    return jwt.decode(token, pub, algorithms=['ES256'],
                      audience='dac-download')


def entity_configuration():
    """Self-signed OpenID Federation Entity Configuration (§3).

    [DEMO] Self-signed only; there is no Trust Anchor yet, so no
    ``authority_hints`` / Trust Marks are included.
    """
    entity_id = current_app.config['WEKO_DAC_ENTITY_ID']
    now = int(time.time())
    payload = {
        'iss': entity_id,
        'sub': entity_id,
        'iat': now,
        'exp': now + 86400,
        'jwks': public_jwks(),
        'metadata': {
            'rdc_rags': {
                'resource_types': ['dataset'],
                'application_endpoint':
                    entity_id + '/api/dac/v1/applications',
                'policy_endpoint_template':
                    entity_id + '/api/dac/v1/datasets/{id}/policy',
                'visa_jwks_uri':
                    entity_id + '/api/dac/v1/visa-jwks.json',
                'odrl_profile': current_app.config['WEKO_DAC_ODRL_PROFILE'],
                'dac_id': current_app.config['WEKO_DAC_DAC_ID'],
            },
        },
    }
    return _sign(payload, typ='entity-statement+jwt')
