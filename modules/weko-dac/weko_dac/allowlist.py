# -*- coding: utf-8 -*-
"""Static allowlist — demo substitute for Trust Chain verification.

Implements the DEMO-24 §3 distribution format (DEMO-20 §4 deviation
list: "静的 allowlist"):

.. code-block:: json

    {
      "trust_anchor": "demo-static-v1",
      "entities": [
        {"entity_id": "…", "role": "agent:requester", "jwks_uri": "…"},
        {"entity_id": "…", "role": "agent:dac",       "jwks_uri": "…"},
        {"entity_id": "…", "role": "wallet",          "jwks_uri": "…"}
      ]
    }

An inline ``"jwks": {"keys": [...]}`` per entity is also accepted
(useful for tests / offline distribution). When no allowlist file is
configured (``WEKO_DAC_ALLOWLIST_PATH`` empty), verification degrades
to the pre-demo behaviour: callers are accepted and the fact is
recorded as ``allowlist: not_configured`` in the verification snapshot.
Once RDC-ATF (spec vol.04) exists this module is replaced by real
Trust Chain resolution.
"""

import json
import os

from flask import current_app

_CACHE = {'path': None, 'mtime': None, 'data': None}


def _load():
    """Load (and cache by mtime) the allowlist file. None if not set."""
    path = current_app.config.get('WEKO_DAC_ALLOWLIST_PATH') or ''
    if not path:
        return None
    try:
        mtime = os.path.getmtime(path)
        if _CACHE['path'] == path and _CACHE['mtime'] == mtime:
            return _CACHE['data']
        with open(path) as fp:
            data = json.load(fp)
        _CACHE.update(path=path, mtime=mtime, data=data)
        return data
    except Exception:
        current_app.logger.exception(
            'weko-dac: failed to load allowlist %s', path)
        return None


def configured():
    """True when an allowlist file is configured and loadable."""
    return _load() is not None


def get_entity(entity_id):
    """Return the allowlist entry for entity_id (exact match) or None."""
    data = _load()
    if not data:
        return None
    for e in data.get('entities', []):
        if e.get('entity_id') == entity_id:
            return e
    return None


def first_by_role(role):
    """Return the first entity with the given role, or None."""
    data = _load()
    if not data:
        return None
    for e in data.get('entities', []):
        if e.get('role') == role:
            return e
    return None


def check_agent(agent_id):
    """Verify a requesting agent against the allowlist.

    Returns a verification result string:
    ``allowed`` / ``denied`` / ``not_configured``.
    Agents match by exact entity_id; role must be ``agent:requester``.
    A bare Keycloak client id (e.g. ``dar-agent``) matches an entry
    whose entity_id ends with ``/<client_id>`` or equals it, since the
    demo tokens carry the client id rather than a full Entity ID
    (DEMO-24 §2).
    """
    data = _load()
    if data is None:
        return 'not_configured'
    for e in data.get('entities', []):
        if e.get('role') != 'agent:requester':
            continue
        eid = e.get('entity_id') or ''
        if eid == agent_id or eid.rstrip('/').endswith('/' + agent_id):
            return 'allowed'
    return 'denied'


def wallet_entity():
    """The wallet entry (role ``wallet``) or None."""
    return first_by_role('wallet')


def wallet_jwks_url():
    """jwks_uri of the allowlisted wallet, falling back to config."""
    entity = wallet_entity()
    if entity and entity.get('jwks_uri'):
        return entity['jwks_uri']
    return current_app.config.get('WEKO_DAC_WALLET_JWKS_URL')


def wallet_inline_jwks():
    """Inline jwks of the allowlisted wallet, if distributed inline."""
    entity = wallet_entity()
    if entity and isinstance(entity.get('jwks'), dict):
        return entity['jwks'].get('keys', [])
    return None


def visa_issuer_entity():
    """The Visa issuer entry (role ``visa_issuer``) or None.

    Used for evidence.passport verification: the Visa's ``iss`` must
    equal this entity_id and its signature must verify with the
    entity's inline ``jwks`` (or ``jwks_uri``)."""
    return first_by_role('visa_issuer')


def entity_inline_jwks(entity):
    """Inline JWK list of an allowlist entity, or None."""
    if entity and isinstance(entity.get('jwks'), dict):
        return entity['jwks'].get('keys') or None
    return None
