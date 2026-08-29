# -*- coding: utf-8 -*-
"""Officer permission helper (spec role ``dac_officer``).

[DEMO] Officers authenticate to WEKO itself (GakuNin/Shibboleth or
local login); authorization maps the spec role to WEKO role names in
``WEKO_DAC_OFFICER_ROLES``.
"""

from flask import current_app
from flask_login import current_user


def is_officer():
    """True when the current WEKO user may operate the DAC console."""
    if not current_user or not current_user.is_authenticated:
        return False
    allowed = set(current_app.config.get('WEKO_DAC_OFFICER_ROLES') or [])
    try:
        user_roles = {r.name for r in current_user.roles}
    except Exception:
        return False
    return bool(allowed & user_roles)
