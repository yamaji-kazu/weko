# -*- coding: utf-8 -*-
"""Flask extension for weko-dac."""

from . import config


class WekoDAC(object):
    """weko-dac extension."""

    def __init__(self, app=None):
        """Extension initialization."""
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Flask application initialization."""
        self.init_config(app)
        self.register_admin_access(app)
        app.extensions['weko-dac'] = self

    @staticmethod
    def init_config(app):
        """Initialize configuration defaults."""
        for k in dir(config):
            if k.startswith('WEKO_DAC_'):
                app.config.setdefault(k, getattr(config, k))

    @staticmethod
    def register_admin_access(app):
        """Grant DAC admin endpoints to officer roles.

        weko-admin gates every admin view through
        ``WEKO_ADMIN_ACCESS_TABLE`` (role name -> list of viewable
        endpoints); a view's own ``is_accessible`` is overwritten at
        request time, so the DAC endpoints must be registered here for
        non-System-Administrator officers to reach the console.
        """
        table = app.config.get('WEKO_ADMIN_ACCESS_TABLE')
        if table is None:
            # weko-admin not present / not configured yet.
            return
        endpoints = app.config.get(
            'WEKO_DAC_ADMIN_ENDPOINTS', ['admin', 'dac/applications', 'dac/offers'])
        system_admin = app.config.get(
            'WEKO_ADMIN_PERMISSION_ROLE_SYSTEM', 'System Administrator')
        for role in app.config.get('WEKO_DAC_OFFICER_ROLES', []):
            if role == system_admin:
                continue  # System Administrator bypasses the table.
            access_list = table.get(role)
            if access_list is None:
                access_list = []
                table[role] = access_list
            for endpoint in endpoints:
                if endpoint not in access_list:
                    access_list.append(endpoint)
