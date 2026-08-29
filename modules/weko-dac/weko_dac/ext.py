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
        app.extensions['weko-dac'] = self

    @staticmethod
    def init_config(app):
        """Initialize configuration defaults."""
        for k in dir(config):
            if k.startswith('WEKO_DAC_'):
                app.config.setdefault(k, getattr(config, k))
