# -*- coding: utf-8 -*-
"""Small shared helpers for weko-dac."""

import uuid


def new_id(prefix):
    """Generate a prefixed random identifier."""
    return '{0}-{1}'.format(prefix, uuid.uuid4().hex[:20])
