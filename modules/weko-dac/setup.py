# -*- coding: utf-8 -*-
#
# This file is part of WEKO3.
# Copyright (C) 2026 National Institute of Informatics.
#
# WEKO3 is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.

"""DAC (Data Access Committee) function for the NII RDC publication platform.

Implements RDC-AAP-01 (Phase 1, demo profile): ODRL Offer policy
management, application intake API (RDC-AAP server), rule-based
assessment engine, DAC officer console, and grant issuance
(ODRL Agreement + GA4GH ControlledAccessGrants Visa + Grant Wallet
deposit + clearinghouse data delivery).
"""

import os

from setuptools import find_packages, setup

readme = open('README.rst').read()

packages = find_packages()

# Get the version string. Cannot be done with import!
g = {}
with open(os.path.join('weko_dac', 'version.py'), 'rt') as fp:
    exec(fp.read(), g)
    version = g['__version__']

setup(
    name='weko-dac',
    version=version,
    description=__doc__,
    long_description=readme,
    keywords='weko dac odrl ga4gh rdc-aap',
    license='GPLv2',
    author='National Institute of Informatics',
    author_email='wekosoftware@nii.ac.jp',
    url='https://github.com/yamaji-kazu/weko',
    packages=packages,
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    entry_points={
        'invenio_base.apps': [
            'weko_dac = weko_dac:WekoDAC',
        ],
        'invenio_base.api_apps': [
            'weko_dac = weko_dac:WekoDAC',
        ],
        'invenio_base.blueprints': [
            'weko_dac_wellknown = weko_dac.views:blueprint_wellknown',
        ],
        'invenio_base.api_blueprints': [
            'weko_dac_api = weko_dac.views:blueprint_api',
        ],
        'invenio_admin.views': [
            'weko_dac_applications = weko_dac.admin:dac_application_adminview',
            'weko_dac_offers = weko_dac.admin:dac_offer_adminview',
        ],
        'invenio_db.models': [
            'weko_dac = weko_dac.models',
        ],
        'invenio_celery.tasks': [
            'weko_dac = weko_dac.tasks',
        ],
        'flask.commands': [
            'dac = weko_dac.cli:dac',
        ],
    },
    install_requires=[],  # all runtime deps ship with the WEKO stack
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Programming Language :: Python :: 3.6',
        'Development Status :: 3 - Alpha',
    ],
)
