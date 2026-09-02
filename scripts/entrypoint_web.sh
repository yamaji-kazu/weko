#!/bin/bash

set -xe
# weko-dac is installed into the container-layer venv and is lost
# when the container is recreated — ensure it at every start.
pip show weko-dac >/dev/null 2>&1 || pip install -e /code/modules/weko-dac
jinja2 /code/scripts/instance.cfg > /home/invenio/.virtualenvs/invenio/var/instance/conf/invenio.cfg
/usr/bin/supervisord -c /code/scripts/supervisord_web.conf