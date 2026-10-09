#!/bin/bash

set -xe
# weko-dac is installed into the container-layer venv and is lost
# when the container is recreated — ensure it at every start.
pip show weko-dac >/dev/null 2>&1 || pip install -e /code/modules/weko-dac
# invenio.cfg を入れ物ごとに作る(2026-10-09)。以前は web と worker が共有の conf/invenio.cfg に同時に
# `>` で書いていた。mdx のスポットの停止の後に全部が同時に起動し(15 ms 差)、長さの違う 2 つの書き込みが
# 重なって末尾 19 バイトの切れ端が残り、web も worker も SyntaxError で起動できなかった。
# 読むのは var/instance/invenio.cfg(共有の conf/ への symlink)なので、それを入れ物の中の実体に置き換える。
# 共有の conf/invenio.cfg も、一時ファイルに書いて mv で置き換える(途中の状態を誰にも読ませない)。
I=/home/invenio/.virtualenvs/invenio/var/instance
jinja2 /code/scripts/instance.cfg > "$I/invenio.cfg.$$.tmp"
python -c "import sys; compile(open(sys.argv[1]).read(), 'invenio.cfg', 'exec')" "$I/invenio.cfg.$$.tmp"
rm -f "$I/invenio.cfg" && mv -f "$I/invenio.cfg.$$.tmp" "$I/invenio.cfg"
cp "$I/invenio.cfg" "$I/conf/invenio.cfg.worker.$$.tmp" && mv -f "$I/conf/invenio.cfg.worker.$$.tmp" "$I/conf/invenio.cfg"
/usr/bin/supervisord -c /code/scripts/supervisord_worker.conf