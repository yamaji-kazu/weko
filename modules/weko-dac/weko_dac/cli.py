# -*- coding: utf-8 -*-
"""CLI commands: ``invenio dac ...``."""

import click
from flask.cli import with_appcontext
from invenio_db import db


@click.group()
def dac():
    """DAC (RDC-AAP) management commands."""


@dac.command('init')
@with_appcontext
def init():
    """Create weko-dac tables and the ES256 signing key."""
    from . import models, signing
    tables = [
        models.DacOffer.__table__, models.DacApplication.__table__,
        models.DacMessage.__table__, models.DacAssessment.__table__,
        models.DacDecision.__table__, models.DacAgreement.__table__,
        models.DacVisa.__table__, models.DacPresentationJti.__table__,
        models.DacEventOutbox.__table__, models.DacAuditOutbox.__table__,
    ]
    db.metadata.create_all(bind=db.engine, tables=tables, checkfirst=True)
    click.secho('Tables created (checkfirst).', fg='green')
    path = signing.generate_key()
    click.secho('Signing key: %s' % path, fg='green')


@dac.command('pump')
@with_appcontext
def pump():
    """Run pending outbound work once (callbacks, wallet, expiry)."""
    from .tasks import expire_grants, pump_events, retry_wallet_deposits
    click.echo('events delivered: %s' % pump_events.apply().result)
    click.echo('wallet deposits: %s' % retry_wallet_deposits.apply().result)
    expire_grants.apply()
    click.echo('expiry sweep done')


@dac.command('demo-offer')
@click.argument('dataset_id')
@click.option('--duo', default='DUO:0000042', help='comma-separated codes')
@click.option('--period', default='P2Y')
@click.option('--access-class', default='controlled')
@click.option('--file', 'file_path', default=None,
              help='path/URL of the restricted data')
@click.option('--checksum', 'checksum_opt', default=None,
              help='sha256 hex; auto-computed from a local --file when omitted')
@with_appcontext
def demo_offer(dataset_id, duo, period, access_class, file_path, checksum_opt):
    """Register a demo ODRL Offer for DATASET_ID."""
    from .models import DacOffer
    from .services import offer_from_template
    template = {
        'access_class': access_class,
        'duo_codes': [c.strip() for c in duo.split(',') if c.strip()],
        'period': period,
        'storage_class': 'rdc:certified-storage',
        'ethics_required': False,
        'duties': ['rdc:cite', 'rdc:reportCompletion', 'rdc:deleteData'],
        'prohibitions': ['distribute', 'rdc:reIdentify'],
    }
    offer = offer_from_template(dataset_id, template)
    row = DacOffer.query.filter_by(dataset_id=dataset_id).first()
    if row is None:
        row = DacOffer(dataset_id=dataset_id, offer=offer)
        db.session.add(row)
    row.access_class = access_class
    row.offer = offer
    row.template = template
    row.distribution_uri = file_path
    # sha256 for the access-token response checksum (分冊01 §6.3)
    checksum = checksum_opt
    if not checksum and file_path \
            and not file_path.startswith(('http://', 'https://')):
        import hashlib
        import os
        if os.path.isfile(file_path):
            h = hashlib.sha256()
            with open(file_path, 'rb') as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b''):
                    h.update(chunk)
            checksum = h.hexdigest()
    if checksum:
        row.checksum = checksum
    db.session.commit()
    click.secho('Offer registered for %s%s' % (
        dataset_id, ' (checksum set)' if checksum else ''), fg='green')
