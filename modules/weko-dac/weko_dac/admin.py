# -*- coding: utf-8 -*-
"""DAC officer console and Offer management (RDC-AAP-01 §4.1 / §7.3)."""

import hashlib
import json
import os

from flask import abort, current_app, flash, redirect, request, url_for
from flask_admin import BaseView, expose
from flask_babelex import gettext as _
from flask_login import current_user
from invenio_db import db

from . import services
from .assessment import generate_assessment
from .models import (DacApplication, DacAssessment, DacDecision,
                     DacMessage, DacOffer)
from .permissions import is_officer


class _OfficerView(BaseView):
    """Base view restricted to DAC officers."""

    def is_accessible(self):
        return is_officer()

    def inaccessible_callback(self, name, **kwargs):
        abort(403)


class DacApplicationView(_OfficerView):
    """Officer console: application list, assessment, decision (§7.3)."""

    @expose('/', methods=['GET'])
    def index(self):
        status = request.args.get('status', '')
        query = DacApplication.query
        if status:
            query = query.filter_by(status=status)
        applications = query.order_by(DacApplication.id.desc()).limit(
            200).all()
        # attach latest recommendation for the list view
        recos = {}
        for app_row in applications:
            a = DacAssessment.query.filter_by(
                application_id=app_row.application_id).order_by(
                DacAssessment.id.desc()).first()
            if a:
                recos[app_row.application_id] = (
                    a.assessment.get('recommendation') or {}).get(
                    'decision')
        return self.render('weko_dac/admin/applications.html',
                           applications=applications, recos=recos,
                           status=status)

    @expose('/<app_id>', methods=['GET'])
    def detail(self, app_id):
        application = DacApplication.query.filter_by(
            application_id=app_id).first()
        if application is None:
            abort(404)
        assessment_row = DacAssessment.query.filter_by(
            application_id=app_id).order_by(
            DacAssessment.id.desc()).first()
        if assessment_row is None:
            assessment_row = self._generate(application)
        messages = DacMessage.query.filter_by(
            application_id=app_id).order_by(DacMessage.id).all()
        decisions = DacDecision.query.filter_by(
            application_id=app_id).order_by(DacDecision.id).all()
        return self.render(
            'weko_dac/admin/application_detail.html',
            application=application,
            assessment=assessment_row,
            assessment_json=json.dumps(
                assessment_row.assessment, ensure_ascii=False, indent=2),
            payload_json=json.dumps(
                application.payload, ensure_ascii=False, indent=2),
            messages=messages,
            decisions=decisions)

    @staticmethod
    def _generate(application):
        row = DacAssessment(
            application_id=application.application_id,
            assessment=generate_assessment(application))
        db.session.add(row)
        from . import audit
        audit.record('assessment.generated',
                     subject={'application_id':
                              application.application_id},
                     actor={'kind': 'service', 'id': 'rdc-odrl-eval'})
        db.session.commit()
        return row

    @expose('/<app_id>/assessment/refresh', methods=['POST'])
    def refresh_assessment(self, app_id):
        """§7.2 assessment:refresh."""
        application = DacApplication.query.filter_by(
            application_id=app_id).first()
        if application is None:
            abort(404)
        self._generate(application)
        flash(_('Assessment regenerated.'))
        return redirect(url_for('.detail', app_id=app_id))

    @expose('/<app_id>/decision', methods=['POST'])
    def decision(self, app_id):
        """§7.3 decision endpoint (reason is mandatory)."""
        application = DacApplication.query.filter_by(
            application_id=app_id).first()
        if application is None:
            abort(404)
        decision = request.form.get('decision', '')
        reason = (request.form.get('reason') or '').strip()
        conditions = [c.strip() for c in
                      (request.form.get('conditions') or '').splitlines()
                      if c.strip()]
        if decision not in ('approve', 'approve_with_conditions',
                            'reject', 'request_info'):
            flash(_('Unknown decision.'), 'error')
            return redirect(url_for('.detail', app_id=app_id))
        if not reason:
            flash(_('A reason is required for every decision.'), 'error')
            return redirect(url_for('.detail', app_id=app_id))
        assessment_row = DacAssessment.query.filter_by(
            application_id=app_id).order_by(
            DacAssessment.id.desc()).first()
        officer = current_user.email or str(current_user.get_id())
        try:
            services.execute_decision(
                application, decision, reason, officer,
                conditions=conditions,
                inquiry_body=request.form.get('inquiry_body') or None,
                assessment_row=assessment_row)
        except ValueError as ex:
            db.session.rollback()
            flash(str(ex), 'error')
            return redirect(url_for('.detail', app_id=app_id))
        flash(_('Decision recorded: %(d)s', d=decision))
        return redirect(url_for('.detail', app_id=app_id))

    @expose('/<app_id>/revoke', methods=['POST'])
    def revoke(self, app_id):
        application = DacApplication.query.filter_by(
            application_id=app_id).first()
        if application is None:
            abort(404)
        reason = (request.form.get('reason') or '').strip()
        if not reason:
            flash(_('A reason is required.'), 'error')
            return redirect(url_for('.detail', app_id=app_id))
        officer = current_user.email or str(current_user.get_id())
        try:
            services.revoke_grant(application, reason, officer)
        except ValueError as ex:
            db.session.rollback()
            flash(str(ex), 'error')
            return redirect(url_for('.detail', app_id=app_id))
        flash(_('Grant revoked.'))
        return redirect(url_for('.detail', app_id=app_id))


class DacOfferView(_OfficerView):
    """ODRL Offer management via condition templates (§4.1)."""

    _DUTY_CHOICES = ['rdc:cite', 'rdc:reportCompletion', 'rdc:deleteData',
                     'rdc:registerOutcome']
    _PROHIBITION_CHOICES = ['distribute', 'derive', 'rdc:reIdentify']

    @expose('/', methods=['GET'])
    def index(self):
        offers = DacOffer.query.order_by(DacOffer.id.desc()).all()
        return self.render('weko_dac/admin/offers.html', offers=offers)

    @expose('/new', methods=['GET', 'POST'])
    @expose('/<int:offer_id>/edit', methods=['GET', 'POST'])
    def edit(self, offer_id=None):
        row = DacOffer.query.get(offer_id) if offer_id else None
        if request.method == 'POST':
            dataset_id = (request.form.get('dataset_id') or '').strip()
            if not dataset_id:
                flash(_('dataset_id is required.'), 'error')
                return redirect(request.url)
            template = {
                'access_class':
                    request.form.get('access_class', 'controlled'),
                'duo_codes': [c.strip() for c in
                              (request.form.get('duo_codes') or ''
                               ).split(',') if c.strip()],
                'period': (request.form.get('period') or '').strip(),
                'storage_class':
                    (request.form.get('storage_class') or '').strip(),
                'ethics_required':
                    bool(request.form.get('ethics_required')),
                'duties': request.form.getlist('duties'),
                'prohibitions': request.form.getlist('prohibitions'),
                'spatial': (request.form.get('spatial') or '').strip(),
            }
            offer = services.offer_from_template(dataset_id, template)
            distribution_uri = (request.form.get('distribution_uri')
                                or '').strip()
            checksum = None
            if distribution_uri and os.path.isfile(distribution_uri):
                h = hashlib.sha256()
                with open(distribution_uri, 'rb') as fp:
                    for chunk in iter(lambda: fp.read(65536), b''):
                        h.update(chunk)
                checksum = h.hexdigest()
            if row is None:
                row = DacOffer(dataset_id=dataset_id, offer=offer)
                db.session.add(row)
            row.dataset_id = dataset_id
            row.title = (request.form.get('title') or '').strip() or None
            row.access_class = template['access_class']
            row.offer = offer
            row.template = template
            row.distribution_uri = distribution_uri or None
            row.checksum = checksum
            db.session.commit()
            flash(_('Offer saved.'))
            return redirect(url_for('.index'))
        return self.render('weko_dac/admin/offer_edit.html', offer=row,
                           duty_choices=self._DUTY_CHOICES,
                           prohibition_choices=self._PROHIBITION_CHOICES)


dac_application_adminview = {
    'view_class': DacApplicationView,
    'kwargs': {
        'category': _('DAC'),
        'name': _('Applications'),
        'endpoint': 'dac/applications',
    },
}

dac_offer_adminview = {
    'view_class': DacOfferView,
    'kwargs': {
        'category': _('DAC'),
        'name': _('Dataset Policies (ODRL Offer)'),
        'endpoint': 'dac/offers',
    },
}
