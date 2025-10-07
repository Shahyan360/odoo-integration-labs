import hashlib
import hmac
import secrets
import time
from odoo import http
from odoo.http import request
from odoo.exceptions import AccessError, UserError, ValidationError

class Connectors(http.Controller):
    @http.route('/lab/connectors/oauth/start/<int:connection_id>',type='http',auth='user',methods=['GET'])
    def oauth_start(self,connection_id,**params):
        c=request.env['ic.connection'].browse(connection_id).exists()
        if not c: return request.not_found()
        c._external()
        state=secrets.token_urlsafe(32); verifier=secrets.token_urlsafe(48)
        request.session['ic_oauth']={'state_hash':hashlib.sha256(state.encode()).hexdigest(),'connection':c.id,'uid':request.env.uid,'expires':time.time()+600,'verifier':verifier}
        return request.redirect(c._oauth_url(state,verifier),local=False)

    @http.route('/lab/connectors/oauth/callback',type='http',auth='user',methods=['GET'])
    def oauth_callback(self,state=None,code=None,realmId=None,error=None,**params):
        pending=request.session.pop('ic_oauth',None)
        if not pending or pending['uid']!=request.env.uid or pending['expires']<time.time() or not hmac.compare_digest(pending['state_hash'],hashlib.sha256((state or '').encode()).hexdigest()):
            return request.make_response('OAuth state expired or mismatched.',status=403)
        if error or not code: return request.make_response('Developer account consent was not completed.',status=400)
        c=request.env['ic.connection'].browse(pending['connection']).exists()
        if not c: return request.not_found()
        try:
            with request.env.cr.savepoint(): c._exchange(code,pending['verifier'],realm=realmId)
        except (UserError,ValidationError,AccessError):
            return request.make_response('OAuth exchange failed. Check the configured sandbox and private environment values.',status=400)
        return request.redirect('/web#model=ic.connection&id=%s&view_type=form'%c.id)

    @http.route('/lab/connectors/stripe/<string:code>',type='http',auth='public',methods=['POST'],csrf=False,save_session=False)
    def stripe_event(self,code,**params):
        raw=request.httprequest.get_data(cache=False)
        if len(raw)>1_000_000: return request.make_response('Event too large.',status=413)
        # Sole sudo lookup: connection code and service identity; mapping/payment actions use that identity.
        c=request.env['ic.connection'].sudo().search([('code','=',code),('provider','=','stripe'),('active','=',True)],limit=1)
        if not c: return request.not_found()
        service=c.service_user_id; company=c.company_id
        if not service.active or company not in service.company_ids: return request.make_response('Service identity unavailable.',status=503)
        c=request.env['ic.connection'].with_user(service).with_company(company).with_context(allowed_company_ids=[company.id]).browse(c.id)
        try:
            with request.env.cr.savepoint(): c._stripe_receive(raw,request.httprequest.headers.get('Stripe-Signature'))
        except AccessError: return request.make_response('Invalid signature.',status=401)
        except (ValidationError,UserError): return request.make_response('Event rejected; internal review required.',status=400)
        return request.make_response('Queued for internal processing.',status=202)
