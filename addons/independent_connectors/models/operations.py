import base64
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from datetime import timedelta
from urllib.parse import urlencode, urlsplit
import requests
from cryptography.fernet import Fernet, InvalidToken
from odoo import api, fields, models
from odoo.exceptions import AccessError, UserError, ValidationError
from ..common import guard, decimal

MANAGER='independent_connectors.group_manager'
PROVIDERS=[('outlook','Outlook Contacts'),('zoho','Zoho CRM (US)'),('quickbooks','QuickBooks Sandbox Customers'),('stripe','Stripe Test Payments')]

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def secret(name):
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{2,80}',name or ''):
        raise ValidationError('Configure an uppercase environment variable name.')
    value=os.environ.get(name)
    if not value: raise ValidationError('Required private environment value is missing: '+name)
    return value

def call(method,url,**kwargs):
    # Endpoints originate in provider-specific methods, never in an inbound payload.
    try:
        with requests.request(method,url,timeout=(10,40),allow_redirects=False,stream=True,**kwargs) as response:
            chunks=[]; length=0
            for chunk in response.iter_content(65536):
                length+=len(chunk)
                if length>2_000_000: raise ValidationError('Provider response exceeds the laboratory limit.')
                chunks.append(chunk)
            if response.status_code<200 or response.status_code>=300:
                raise ValidationError('Provider HTTP %s; inspect the provider console without exposing tokens.'%response.status_code)
            raw=b''.join(chunks)
            return json.loads(raw) if raw else {}
    except (requests.RequestException,ValueError):
        raise ValidationError('Provider transport or JSON response failed; request credentials were not logged.')

class Connection(models.Model):
    _name='ic.connection'
    _description='Independent Demonstration Connection'
    _check_company_auto=True
    name=fields.Char(required=True)
    code=fields.Char(required=True,index=True)
    active=fields.Boolean(default=True)
    company_id=fields.Many2one('res.company',required=True,default=lambda s:s.env.company)
    provider=fields.Selection(PROVIDERS,required=True)
    mode=fields.Selection([('simulator','Local Simulator'),('sandbox','Authorized Developer Account')],required=True,default='simulator')
    allow_external=fields.Boolean(default=False)
    client_id=fields.Char()
    client_secret_env=fields.Char(default='LAB_OAUTH_CLIENT_SECRET')
    tenant=fields.Char(default='organizations')
    redirect_uri=fields.Char(default='http://127.0.0.1:8180/lab/connectors/oauth/callback')
    realm_id=fields.Char(readonly=True)
    token_ciphertext=fields.Text(groups='base.group_system',copy=False)
    token_expires=fields.Datetime(readonly=True,copy=False)
    connected=fields.Boolean(readonly=True,copy=False)
    zoho_module=fields.Selection([('Contacts','Contacts'),('Leads','Leads')],default='Contacts',required=True)
    conflict_policy=fields.Selection([('review','Review Both-Side Changes'),('local','Keep Local Changes'),('remote','Replace Mapped Contact Fields')],default='review',required=True)
    make_leads=fields.Boolean(default=False)
    cursor=fields.Text(readonly=True,copy=False)
    sync_complete=fields.Boolean(readonly=True,copy=False)
    max_attempts=fields.Integer(default=5,required=True)
    stripe_secret_env=fields.Char(default='STRIPE_TEST_SECRET_KEY')
    webhook_secret_env=fields.Char(default='LAB_CONNECTOR_SECRET')
    journal_id=fields.Many2one('account.journal',check_company=True,domain="[('type','in',['bank','cash'])]")
    inbound_method_id=fields.Many2one('account.payment.method.line',check_company=True)
    service_user_id=fields.Many2one('res.users',required=True,default=lambda s:s.env.user)
    _sql_constraints=[('code_unique','unique(code)','Use a unique connection code.')]

    @api.constrains('code','tenant','max_attempts','journal_id','inbound_method_id','service_user_id','company_id','redirect_uri')
    def _check_configuration(self):
        for c in self:
            if not re.fullmatch(r'[a-z0-9-]{2,40}',c.code): raise ValidationError('Use a short lowercase connection code.')
            if not re.fullmatch(r'[a-zA-Z0-9.-]{1,100}',c.tenant): raise ValidationError('Invalid Microsoft tenant identifier.')
            if not 1<=c.max_attempts<=10: raise ValidationError('Use between 1 and 10 retry attempts.')
            if c.company_id not in c.service_user_id.company_ids: raise ValidationError('Service user must have access to this company.')
            if c.inbound_method_id and (c.inbound_method_id.journal_id!=c.journal_id or c.inbound_method_id.payment_type!='inbound'):
                raise ValidationError('Select an inbound method from the configured journal.')
            u=urlsplit(c.redirect_uri or '')
            if u.path!='/lab/connectors/oauth/callback' or u.query or u.fragment or u.username or u.password:
                raise ValidationError('Use the exact callback path with no credentials, query or fragment.')
            if u.scheme!='https' and not (u.scheme=='http' and u.hostname in ('127.0.0.1','localhost')):
                raise ValidationError('OAuth requires HTTPS, except a registered loopback callback.')

    @api.model_create_multi
    def create(self,vals_list):
        if not self.env.user.has_group(MANAGER): raise AccessError('Connection management role required.')
        for vals in vals_list:
            if {'token_ciphertext','token_expires','connected','realm_id','cursor','sync_complete'}.intersection(vals):
                raise AccessError('Provider state is managed by connector actions.')
        return super().create(vals_list)

    def write(self,vals):
        guard(self,MANAGER)
        if {'token_ciphertext','token_expires','connected','realm_id','cursor','sync_complete'}.intersection(vals):
            raise AccessError('Provider state is managed by connector actions.')
        identity={'provider','company_id','mode','client_id','tenant','zoho_module','service_user_id'}
        if identity.intersection(vals) and any(c.connected or self.env['ic.binding'].search_count([('connection_id','=',c.id)]) or self.env['ic.job'].search_count([('connection_id','=',c.id)]) for c in self):
            raise UserError('An active or used connection has a fixed identity. Create a new connection instead.')
        return super().write(vals)

    def _external(self):
        self.ensure_one(); guard(self,MANAGER)
        if self.mode!='sandbox' or not self.allow_external: raise UserError('Enable an explicitly authorized developer account first.')

    def _oauth_spec(self):
        self.ensure_one()
        if self.provider=='outlook':
            base='https://login.microsoftonline.com/'+self.tenant+'/oauth2/v2.0/'
            return base+'authorize',base+'token','offline_access https://graph.microsoft.com/Contacts.Read'
        if self.provider=='zoho':
            return 'https://accounts.zoho.com/oauth/v2/auth','https://accounts.zoho.com/oauth/v2/token','ZohoCRM.modules.%s.READ'%self.zoho_module.lower()
        if self.provider=='quickbooks':
            return 'https://appcenter.intuit.com/connect/oauth2','https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer','com.intuit.quickbooks.accounting'
        raise UserError('Stripe uses a private test key and signed webhooks, not this OAuth flow.')

    def action_authorize(self):
        self.ensure_one(); self._external()
        if not self.client_id: raise UserError('Register a developer application and configure its client ID and callback first.')
        return {'type':'ir.actions.act_url','url':'/lab/connectors/oauth/start/%s'%self.id,'target':'self'}

    def _oauth_url(self,state,verifier):
        url,token,scope=self._oauth_spec()
        values={'client_id':self.client_id,'response_type':'code','redirect_uri':self.redirect_uri,'scope':scope,'state':state}
        if self.provider=='outlook':
            values.update(response_mode='query',code_challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('='),code_challenge_method='S256')
        if self.provider=='zoho': values.update(access_type='offline',prompt='consent')
        return url+'?'+urlencode(values)

    def _token_request(self,values):
        self._external()
        url=self._oauth_spec()[1]
        values=dict(values,client_id=self.client_id)
        credential=secret(self.client_secret_env)
        kwargs={'data':values,'headers':{'Accept':'application/json'}}
        if self.provider=='quickbooks':
            kwargs['auth']=(self.client_id,credential); values.pop('client_id',None)
        else: values['client_secret']=credential
        data=call('POST',url,**kwargs)
        if data.get('error') or not data.get('access_token'): raise ValidationError('OAuth provider refused the exchange; inspect the developer console.')
        if self.provider=='zoho' and data.get('api_domain') not in (None,'https://sandbox.zohoapis.com'):
            raise ValidationError('This independent lab permits only Zoho US sandbox tokens.')
        return data

    def _seal_tokens(self,data,old=None,realm=None):
        ttl=int(data.get('expires_in',3600))
        if not 1<=ttl<=86400: raise ValidationError('Unexpected token lifetime.')
        payload={'access_token':data['access_token'],'refresh_token':data.get('refresh_token') or (old or {}).get('refresh_token')}
        try: ciphertext=Fernet(secret('LAB_TOKEN_ENCRYPTION_KEY').encode()).encrypt(json.dumps(payload).encode()).decode()
        except (ValueError,TypeError): raise ValidationError('Configure a private Fernet encryption key.')
        values={'token_ciphertext':ciphertext,'token_expires':fields.Datetime.now()+timedelta(seconds=ttl),'connected':True}
        if realm is not None: values['realm_id']=realm
        super(Connection,self.sudo()).write(values)

    def _exchange(self,code,verifier,realm=None):
        self.ensure_one(); self._external()
        if self.provider=='quickbooks' and not re.fullmatch(r'[0-9]{1,30}',realm or ''): raise ValidationError('Missing sandbox company realm.')
        if self.realm_id and realm and self.realm_id!=realm: raise ValidationError('Create a new connection for another company realm.')
        values={'grant_type':'authorization_code','code':code,'redirect_uri':self.redirect_uri}
        if self.provider=='outlook': values['code_verifier']=verifier
        self._seal_tokens(self._token_request(values),realm=realm if self.provider=='quickbooks' else None)

    def _access_token(self):
        self.ensure_one(); self._external()
        if not self.connected: raise UserError('Authorize this connection first.')
        try: tokens=json.loads(Fernet(secret('LAB_TOKEN_ENCRYPTION_KEY').encode()).decrypt(self.sudo().token_ciphertext.encode()))
        except (InvalidToken,ValueError,TypeError,AttributeError): raise ValidationError('Token vault cannot be decrypted. Reauthorize using the original private key.')
        if self.token_expires<=fields.Datetime.now()+timedelta(seconds=90):
            if not tokens.get('refresh_token'): raise UserError('Refresh consent is missing; authorize again.')
            values={'grant_type':'refresh_token','refresh_token':tokens['refresh_token']}
            if self.provider=='outlook': values['scope']=self._oauth_spec()[2]
            fresh=self._token_request(values); self._seal_tokens(fresh,old=tokens); return fresh['access_token']
        return tokens['access_token']

    def action_disconnect(self):
        guard(self,MANAGER)
        super(Connection,self.sudo()).write({'token_ciphertext':False,'token_expires':False,'connected':False})
        return True

    def action_restart_scan(self):
        guard(self,MANAGER)
        super().write({'cursor':False,'sync_complete':False})
        return True

    def action_pull_page(self):
        guard(self,MANAGER)
        for c in self:
            c._external()
            if c.provider=='stripe': raise UserError('Stripe payment events arrive through signed webhooks.')
            if c.sync_complete: raise UserError('Scan completed. Restart it explicitly to reread mapped contacts.')
            token=c._access_token(); cursor=json.loads(c.cursor or '{}')
            if c.provider=='outlook':
                url=cursor.get('next') or 'https://graph.microsoft.com/v1.0/me/contacts?$top=100&$select=id,displayName,emailAddresses,businessPhones,lastModifiedDateTime'
                parts=urlsplit(url)
                if parts.scheme!='https' or parts.netloc!='graph.microsoft.com' or parts.path!='/v1.0/me/contacts': raise ValidationError('Unexpected Graph pagination URL.')
                data=call('GET',url,headers={'Authorization':'Bearer '+token,'Prefer':'IdType="ImmutableId"'})
                rows=data.get('value',[]); nxt={'next':data['@odata.nextLink']} if data.get('@odata.nextLink') else {}
                normalized=[{'id':r['id'],'name':r.get('displayName'),'email':next((a.get('address') for a in r.get('emailAddresses',[]) if a.get('address')),False),'phone':next(iter(r.get('businessPhones',[])),False)} for r in rows]
            elif c.provider=='zoho':
                params={'fields':'id,First_Name,Last_Name,Email,Phone','per_page':200}
                if cursor.get('token'): params['page_token']=cursor['token']
                else: params['page']=cursor.get('page',1)
                data=call('GET','https://sandbox.zohoapis.com/crm/v8/'+c.zoho_module,params=params,headers={'Authorization':'Zoho-oauthtoken '+token})
                rows=data.get('data',[]); info=data.get('info',{})
                nxt=({'page':params['page']+1} if params.get('page',10)<10 else {'token':info.get('next_page_token')}) if info.get('more_records') else {}
                if nxt and 'token' in nxt and not nxt['token']: raise ValidationError('Zoho pagination token missing; restart the scan.')
                normalized=[{'id':r['id'],'name':' '.join(v for v in (r.get('First_Name'),r.get('Last_Name')) if v),'email':r.get('Email'),'phone':r.get('Phone')} for r in rows]
            else:
                if not re.fullmatch(r'[0-9]{1,30}',c.realm_id or ''): raise ValidationError('Sandbox realm is missing.')
                position=int(cursor.get('position',1))
                data=call('GET','https://sandbox-quickbooks.api.intuit.com/v3/company/'+c.realm_id+'/query',params={'query':'select * from Customer startposition %s maxresults 100'%position},headers={'Authorization':'Bearer '+token,'Accept':'application/json'})
                rows=data.get('QueryResponse',{}).get('Customer',[]); nxt={'position':position+100} if len(rows)==100 else {}
                normalized=[{'id':r['Id'],'name':r.get('DisplayName'),'email':(r.get('PrimaryEmailAddr') or {}).get('Address'),'phone':(r.get('PrimaryPhone') or {}).get('FreeFormNumber')} for r in rows]
            if len(normalized)>200: raise ValidationError('Unexpected provider page size.')
            for row in normalized: self.env['ic.job']._enqueue(c,'contact',str(row['id'])+':'+digest(row),row)
            super(Connection,c).write({'cursor':json.dumps(nxt) if nxt else False,'sync_complete':not bool(nxt)})
        return True

    def action_simulate_contact(self):
        guard(self,MANAGER)
        for c in self:
            if c.mode!='simulator' or c.provider=='stripe': raise UserError('Choose a local contacts simulator.')
            row={'id':'fictional-101','name':'Fictional '+c.provider.title()+' Contact','email':c.code+'@example.invalid','phone':'+12025550101'}
            job=self.env['ic.job']._enqueue(c,'contact',row['id']+':'+digest(row),row)
            job.action_process()
        return True

    def _stripe_key(self):
        self._external()
        key=secret(self.stripe_secret_env)
        if not key.startswith('sk_test_'): raise ValidationError('Only Stripe test secret keys are accepted.')
        return key

    def _stripe_receive(self,raw,header):
        self.ensure_one()
        # Called only after controller selects this connection's dedicated service user.
        guard(self,MANAGER,operation='read')
        if self.provider!='stripe' or len(raw)>1_000_000: raise ValidationError('Invalid Stripe endpoint request.')
        parts={}
        for entry in (header or '').split(','):
            key,sep,value=entry.partition('=')
            if sep: parts.setdefault(key,[]).append(value)
        try: timestamp=int(parts['t'][0])
        except (KeyError,ValueError,IndexError): raise AccessError('Invalid signature.')
        if abs(time.time()-timestamp)>300: raise AccessError('Signature timestamp expired.')
        expected=hmac.new(secret(self.webhook_secret_env).encode(),str(timestamp).encode()+b'.'+raw,hashlib.sha256).hexdigest()
        if not any(hmac.compare_digest(expected,v) for v in parts.get('v1',[])): raise AccessError('Invalid signature.')
        try: data=json.loads(raw)
        except (ValueError,TypeError): raise ValidationError('Expected a JSON event.')
        if data.get('livemode') is not False or not re.fullmatch(r'evt_[a-zA-Z0-9_]{1,100}',str(data.get('id',''))): raise ValidationError('Only identified Stripe test events are accepted.')
        if data.get('type')!='payment_intent.succeeded': raise ValidationError('This lab supports payment_intent.succeeded only.')
        obj=data.get('data',{}).get('object',{})
        if obj.get('object')!='payment_intent' or obj.get('status')!='succeeded' or obj.get('livemode') is not False: raise ValidationError('Expected a successful test PaymentIntent.')
        row={key:obj.get(key) for key in ('id','amount','amount_received','currency','status','livemode','metadata')}
        return self.env['ic.job']._enqueue(self,'payment',data['id'],row)

class Binding(models.Model):
    _name='ic.binding'
    _description='Company and Connection Scoped Contact Binding'
    _check_company_auto=True
    connection_id=fields.Many2one('ic.connection',required=True,ondelete='restrict')
    company_id=fields.Many2one(related='connection_id.company_id',store=True)
    external_id=fields.Char(required=True,index=True)
    partner_id=fields.Many2one('res.partner',required=True,check_company=True,ondelete='restrict')
    lead_id=fields.Many2one('crm.lead',check_company=True,ondelete='restrict',readonly=True)
    local_fingerprint=fields.Char(readonly=True)
    remote_fingerprint=fields.Char(readonly=True)
    last_job_id=fields.Many2one('ic.job',readonly=True,ondelete='restrict')
    _sql_constraints=[('binding_unique','unique(connection_id,external_id)','This external contact is already mapped.')]
    @api.model_create_multi
    def create(self,vals_list):
        if not self.env.user.has_group(MANAGER): raise AccessError('Connector manager role required.')
        for vals in vals_list:
            if {'local_fingerprint','remote_fingerprint','lead_id','last_job_id'}.intersection(vals): raise AccessError('Import metadata is managed by the connector.')
        return super().create(vals_list)
    def write(self,vals):
        guard(self,MANAGER)
        if set(vals)-{'partner_id'}: raise AccessError('Only a reviewed partner remapping is editable.')
        result=super().write(vals)
        super().write({'local_fingerprint':False,'remote_fingerprint':False})
        return result

class Job(models.Model):
    _name='ic.job'
    _description='Immutable Connector Inbox and Bounded Retry Job'
    _order='id asc'
    connection_id=fields.Many2one('ic.connection',required=True,ondelete='restrict')
    company_id=fields.Many2one(related='connection_id.company_id',store=True)
    kind=fields.Selection([('contact','Contact Import'),('payment','Stripe Receipt')],required=True)
    external_key=fields.Char(required=True,index=True)
    payload=fields.Text(required=True)
    payload_hash=fields.Char(required=True)
    state=fields.Selection([('pending','Pending'),('error','Retryable Error'),('dead','Manual Review'),('done','Done')],default='pending',readonly=True)
    attempts=fields.Integer(default=0,readonly=True)
    next_retry=fields.Datetime(readonly=True)
    error=fields.Text(readonly=True)
    binding_id=fields.Many2one('ic.binding',readonly=True)
    payment_id=fields.Many2one('ic.payment',readonly=True)
    _sql_constraints=[('job_unique','unique(connection_id,kind,external_key)','Event has already been queued.')]
    @api.model_create_multi
    def create(self,vals_list): raise AccessError('Inbox rows are created by verified connector entry points.')
    def write(self,vals): raise AccessError('Inbox history is managed by its processing actions.')
    def unlink(self): raise AccessError('Connector history is retained for review.')

    @api.model
    def _enqueue(self,connection,kind,key,row):
        connection.ensure_one(); guard(connection,MANAGER,operation='read')
        # Serializes imports, webhook replays and distinct business events per connection.
        self.env.cr.execute('SELECT pg_advisory_xact_lock(%s,%s)',(710010,connection.id))
        hashed=digest(row)
        prior=self.search([('connection_id','=',connection.id),('kind','=',kind),('external_key','=',key)],limit=1)
        if prior:
            if prior.payload_hash!=hashed: raise ValidationError('Existing event ID was replayed with different content.')
            return prior
        return super().create({'connection_id':connection.id,'kind':kind,'external_key':key,'payload':json.dumps(row,sort_keys=True),'payload_hash':hashed})

    def action_process(self):
        guard(self,MANAGER,operation='read')
        for job in self:
            if job.state in ('done','dead'): continue
            c=job.connection_id
            guard(c,MANAGER,operation='read')
            self.env.cr.execute('SELECT pg_advisory_xact_lock(%s,%s)',(710010,c.id))
            super(Job,job).write({'attempts':job.attempts+1})
            try:
                with self.env.cr.savepoint():
                    payload=json.loads(job.payload)
                    if digest(payload)!=job.payload_hash: raise ValidationError('Inbox content hash mismatch.')
                    if job.kind=='contact': job._contact(payload)
                    else: job._payment(payload)
                    super(Job,job).write({'state':'done','error':False,'next_retry':False})
            except Exception as error:
                message=str(error)[:1000] if isinstance(error,(UserError,ValidationError)) else type(error).__name__+'; processing failed without logging the payload.'
                super(Job,job).write({'state':'dead' if job.attempts>=c.max_attempts else 'error','error':message,'next_retry':fields.Datetime.now()+timedelta(minutes=min(2**job.attempts,120))})
        return True

    def action_retry(self):
        guard(self,MANAGER,operation='read')
        for job in self.filtered(lambda j:j.state in ('error','dead')):
            super(Job,job).write({'state':'pending','attempts':0,'error':False,'next_retry':False})
        return self.action_process()

    @api.model
    def _cron_retry(self):
        for job in self.search([('state','in',['pending','error']), '|',('next_retry','=',False),('next_retry','<=',fields.Datetime.now())],limit=50):
            c=job.connection_id
            if c.active and c.company_id in c.service_user_id.company_ids:
                job.with_user(c.service_user_id).with_company(c.company_id).with_context(allowed_company_ids=[c.company_id.id]).action_process()

    def _contact(self,p):
        self.ensure_one(); c=self.connection_id
        if c.provider=='stripe': raise ValidationError('Stripe cannot import CRM contacts through this mapper.')
        external=str(p.get('id') or '')
        if not external or len(external)>200 or not p.get('name'): raise ValidationError('Contact ID and name are required.')
        vals={'name':str(p['name'])[:200],'email':str(p.get('email') or '')[:200] or False,'phone':str(p.get('phone') or '')[:100] or False}
        binding=self.env['ic.binding'].search([('connection_id','=',c.id),('external_id','=',external)],limit=1)
        if binding and binding.last_job_id and binding.last_job_id.id>self.id:
            super(Job,self).write({'binding_id':binding.id}); return
        current=lambda partner: digest({k:partner[k] or False for k in ('name','email','phone')})
        remote=digest(vals)
        if not binding:
            # No email-based automatic merges across connectors or companies.
            partner=self.env['res.partner'].with_company(c.company_id).create(dict(vals,company_id=c.company_id.id))
            binding=super(Binding,self.env['ic.binding']).create({'connection_id':c.id,'external_id':external,'partner_id':partner.id})
        else:
            partner=binding.partner_id
            changed=binding.local_fingerprint and current(partner)!=binding.local_fingerprint
            if binding.remote_fingerprint==remote:
                super(Binding,binding).write({'last_job_id':self.id})
                super(Job,self).write({'binding_id':binding.id}); return
            if changed and c.conflict_policy=='review': raise ValidationError('Mapped contact changed locally and remotely. Review the connection conflict policy.')
            if not changed or c.conflict_policy=='remote': partner.write(vals)
        lead=binding.lead_id
        if c.make_leads and not lead:
            lead=self.env['crm.lead'].with_company(c.company_id).create({'name':'Imported inquiry: '+partner.name,'partner_id':partner.id,'email_from':partner.email,'phone':partner.phone,'company_id':c.company_id.id,'type':'lead'})
        super(Binding,binding).write({'local_fingerprint':current(partner),'remote_fingerprint':remote,'lead_id':lead.id or False,'last_job_id':self.id})
        super(Job,self).write({'binding_id':binding.id})

    def _payment(self,p):
        self.ensure_one(); c=self.connection_id
        if c.provider!='stripe': raise ValidationError('Payment mapper requires a Stripe test connection.')
        binding=self.env['ic.payment'].search([('connection_id','=',c.id),('external_id','=',p.get('id'))],limit=1)
        if not binding: raise ValidationError('PaymentIntent must have been created or bound explicitly for this invoice.')
        guard(binding,MANAGER,operation='read')
        if binding.state=='paid':
            super(Job,self).write({'payment_id':binding.id}); return
        if p.get('livemode') is not False or p.get('status')!='succeeded' or p.get('currency','').upper()!=binding.currency_id.name:
            raise ValidationError('Payment status, mode or currency does not match the invoice binding.')
        amount=p.get('amount_received')
        if isinstance(amount,bool) or not isinstance(amount,int) or amount!=binding.amount_minor or p.get('amount')!=binding.amount_minor:
            raise ValidationError('Received minor-unit amount does not match the bound invoice amount.')
        meta=p.get('metadata') or {}
        if meta.get('lab_binding')!=binding.uuid or meta.get('lab_database')!=hashlib.sha256(self.env.cr.dbname.encode()).hexdigest():
            raise ValidationError('Payment metadata does not match this isolated database and binding.')
        # Sandbox processing re-fetches the provider object before any accounting action.
        if c.mode=='sandbox':
            live=call('GET','https://api.stripe.com/v1/payment_intents/'+binding.external_id,auth=(c._stripe_key(),''))
            if any(live.get(k)!=p.get(k) for k in ('id','currency','amount_received','status','livemode','metadata')):
                raise ValidationError('Provider object differs from the signed event snapshot.')
        invoice=binding.invoice_id
        guard(invoice,'account.group_account_invoice')
        if invoice.state!='posted' or invoice.move_type!='out_invoice' or invoice.currency_id!=binding.currency_id:
            raise ValidationError('Receipt requires its posted customer invoice.')
        if not c.journal_id or not c.inbound_method_id: raise ValidationError('Configure an accounting journal and inbound payment method.')
        if decimal(binding.amount)>decimal(invoice.amount_residual): raise ValidationError('Receipt exceeds invoice residual; review an already-paid or edited invoice.')
        wizard=self.env['account.payment.register'].with_company(c.company_id).with_context(active_model='account.move',active_ids=invoice.ids).create({
            'amount':binding.amount,'journal_id':c.journal_id.id,'payment_method_line_id':c.inbound_method_id.id,'payment_date':fields.Date.context_today(self),'communication':'Stripe test '+binding.external_id})
        payments=wizard._create_payments()
        super(Payment,binding).write({'payment_ids':[(6,0,payments.ids)],'state':'paid'})
        super(Job,self).write({'payment_id':binding.id})

class Payment(models.Model):
    _name='ic.payment'
    _description='Stripe Test PaymentIntent Invoice Binding'
    _check_company_auto=True
    connection_id=fields.Many2one('ic.connection',required=True,ondelete='restrict')
    company_id=fields.Many2one(related='connection_id.company_id',store=True)
    invoice_id=fields.Many2one('account.move',required=True,check_company=True,ondelete='restrict')
    currency_id=fields.Many2one(related='invoice_id.currency_id',store=True)
    amount=fields.Monetary(required=True)
    amount_minor=fields.Integer(readonly=True)
    uuid=fields.Char(required=True,readonly=True,default=lambda s:str(uuid.uuid4()),copy=False)
    external_id=fields.Char(readonly=True,index=True,copy=False)
    state=fields.Selection([('draft','Draft'),('awaiting','Awaiting Test Payment'),('paid','Registered in Odoo'),('credited','Draft Credit Created')],default='draft',readonly=True)
    payment_ids=fields.Many2many('account.payment',readonly=True)
    credit_id=fields.Many2one('account.move',readonly=True,check_company=True)
    _sql_constraints=[('intent_unique','unique(connection_id,external_id)','This PaymentIntent is already bound.'),('uuid_unique','unique(uuid)','Binding UUID must be unique.')]
    @api.model_create_multi
    def create(self,vals_list): raise AccessError('Create a binding from its posted invoice action.')
    def write(self,vals): raise AccessError('Payment binding history is managed by workflow actions.')
    def unlink(self): raise AccessError('Payment history is retained.')

    def action_create_intent(self):
        guard(self,MANAGER,operation='read')
        if not self.env.user.has_group('account.group_account_invoice'): raise AccessError('Accounting access is required.')
        for b in self:
            if b.external_id: continue
            invoice=b.invoice_id; c=b.connection_id
            guard(c,MANAGER,operation='read')
            if c.provider!='stripe' or not c.active: raise UserError('Use an active Stripe test connection.')
            guard(invoice,'account.group_account_invoice')
            if invoice.state!='posted' or invoice.move_type!='out_invoice' or b.amount<=0 or b.amount>invoice.amount_residual:
                raise UserError('Use a positive amount within a posted customer invoice residual.')
            # Restrict this demonstration to currencies with two decimal minor units.
            if invoice.currency_id.name not in ('USD','EUR','GBP','AED','PKR') or invoice.currency_id.decimal_places!=2:
                raise UserError('This lab supports two-decimal USD, EUR, GBP, AED and PKR only.')
            minor=decimal(b.amount)*100
            if minor!=minor.to_integral_value() or minor>99999999: raise UserError('Invalid Stripe two-decimal amount.')
            metadata={'lab_binding':b.uuid,'lab_database':hashlib.sha256(self.env.cr.dbname.encode()).hexdigest()}
            if c.mode=='simulator': external='pi_sim_'+b.uuid.replace('-','')
            else:
                data=call('POST','https://api.stripe.com/v1/payment_intents',auth=(c._stripe_key(),''),headers={'Idempotency-Key':'odoo-lab-'+b.uuid},data={'amount':int(minor),'currency':b.currency_id.name.lower(),'payment_method_types[]':'card',**{'metadata[%s]'%k:v for k,v in metadata.items()}})
                external=data.get('id')
                if data.get('livemode') is not False or not re.fullmatch(r'pi_[a-zA-Z0-9_]+',external or ''): raise ValidationError('Provider returned an unexpected test PaymentIntent.')
            super(Payment,b).write({'amount_minor':int(minor),'external_id':external,'state':'awaiting'})
        return True

    def action_simulate_success(self):
        guard(self,MANAGER,operation='read')
        for b in self:
            if b.connection_id.mode!='simulator' or b.state!='awaiting': raise UserError('Create an awaiting simulator PaymentIntent first.')
            row={'id':b.external_id,'object':'payment_intent','amount':b.amount_minor,'amount_received':b.amount_minor,'currency':b.currency_id.name.lower(),'status':'succeeded','livemode':False,'metadata':{'lab_binding':b.uuid,'lab_database':hashlib.sha256(self.env.cr.dbname.encode()).hexdigest()}}
            raw=json.dumps({'id':'evt_sim_'+b.uuid.replace('-',''),'type':'payment_intent.succeeded','livemode':False,'data':{'object':row}}).encode()
            stamp=str(int(time.time())); signature=hmac.new(secret(b.connection_id.webhook_secret_env).encode(),stamp.encode()+b'.'+raw,hashlib.sha256).hexdigest()
            job=b.connection_id._stripe_receive(raw,'t='+stamp+',v1='+signature)
            job.action_process()
        return True

    def action_draft_credit(self):
        guard(self,MANAGER,operation='read')
        if not self.env.user.has_group('account.group_account_invoice'): raise AccessError('Accounting role required.')
        for b in self:
            if b.credit_id: continue
            if b.state!='paid' or b.amount!=b.invoice_id.amount_total: raise UserError('Only a full-invoice test credit is supported. Review partial credits in native accounting.')
            credit=b.invoice_id._reverse_moves(default_values_list=[{'date':fields.Date.context_today(self),'ref':'Review credit for Stripe test '+b.external_id}],cancel=False)
            super(Payment,b).write({'credit_id':credit.id,'state':'credited'})
        return True

class Move(models.Model):
    _inherit='account.move'
    ic_connection_id=fields.Many2one('ic.connection',check_company=True,copy=False,domain="[('provider','=','stripe')]")
    def action_prepare_test_payment(self):
        self.ensure_one(); guard(self,'account.group_account_invoice')
        c=self.ic_connection_id
        if not c or c.provider!='stripe': raise UserError('Select a Stripe test connection.')
        guard(c,MANAGER,operation='read')
        if self.state!='posted' or self.move_type!='out_invoice' or self.amount_residual<=0: raise UserError('Use a posted customer invoice with a positive residual.')
        existing=self.env['ic.payment'].search([('invoice_id','=',self.id),('state','in',['draft','awaiting'])],limit=1)
        binding=existing or super(Payment,self.env['ic.payment']).create({'connection_id':c.id,'invoice_id':self.id,'amount':self.amount_residual})
        return {'type':'ir.actions.act_window','res_model':'ic.payment','res_id':binding.id,'view_mode':'form'}
