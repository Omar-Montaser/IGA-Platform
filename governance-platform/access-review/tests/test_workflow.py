"""Acceptance of persisted review decisions and connector verification."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from uuid import uuid4
import httpx
from fastapi.testclient import TestClient
from iga_review.api import create_app
from iga_review.connector import FixtureConnector, HTTPConnector
from iga_review.demo import build_demo
from iga_review.domain import User, Scan, timestamp
from iga_review.service import ReviewService, ServiceError

HR=Path(__file__).resolve().parents[2]/'hr-policy/data'

class Case(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root=Path(temp.name); self.now=datetime(2026,9,21,12,tzinfo=timezone.utc)
        self.payload=build_demo(json.loads((HR/'identities.json').read_text()),json.loads((HR/'policies.json').read_text()),self.now-timedelta(minutes=1))
        def user(id,role,hr=None):return User(id,id,role,hr,hashlib.sha256((id+'-secret').encode()).hexdigest())
        self.admin=user('admin','admin'); self.manager=user('manager','reviewer','id:person-0001')
        self.outsider=user('outsider','reviewer'); self.self_actor=user('self','admin','id:person-0005')
        self.users=[self.admin,self.manager,self.outsider,self.self_actor]
        self.connector=FixtureConnector(self.root/'fixture.db',self.payload['scan'],clock=lambda:self.now+timedelta(seconds=1))
        self.service=self.make_service()
        self.campaign=self.service.create_campaign(self.payload,self.admin)
        self.target=next(f for f in self.campaign['findings'] if f['account_id']=='acct:person-0005' and f['entitlement_id']=='ent:engineering:production-deploy')
    def make_service(self):
        return ReviewService(self.root/'review.db',self.users,fallback_reviewer_id='admin',connectors={'prototype-system':self.connector},clock=lambda:self.now,demo=True)
    def decide(self,item=None,actor=None,key=None,**fields):
        item=item or self.target
        body=dict(action='revoke',reason='Reviewed supporting evidence.',expected_version=item['version'],acknowledge_risk=False)
        body.update(fields)
        return self.service.decide(item['id'],actor or self.admin,body,key or str(uuid4()))
    def error(self,status,fn):
        with self.assertRaises(ServiceError) as got:fn()
        self.assertEqual(got.exception.status,status)
    def export(self):return self.service.export(self.campaign['id'],self.admin)
    def process(self):return self.service.process(self.campaign['id'],self.admin)['processed']

class WorkflowTests(Case):
    def test_inputs_digests_and_empty_decision_history(self):
        data=self.export();self.assertEqual(data['inputs'],self.payload)
        expected=hashlib.sha256(json.dumps(self.payload['scan'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        self.assertEqual(data['campaign']['metadata']['input_digests']['scan'],expected)
        self.assertEqual(data['decisions'],[]);self.assertTrue(data['audit']['integrity'])
    def test_import_idempotence_and_scan_id_immutability(self):
        same=self.service.create_campaign(deepcopy(self.payload),self.admin)
        self.assertEqual(same['id'],self.campaign['id']);self.assertIsNone(same['superseded_by'])
        changed=deepcopy(self.payload);changed['scan']['assignments'].pop()
        self.error(409,lambda:self.service.create_campaign(changed,self.admin))
    def test_role_object_scope_and_self_review(self):
        self.error(403,lambda:self.service.create_campaign(self.payload,self.manager))
        self.error(404,lambda:self.service.get_finding(self.target['id'],self.outsider))
        self.error(404,lambda:self.decide(actor=self.outsider))
        self.error(403,lambda:self.decide(actor=self.self_actor))
        self.error(403,lambda:self.service.export(self.campaign['id'],self.manager))
        self.error(403,lambda:self.service.process(self.campaign['id'],self.manager))
        self.assertTrue(all(f['reviewer_id']=='manager' for f in self.service.get_campaign(self.campaign['id'],self.manager)['findings']))
    def test_assigned_manager_decision_uses_authenticated_actor(self):
        self.assertEqual(self.decide(actor=self.manager)['actor_id'],'manager')
        self.assertEqual(self.service.get_finding(self.target['id'],self.manager)['status'],'revoke_queued')
    def test_decision_is_durable_without_connector_execution(self):
        before=self.connector.scan('prototype-system','before')
        self.decide()
        self.assertEqual(before['assignments'],self.connector.scan('prototype-system','after')['assignments'])
        actions=[e['action'] for e in self.export()['audit']['events']]
        self.assertIn('decision_recorded',actions);self.assertNotIn('dispatch_started',actions)
    def test_revoke_verifies_fresh_state_and_all_grant_paths(self):
        self.assertEqual(len(self.target['assignment_ids']),2);self.decide()
        self.assertEqual(self.process()[0]['state'],'verified')
        data=self.export();fresh=data['requests'][0]['verification']['scan']
        self.assertNotEqual(fresh['scan_id'],self.payload['scan']['scan_id'])
        self.assertFalse(any(a['identity']==self.target['account_id'] and a['entitlement']==self.target['entitlement_id'] for a in fresh['assignments']))
        self.assertEqual(self.service.get_finding(self.target['id'],self.admin)['status'],'revoked_verified')
        actions=[e['action'] for e in data['audit']['events']]
        self.assertLess(actions.index('decision_recorded'),actions.index('dispatch_started'))
        self.assertLess(actions.index('connector_acknowledged'),actions.index('verified'))
        self.assertTrue(data['audit']['integrity'])
    def test_idempotent_decision_and_conflicting_key(self):
        first=self.decide(key='key-stable-001')
        self.assertEqual(self.decide(key='key-stable-001'),first)
        self.error(409,lambda:self.decide(key='key-stable-001',reason='Different justification.'))
        self.assertEqual(len(self.export()['decisions']),1);self.assertEqual(len(self.export()['requests']),1)
    def test_concurrent_decisions_commit_once(self):
        def attempt(i):
            try:return self.decide(key=f'parallel-{i}')
            except ServiceError as exc:return exc.status
        with ThreadPoolExecutor(max_workers=2) as pool:values=list(pool.map(attempt,[1,2]))
        self.assertEqual(sum(isinstance(x,dict) for x in values),1);self.assertIn(409,values)
        self.assertEqual(len(self.export()['decisions']),1)
    def test_risky_certification_requires_acknowledgement(self):
        self.error(422,lambda:self.decide(action='certify'))
        self.decide(action='certify',acknowledge_risk=True)
        self.assertEqual(self.service.get_finding(self.target['id'],self.admin)['status'],'certified')
        self.assertEqual(self.export()['requests'],[])
    def test_missing_access_only_allows_acknowledgement(self):
        missing=next(f for f in self.campaign['findings'] if f['kind']=='missing_access')
        self.error(422,lambda:self.decide(item=missing))
        self.decide(item=missing,action='acknowledge')
        self.assertEqual(self.service.get_finding(missing['id'],self.admin)['status'],'acknowledged')
        self.assertEqual(self.export()['requests'],[])
    def test_staleness_rechecked_at_decision_and_dispatch(self):
        self.now+=timedelta(days=2);self.error(403,lambda:self.decide())
        self.assertFalse(self.service.get_finding(self.target['id'],self.admin)['can_decide'])
        self.now-=timedelta(days=2);self.decide();self.now+=timedelta(days=2)
        self.assertEqual(self.process()[0]['state'],'failed')
    def test_new_campaign_supersedes_old_approval(self):
        self.decide();new=deepcopy(self.payload)
        new['scan'].update(scan_id='scan:new-review',scanned_at=timestamp(self.now))
        newer=self.service.create_campaign(new,self.admin)
        old=self.service.get_campaign(self.campaign['id'],self.admin)
        self.assertEqual(old['superseded_by'],newer['id']);self.assertFalse(old['actionable'])
        self.assertEqual(self.process()[0]['state'],'failed')
    def test_unresolved_routing_blocks_admin(self):
        service=ReviewService(self.root/'unrouted.db',[self.admin],clock=lambda:self.now)
        item=service.create_campaign(self.payload,self.admin)['findings'][0]
        self.assertIsNone(item['reviewer_id']);self.assertFalse(item['can_decide'])
        self.error(403,lambda:service.decide(item['id'],self.admin,dict(action='revoke',reason='Reviewed evidence carefully.',expected_version=1),'unrouted-key'))
    def test_success_response_without_removal_is_not_verified(self):
        fixture=self.connector
        class Liar:
            def revoke(_,request):return dict(request_id=request['request_id'],status='succeeded',message='ok')
            def scan(_,source,id):return fixture.scan(source,id)
        self.service.connectors['prototype-system']=Liar();self.decide()
        result=self.process()[0];self.assertEqual(result['state'],'verification_failed')
        self.assertIn('still exists',result['error']);self.assertIsNotNone(self.export()['requests'][0]['verification'])
    def test_wrong_stale_partial_mapping_or_reused_verification_fails(self):
        request=dict(source='prototype-system',identity=self.target['account_id'],entitlement=self.target['entitlement_id'],scan_id=self.payload['scan']['scan_id'],mapping_version='demo-mapping-1',approved_at=timestamp(self.now))
        fresh=deepcopy(self.payload['scan']);fresh.update(scan_id='scan:fresh',request_id='rescan:expected',scanned_at=timestamp(self.now+timedelta(seconds=1)))
        fresh['assignments']=[a for a in fresh['assignments'] if not(a['identity']==request['identity'] and a['entitlement']==request['entitlement'])]
        for field,value in [('request_id','rescan:wrong'),('mapping_version','other'),('scan_id',request['scan_id']),('scanned_at',timestamp(self.now)),('complete',False)]:
            with self.subTest(field=field):
                changed=deepcopy(fresh);changed[field]=value
                self.assertIsNotNone(self.service._verification_problem(request,Scan.model_validate(changed),'rescan:expected',self.now))
        self.assertIsNone(self.service._verification_problem(request,Scan.model_validate(fresh),'rescan:expected',self.now))
    def test_transport_retry_reuses_request_and_sanitizes_error(self):
        fixture=self.connector
        class Flaky:
            ids=[]
            def revoke(inner,request):
                inner.ids.append(request['request_id'])
                if len(inner.ids)==1:raise httpx.ReadTimeout('sensitive-remote-address')
                return fixture.revoke(request)
            def scan(_,source,id):return fixture.scan(source,id)
        flaky=Flaky();self.service.connectors['prototype-system']=flaky
        decision=self.decide();first=self.process()[0]
        self.assertEqual(first['state'],'failed');self.assertNotIn('sensitive',first['error'])
        self.assertEqual(self.service.retry(decision['request_id'],self.admin)['state'],'verified')
        self.assertEqual(flaky.ids,[decision['request_id']]*2)
    def test_verification_retry_does_not_repeat_removal(self):
        fixture=self.connector
        class Partial:
            calls=0;bad=True
            def revoke(inner,request):inner.calls+=1;return fixture.revoke(request)
            def scan(inner,source,id):
                data=fixture.scan(source,id)
                if inner.bad:data['complete']=False
                return data
        connector=Partial();self.service.connectors['prototype-system']=connector
        decision=self.decide();self.assertEqual(self.process()[0]['state'],'verification_failed')
        connector.bad=False
        self.assertEqual(self.service.retry(decision['request_id'],self.admin)['state'],'verified');self.assertEqual(connector.calls,1)
    def test_restart_retains_queue_and_audit(self):
        self.decide();restarted=self.make_service()
        self.assertEqual(restarted.get_finding(self.target['id'],self.admin)['status'],'revoke_queued')
        self.assertEqual(restarted.process(self.campaign['id'],self.admin)['processed'][0]['state'],'verified')
        self.assertTrue(restarted.audit(self.campaign['id'],self.admin)['integrity'])
    def test_removed_or_reassigned_approver_cannot_dispatch(self):
        self.decide(actor=self.manager)
        self.service.users.pop('manager')
        self.assertEqual(self.process()[0]['state'],'failed')
        self.assertTrue(any(a['identity']==self.target['account_id'] and a['entitlement']==self.target['entitlement_id'] for a in self.connector.scan('prototype-system','unchanged')['assignments']))
    def test_claim_lease_prevents_parallel_dispatch_then_expires(self):
        decision=self.decide()
        with self.service.store.transaction() as conn:conn.execute('UPDATE requests SET state=?,lease_until=? WHERE id=?',('dispatching',timestamp(self.now+timedelta(seconds=30)),decision['request_id']))
        self.assertTrue(self.process()[0]['busy']);self.now+=timedelta(seconds=31)
        self.assertEqual(self.process()[0]['state'],'verified')
    def test_inputs_and_audit_cannot_be_overwritten(self):
        with self.service.store.transaction() as conn:
            for sql in ['DELETE FROM audit','UPDATE audit SET action="changed"','UPDATE campaigns SET inputs_json="{}"']:
                with self.assertRaises(sqlite3.IntegrityError):conn.execute(sql)
        self.assertTrue(self.export()['audit']['integrity'])
    def test_unconfigured_connector_never_claims_success(self):
        self.service.connectors.clear();self.decide()
        self.assertEqual(self.process()[0]['state'],'failed')
        self.assertNotEqual(self.service.get_finding(self.target['id'],self.admin)['status'],'revoked_verified')
    def test_explanations_do_not_decide(self):
        self.assertEqual(self.service.explain(self.target['id'],self.manager)['provider'],'rules')
        self.assertEqual(self.service.get_finding(self.target['id'],self.admin)['status'],'pending')
        self.assertEqual(self.export()['decisions'],[])

class APITests(Case):
    def setUp(self):
        super().setUp();self.client=TestClient(create_app(self.service));self.addCleanup(self.client.close)
        self.headers={'Authorization':'Bearer admin-secret'}
    def test_auth_and_submitted_actor_rejection(self):
        root=self.client.get('/')
        self.assertEqual(root.status_code,200)
        # Root may return HTML (UI) or JSON (API status) depending on static files
        if 'text/html' in root.headers.get('content-type', ''):
            self.assertIn('IGA Access Review', root.text)
        else:
            self.assertIn('core API ready', root.json()['status'])
        self.assertEqual(self.client.get('/api/health').status_code,200)
        self.assertEqual(self.client.get('/api/campaigns').status_code,401)
        self.assertEqual(self.client.get('/api/me',headers=self.headers).json()['id'],'admin')
        r=self.client.post('/api/findings/'+self.target['id']+'/decisions',headers={**self.headers,'Idempotency-Key':'http-request-01'},json=dict(action='revoke',reason='Reviewed source evidence.',expected_version=1,actor_id='manager'))
        self.assertEqual(r.status_code,422)
    def test_http_approve_process_and_export(self):
        r=self.client.post('/api/findings/'+self.target['id']+'/decisions',headers={**self.headers,'Idempotency-Key':'http-request-02'},json=dict(action='revoke',reason='Reviewed source evidence.',expected_version=1,acknowledge_risk=False))
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.client.post('/api/campaigns/'+self.campaign['id']+'/process',headers=self.headers).status_code,200)
        self.assertEqual(self.client.get('/api/campaigns/'+self.campaign['id']+'/export',headers=self.headers).json()['requests'][0]['state'],'verified')
    def test_duplicate_keys_cross_origin_and_cross_site_rejected(self):
        r=self.client.post('/api/campaigns',headers={**self.headers,'Content-Type':'application/json'},content='{"name":"a","name":"b"}')
        self.assertEqual(r.status_code,422)
        self.assertEqual(self.client.get('/api/me',headers={**self.headers,'Origin':'https://foreign.example'}).status_code,403)
        self.assertEqual(self.client.get('/api/me',headers={**self.headers,'Sec-Fetch-Site':'cross-site'}).status_code,403)
    def test_security_headers_schema_and_audit_scope(self):
        r=self.client.get('/api/schemas/scan',headers=self.headers)
        self.assertEqual(r.status_code,200);self.assertFalse(r.json()['additionalProperties'])
        self.assertIn("frame-ancestors 'none'",r.headers['content-security-policy']);self.assertEqual(r.headers['cache-control'],'no-store')
        self.assertNotIn('access-control-allow-origin',r.headers)
        self.assertEqual(self.client.get('/api/campaigns/'+self.campaign['id']+'/audit',headers={'Authorization':'Bearer outsider-secret'}).status_code,404)

class TransportTests(unittest.TestCase):
    def test_configured_endpoint_service_auth_and_idempotency(self):
        seen=[]
        def response(request):seen.append(request);return httpx.Response(200,json=dict(request_id='req:1',status='succeeded',message='accepted'))
        with httpx.Client(transport=httpx.MockTransport(response)) as client:
            result=HTTPConnector('https://connector.example','service-secret',client=client).revoke(dict(request_id='req:1',identity='acct:1',entitlement='ent:x:read'))
        self.assertEqual(result['status'],'succeeded');self.assertEqual(str(seen[0].url),'https://connector.example/revocations')
        self.assertEqual(seen[0].headers['authorization'],'Bearer service-secret');self.assertEqual(seen[0].headers['idempotency-key'],'req:1')
    def test_unsafe_connector_configuration_rejected(self):
        for url in ['http://remote.example','https://user:password@connector.example','https://connector.example?target=x','file:///tmp/x']:
            with self.subTest(url=url),self.assertRaises(ValueError):HTTPConnector(url,'token')
    def test_redirect_does_not_forward_credentials(self):
        seen=[]
        def response(request):seen.append(request);return httpx.Response(307,headers={'location':'https://other.example'})
        with httpx.Client(transport=httpx.MockTransport(response)) as client:
            with self.assertRaises(httpx.HTTPStatusError):HTTPConnector('https://connector.example','token',client=client).scan('source','req:1')
        self.assertEqual(len(seen),1)
