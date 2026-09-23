"""Environment-first acceptance, isolated from live sources and external AI."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from iga_review.api import create_app
from iga_review.connector import FixtureConnector
from iga_review.demo import build_demo
from iga_review.domain import User, timestamp
from iga_review.runs import LeaseLost, CampaignRunWorker
from iga_review.service import ReviewService, ServiceError
from iga_review.source_inputs import SourceInputs
from iga_review.store import Store

HR = Path(__file__).resolve().parents[2] / 'hr-policy/data'


class RunTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.now = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)
        self.payload = build_demo(json.loads((HR/'identities.json').read_text()),
                                  json.loads((HR/'policies.json').read_text()), self.now)
        self.docs = {k: self.payload[k] for k in ('identities', 'policies', 'correlations')}
        self.admin = User('admin', 'Admin', 'admin', None, hashlib.sha256(b'admin').hexdigest())
        self.reviewer = User('reviewer', 'Reviewer', 'reviewer', None, hashlib.sha256(b'reviewer').hexdigest())
        self.source = 'prototype-system'
        self.connector = FixtureConnector(self.root/'fixture.db', self.payload['scan'], clock=lambda: self.now)
        self.env = {self.source: {'name': 'Test environment', 'mode': 'simulated', 'load_inputs': lambda now: deepcopy(self.docs)}}
        self.service = self.make_service()

    def make_service(self):
        return ReviewService(self.root/'review.db', [self.admin, self.reviewer], fallback_reviewer_id='admin',
                             connectors={self.source: self.connector}, environments=self.env, clock=lambda: self.now, demo=True)

    def start(self, key='first', name='Access review'):
        return self.service.runs.start(self.source, {'name': name}, self.admin, key)

    def run_job(self, key='first'):
        run = self.start(key)
        self.assertTrue(self.service.runs.tick())
        return self.service.runs.get(run['id'], self.admin)

    def test_empty_environment_reads_do_not_scan_and_complete_flow_pins_evidence(self):
        with patch.object(self.connector, 'scan', wraps=self.connector.scan) as scan:
            before = self.service.runs.environments_view(self.admin)['sources'][0]
            self.assertEqual(before['status'], 'never_scanned')
            self.assertIsNone(before['inventory'])
            self.assertTrue(before['can_start'])
            scan.assert_not_called()
            run = self.run_job()
            self.assertEqual(run['state'], 'completed', run)
            self.assertEqual(scan.call_count, 1)
            self.assertGreater(run['review']['fallback_cases'], 0)
            self.assertEqual(run['review']['providers'], ['rules'])
            exported = self.service.export(run['campaign_id'], self.admin)
            self.assertTrue(exported['audit']['integrity'])
            self.assertEqual(exported['decisions'], [])
            self.assertEqual(exported['requests'], [])
            after = self.service.runs.environments_view(self.admin)['sources'][0]
            self.assertEqual(after['inventory']['scan_id'], exported['inputs']['scan']['scan_id'])
            self.assertEqual(after['inventory']['counts']['accounts'], len(self.payload['scan']['identities']))
            self.assertEqual(scan.call_count, 1)

    def test_idempotency_concurrent_starts_and_conflicts(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            ids = list(pool.map(lambda _: self.start()['id'], range(4)))
        self.assertEqual(len(set(ids)), 1)
        for key, name in [('first', 'Changed'), ('second', 'Access review')]:
            with self.assertRaises(ServiceError) as got:
                self.start(key, name)
            self.assertEqual(got.exception.status, 409)
        self.assertEqual(self.start()['id'], ids[0])

    def test_api_authorization_strict_payload_and_202(self):
        with TestClient(create_app(self.service, run_campaign_worker=False)) as client:
            path = f'/api/environments/{self.source}/campaign-runs'
            self.assertEqual(client.get('/api/environments').status_code, 401)
            headers = {'Authorization': 'Bearer reviewer', 'Idempotency-Key': 'x'}
            self.assertEqual(client.get('/api/environments', headers=headers).status_code, 403)
            self.assertEqual(client.post(path, headers=headers, json={'name': 'Test'}).status_code, 403)
            headers['Authorization'] = 'Bearer admin'
            self.assertEqual(client.post(path, headers=headers, json={'name': 'Test', 'scan': {}}).status_code, 422)
            response = client.post(path, headers=headers, json={'name': 'Test'})
            self.assertEqual(response.status_code, 202, response.text)
            self.assertEqual(response.json()['state'], 'queued')
            run_id = response.json()['id']
            self.assertEqual(client.get(f'/api/campaign-runs/{run_id}', headers={'Authorization': 'Bearer reviewer'}).status_code, 403)
            self.assertEqual(client.post(f'/api/campaign-runs/{run_id}/retry', headers={'Authorization': 'Bearer reviewer'}).status_code, 403)

    def test_asgi_lifespan_processes_jobs_without_extra_worker(self):
        with TestClient(create_app(self.service)) as client:
            headers = {'Authorization': 'Bearer admin', 'Idempotency-Key': 'lifespan'}
            response = client.post(f'/api/environments/{self.source}/campaign-runs', headers=headers, json={'name': 'Browser start'})
            self.assertEqual(response.status_code, 202)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                run = client.get('/api/campaign-runs/' + response.json()['id'], headers=headers).json()
                if run['state'] not in ('queued', 'scanning', 'validating', 'reviewing'):
                    break
                time.sleep(.1)
            self.assertEqual(run['state'], 'completed', run)

    def test_scan_failures_are_sanitized_retryable_and_do_not_supersede(self):
        old = self.service.create_campaign(self.payload, self.admin)
        with patch.object(self.connector, 'scan', side_effect=RuntimeError('secret-token-in-upstream-body')):
            run = self.run_job()
        self.assertEqual(run['state'], 'failed')
        self.assertTrue(run['can_retry'])
        self.assertNotIn('secret-token', json.dumps(run))
        self.assertIsNone(self.service.get_campaign(old['id'], self.admin)['superseded_by'])
        self.service.runs.retry(run['id'], self.admin)
        self.service.runs.tick()
        final = self.service.runs.get(run['id'], self.admin)
        self.assertEqual(final['state'], 'completed', final)
        self.assertEqual(final['attempts'], 2)

    def test_bad_evidence_blocks_without_campaign(self):
        original = self.connector.scan
        mutations = [lambda s: s.update(request_id='wrong'),
                     lambda s: s.update(source='wrong'),
                     lambda s: s.update(scanned_at=timestamp(self.now-timedelta(seconds=1))),
                     lambda s: s.update(complete=False),
                     lambda s: s.update(scanned_at=timestamp(self.now+timedelta(hours=1)))]
        for index, mutate in enumerate(mutations):
            def scan(source, request_id):
                result = original(source, request_id); mutate(result); return result
            with self.subTest(index=index), patch.object(self.connector, 'scan', side_effect=scan):
                run = self.run_job('bad-' + str(index))
                self.assertEqual(run['state'], 'blocked', run)
                self.assertFalse(run['can_retry'])
                self.assertIsNone(run['campaign_id'])
        self.assertEqual(self.service.list_campaigns(self.admin)['campaigns'], [])

    def test_wrong_mapping_and_invalid_correlations_block(self):
        self.env[self.source]['mapping_version'] = 'wrong'
        self.assertEqual(self.run_job('mapping')['state'], 'blocked')
        self.env[self.source].pop('mapping_version')
        self.docs['correlations'][0]['account_id'] = 'unknown-account'
        self.assertEqual(self.run_job('correlation')['state'], 'blocked')

    def test_stale_hr_and_external_ai_consent_block(self):
        self.now += timedelta(days=31)
        self.assertEqual(self.run_job('stale')['state'], 'blocked')
        self.now -= timedelta(days=31)
        for key in ('identities', 'policies'):
            self.docs[key]['synthetic'] = False
        with patch.object(self.service.reviewer, 'provider', 'external'):
            run = self.run_job('consent')
        self.assertEqual(run['state'], 'blocked')
        self.assertIn('approval', run['error'])

    def test_accepted_inventory_survives_review_failure_and_retry_reuses_it(self):
        run = self.start()
        with patch.object(self.service, 'create_campaign', side_effect=RuntimeError('provider failure')):
            self.service.runs.tick()
        saved = self.service.runs.get(run['id'], self.admin)
        self.assertTrue(saved['scan_id'])
        self.assertIsNotNone(self.service.runs.environments_view(self.admin)['sources'][0]['inventory'])
        self.service = self.make_service()
        with patch.object(self.connector, 'scan', side_effect=AssertionError('Must use pinned scan')):
            self.service.runs.retry(run['id'], self.admin)
            self.service.runs.tick()
        self.assertEqual(self.service.runs.get(run['id'], self.admin)['state'], 'completed')

    def test_lease_expiry_fences_old_worker_and_new_worker_recovers(self):
        run = self.start()
        run_id, token = self.service.runs.claim()
        self.assertIsNone(self.make_service().runs.claim())
        self.now += timedelta(seconds=31)
        self.service = self.make_service()
        replacement_id, replacement_token = self.service.runs.claim()
        self.assertEqual(replacement_id, run_id)
        with self.assertRaises(LeaseLost):
            self.service.runs.execute(run_id, token)
        self.service.runs.execute(replacement_id, replacement_token)
        self.assertEqual(self.service.runs.get(run['id'], self.admin)['state'], 'completed')

    def test_atomic_completion_survives_lost_return_after_campaign_commit(self):
        original = self.service.create_campaign
        def lost_response(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError('Process lost its response after transaction commit')
        with patch.object(self.service, 'create_campaign', side_effect=lost_response):
            run = self.run_job()
        self.assertEqual(run['state'], 'completed')
        self.service = self.make_service()
        self.assertFalse(self.service.runs.tick())
        self.assertEqual(self.start()['campaign_id'], run['campaign_id'])
        self.assertEqual(len(self.service.list_campaigns(self.admin)['campaigns']), 1)

    def test_maximum_recovery_attempts(self):
        run = self.start()
        for _ in range(3):
            self.assertIsNotNone(self.service.runs.claim())
            self.now += timedelta(seconds=31)
        self.assertIsNone(self.service.runs.claim())
        final = self.service.runs.get(run['id'], self.admin)
        self.assertEqual(final['state'], 'failed')
        self.assertFalse(final['can_retry'])

    def test_missing_setup_is_explicit_and_does_not_enqueue(self):
        self.env[self.source].pop('load_inputs')
        view = self.service.runs.environments_view(self.admin)['sources'][0]
        self.assertFalse(view['can_start'])
        self.assertTrue(view['setup_error'])
        with self.assertRaises(ServiceError):
            self.start()

    def test_synthetic_context_refresh_does_not_reset_source(self):
        (self.root/'demo-import.json').write_text(json.dumps(self.payload), encoding='utf-8')
        loader = SourceInputs(self.root, demo=True)
        later = loader(self.now + timedelta(days=45))
        self.assertNotEqual(later['identities']['snapshot_at'], self.docs['identities']['snapshot_at'])
        self.assertNotIn('scan', later)
        self.assertEqual(later['correlations'], self.docs['correlations'])
        self.assertEqual(json.loads((self.root/'demo-import.json').read_text()), self.payload)

    def test_legacy_windows_demo_context_encoding_is_supported(self):
        self.payload['name'] = 'Legacy demo · review'
        (self.root/'demo-import.json').write_bytes(json.dumps(self.payload, ensure_ascii=False).encode('cp1252'))
        self.assertEqual(SourceInputs(self.root, demo=True)(self.now)['correlations'], self.docs['correlations'])

    def test_additive_migration_preserves_campaign_inputs_and_audit(self):
        campaign = self.service.create_campaign(self.payload, self.admin)
        before = self.service.export(campaign['id'], self.admin)
        with self.service.store.transaction() as conn:
            conn.execute('UPDATE meta SET version=2')
        self.service = self.make_service()
        after = self.service.export(campaign['id'], self.admin)
        self.assertEqual(before, after)
        with self.service.store.read() as conn:
            self.assertEqual(conn.execute('SELECT version FROM meta').fetchone()[0], 3)

    def test_pinned_inputs_and_inventory_are_immutable(self):
        run = self.run_job()
        with self.service.store.transaction() as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE campaign_runs SET inputs_json='{}' WHERE id=?", (run['id'],))
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE inventory_snapshots SET scan_json='{}'")

    def test_legacy_import_cannot_supersede_while_run_is_active(self):
        self.start()
        with self.assertRaises(ServiceError) as got:
            self.service.create_campaign(self.payload, self.admin)
        self.assertEqual(got.exception.code, 'source_busy')

    def test_shutdown_fences_blocked_call_and_restart_recovers(self):
        run = self.start()
        entered, release = threading.Event(), threading.Event()
        original = self.connector.scan
        def blocked_scan(*args):
            entered.set()
            release.wait(10)
            return original(*args)
        worker = CampaignRunWorker(self.service.runs)
        with patch.object(self.connector, 'scan', side_effect=blocked_scan):
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                worker.close()
                self.assertFalse(worker.thread.is_alive())
                replacement = self.make_service()
                claim = replacement.runs.claim()
                self.assertIsNotNone(claim)
            finally:
                release.set()
                worker.close()
        replacement.runs.execute(*claim)
        self.assertEqual(replacement.runs.get(run['id'], self.admin)['state'], 'completed')
        self.assertEqual(len(replacement.list_campaigns(self.admin)['campaigns']), 1)

    def test_deadline_releases_worker_even_when_connector_is_stuck(self):
        run = self.start()
        entered, release = threading.Event(), threading.Event()
        def stuck(*args):
            entered.set()
            release.wait(10)
            raise RuntimeError('late failure')
        with patch.object(self.connector, 'scan', side_effect=stuck):
            thread = threading.Thread(target=self.service.runs.tick)
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                self.now += timedelta(seconds=1801)
                thread.join(3)
                self.assertFalse(thread.is_alive())
            finally:
                release.set()
                thread.join(5)
        self.service.runs.tick()
        self.assertEqual(self.service.runs.get(run['id'], self.admin)['state'], 'completed')

    def test_completion_failure_rolls_back_campaign_and_supersession(self):
        old = self.service.create_campaign(self.payload, self.admin)
        with patch.object(self.service.runs, 'finish', side_effect=RuntimeError('commit failure')):
            run = self.run_job()
        self.assertEqual(run['state'], 'failed')
        self.assertEqual(len(self.service.list_campaigns(self.admin)['campaigns']), 1)
        self.assertIsNone(self.service.get_campaign(old['id'], self.admin)['superseded_by'])
        self.service.runs.retry(run['id'], self.admin)
        self.service.runs.tick()
        self.assertEqual(self.service.runs.get(run['id'], self.admin)['state'], 'completed')

    def test_retry_blocks_expired_accepted_scan_without_replacing_it(self):
        with patch.object(self.service, 'create_campaign', side_effect=RuntimeError('interrupted')):
            run = self.run_job()
        self.now += timedelta(hours=25)
        self.service.runs.retry(run['id'], self.admin)
        with patch.object(self.connector, 'scan', side_effect=AssertionError('No replacement evidence')):
            self.service.runs.tick()
        final = self.service.runs.get(run['id'], self.admin)
        self.assertEqual(final['state'], 'blocked')
        self.assertEqual(final['scan_id'], run['scan_id'])
        self.assertIsNone(final['campaign_id'])

    def test_long_review_cannot_commit_expired_evidence(self):
        original = self.service._review_cases
        def reviewed(*args):
            result = original(*args)
            # Keep the lease valid but make the HR freshness boundary pass.
            self.now += timedelta(seconds=1)
            return result
        from iga_review.domain import EngineConfig
        self.service.config = EngineConfig(max_scan_age_hours=0.0001)
        with patch.object(self.service, '_review_cases', side_effect=reviewed):
            run = self.run_job()
        self.assertEqual(run['state'], 'blocked')
        self.assertIsNone(run['campaign_id'])

    def test_new_run_observes_prior_removal_and_preserves_history(self):
        first = self.run_job()
        before = self.service.export(first['campaign_id'], self.admin)['inputs']
        campaign = self.service.get_campaign(first['campaign_id'], self.admin)
        finding = next(f for f in campaign['findings'] if f['account_id'] == 'acct:person-0005'
                       and f['entitlement_id'] == 'ent:engineering:production-deploy')
        decision = self.service.decide(finding['id'], self.admin,
            {'action': 'revoke', 'reason': 'Remove verified excess access', 'expected_version': finding['version'],
             'acknowledge_risk': True}, 'remove-approved')
        self.now += timedelta(seconds=1)
        self.assertEqual(self.service._work(decision['request_id'])['state'], 'verified')
        self.now += timedelta(seconds=1)
        second = self.run_job('second')
        after = self.service.export(second['campaign_id'], self.admin)['inputs']
        self.assertNotEqual(before['scan']['scan_id'], after['scan']['scan_id'])
        self.assertFalse(any(a['identity'] == finding['account_id'] and a['entitlement'] == finding['entitlement_id']
                             for a in after['scan']['assignments']))
        self.assertEqual(self.service.export(first['campaign_id'], self.admin)['inputs'], before)

    def test_newer_legacy_import_is_last_known_inventory(self):
        first = self.run_job()
        self.now += timedelta(seconds=2)
        payload = deepcopy(self.payload)
        payload['scan'] = self.connector.scan(self.source, 'manual-import')
        self.service.create_campaign(payload, self.admin)
        env = self.service.runs.environments_view(self.admin)['sources'][0]
        self.assertEqual(env['inventory']['scan_id'], payload['scan']['scan_id'])
        self.assertNotEqual(env['inventory']['scan_id'], first['scan_id'])

    def test_linux_binding_username_and_uid_are_both_checked(self):
        from types import SimpleNamespace
        from iga_review.source_inputs import validate_binding_evidence
        from iga_review.domain import InputError
        scan = SimpleNamespace(source='linux', identities=[SimpleNamespace(id='linux:uid:1001', username='alice')])
        for evidence in ['POSIX account bob (uid 1001)', 'POSIX account alice (uid 1002)', 'No evidence']:
            with self.subTest(evidence=evidence), self.assertRaises(InputError):
                validate_binding_evidence(scan, [{'account_id': 'linux:uid:1001', 'evidence': evidence}], 'linux-posix')
        validate_binding_evidence(scan, [{'account_id': 'linux:uid:1001', 'evidence': 'POSIX account alice (uid 1001)'}], 'linux-posix')

    def test_reused_scan_id_and_invalid_scope_block(self):
        first = self.run_job()
        original = self.connector.scan
        for key in ('reuse', 'scope'):
            def invalid(*args):
                scan = original(*args)
                if key == 'reuse':
                    scan['scan_id'] = first['scan_id']
                else:
                    scan['scope_entitlements'] = []
                return scan
            with patch.object(self.connector, 'scan', side_effect=invalid):
                run = self.run_job(key)
            self.assertEqual(run['state'], 'blocked')
            self.assertIsNone(self.service.get_campaign(first['campaign_id'], self.admin)['superseded_by'])

    def test_expired_remediation_lease_must_recover_before_start(self):
        campaign = self.service.create_campaign(self.payload, self.admin)
        finding = next(f for f in campaign['findings'] if f['account_id'] == 'acct:person-0005'
                       and f['entitlement_id'] == 'ent:engineering:production-deploy')
        decision = self.service.decide(finding['id'], self.admin,
            {'action': 'revoke', 'reason': 'Remove verified excess access', 'expected_version': finding['version'],
             'acknowledge_risk': True}, 'remove-approved')
        with self.service.store.transaction() as conn:
            conn.execute("UPDATE requests SET state='dispatching',lease_until=? WHERE id=?",
                         (timestamp(self.now - timedelta(seconds=1)), decision['request_id']))
        with self.assertRaises(ServiceError) as got:
            self.start()
        self.assertEqual(got.exception.code, 'source_busy')
        self.now += timedelta(seconds=1)
        self.assertEqual(self.service._work(decision['request_id'])['state'], 'verified')
        self.assertEqual(self.run_job()['state'], 'completed')


if __name__ == '__main__':
    unittest.main()
