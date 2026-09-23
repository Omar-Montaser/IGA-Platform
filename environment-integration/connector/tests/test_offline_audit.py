"""Read-only fixture and real loopback HTTP acceptance; never changes Linux."""
import ast
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'environment-integration/connector/src'))

import httpx
from fastapi.testclient import TestClient
import uvicorn
from iga_connector import api, discovery, normalize, remediation
from iga_connector.transport import FixtureTransport, from_env
from iga_hr import validate_documents
from iga_review.api import create_app
from iga_review.connector import HTTPConnector
from iga_review.domain import Correlation, Scan, User
from iga_review.engine import evaluate
from iga_review.service import ReviewService

SAMPLES = ROOT/'environment-integration/samples'
HR = ROOT/'governance-platform/hr-policy/data'
NOW = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)
TOKEN = 'offline-audit-test-token'


def load(name):
    return json.loads((SAMPLES/name).read_text(encoding='utf-8'))


def lab_planning():
    """Compile only pure planning/classification functions, not Linux imports or commands."""
    tree = ast.parse((ROOT/'environment-integration/linux-lab/lab.py').read_text(encoding='utf-8'))
    functions = {'native_group_name', 'build_mapping', 'plan', 'classify'}
    constants = {'SUDO_PREFIX', 'SUDO_ENTITLEMENT', 'EXTRA_GRANTS', 'LIFECYCLE_LEFTOVERS',
                 'EARLY_PROVISIONED', 'PROPERLY_DEPROVISIONED', 'EXTRA_GRANTS_B', 'LIFECYCLE_LEFTOVERS_B',
                 'EARLY_PROVISIONED_B', 'PROPERLY_DEPROVISIONED_B', 'SCENARIOS'}
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in functions or
             isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in n.targets)]
    namespace = {'sys': sys}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'lab_planning_only', 'exec'), namespace)
    return namespace


class ConnectorAuditTests(unittest.TestCase):
    def setUp(self):
        self.mapping = normalize.Mapping(load('entitlement_map.json'))
        self.transport = FixtureTransport(str(SAMPLES))
        self.accounts = discovery.discover(self.transport, self.mapping.managed_groups)
        self.scan = normalize.build_scan(self.accounts, self.mapping, source='linux-lab', now=NOW,
                                         service_accounts=['iga_svc'])

    def test_fixture_scan_validates_without_inventing_grant_times_or_classification(self):
        Scan.model_validate(self.scan)
        self.assertEqual(len(self.scan['assignments']), 374)
        self.assertEqual(len(self.scan['grant_paths']), 374)
        self.assertTrue(all(row['timestamp'] is None for row in self.scan['assignments']))
        self.assertTrue(all(row['privileged'] is None for row in self.scan['groups']))

    def test_all_captured_access_matches_module2_policy_truth_in_module4(self):
        identities = json.loads((HR/'identities.json').read_text(encoding='utf-8'))
        policies = json.loads((HR/'policies.json').read_text(encoding='utf-8'))
        plan = lab_planning()
        # Captured samples are from scenario B (69 accounts, 374 assignments)
        accounts, _, catalog, profiles, statuses = plan['plan'](identities, policies, scenario='b')
        truth = {(a['username'], eid): plan['classify'](a, eid, profiles, statuses, catalog)[0]
                 for a in accounts for eid in a['entitlements']}
        correlations = [Correlation.model_validate(row) for row in load('correlations.json')['correlations']]
        result = evaluate(validate_documents(identities, policies), Scan.model_validate(self.scan), correlations, now=NOW)
        actual = {(f['username'], f['entitlement_id']): f['policy_result'] for f in result['findings'] if f['kind'] == 'assignment'}
        self.assertEqual(actual, truth)
        # Scenario B counts - will verify actual distribution
        counts = Counter(actual.values())
        self.assertGreater(counts['expected'], 300)
        self.assertGreater(counts.get('lifecycle_restricted', 0), 30)
        self.assertEqual(sum(counts.values()), 374)
        self.assertFalse(any(s['code'] == 'catalog_mismatch' for f in result['findings'] for s in f['signals']))

    def test_fixture_key_lookup_returns_exact_account_not_first_passwd_row(self):
        account = self.accounts[-1]
        self.assertEqual(remediation._username_for(self.transport, account.uid), account.username)

    def test_malformed_and_ambiguous_native_records_fail_closed(self):
        for raw in ('bad:row', 'alice:x:1000:not-a-gid:A:/home/a:/bin/bash',
                    'alice:x:1000:1000:A:/a:/bin/bash\nbob:x:1000:1001:B:/b:/bin/bash'):
            with self.assertRaises(discovery.DiscoveryError):
                discovery.parse_passwd(raw)
        for raw in ('bad:row', 'g:x:1000:a\nh:x:1000:b'):
            with self.assertRaises(discovery.DiscoveryError):
                discovery.parse_group(raw)

    def test_partial_native_enumeration_is_not_complete(self):
        class Partial:
            def run(self, args):
                return 2, 'g:x:1000:a', ''
        with self.assertRaises(discovery.DiscoveryError):
            discovery.discover(Partial(), [])

    def test_sudo_capture_errors_are_not_silently_absence(self):
        for payload in ([], {'alice': '<unreadable>'}, {'alice': ['<unreadable: denied>']}):
            with patch.object(self.transport, 'run', return_value=(0, json.dumps(payload), '')):
                with self.assertRaises(discovery.DiscoveryError):
                    discovery._sudo_grants(self.transport)

    def test_ambiguous_native_mapping_is_rejected(self):
        value = load('entitlement_map.json')
        first = next(iter(value['entitlements'].values()))
        value['entitlements']['ent:duplicate'] = deepcopy(first)
        with self.assertRaises(ValueError):
            normalize.Mapping(value)

    def test_helper_exit_code_cannot_claim_success(self):
        with patch.object(self.transport, 'run', return_value=(1, '{"ok": true}', '')):
            with self.assertRaises(remediation.RemediationError):
                remediation._call(self.transport, ['remove-group', 'alice', 'g'])

    def test_fixture_missing_sudo_capture_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            for filename in ('passwd', 'group'):
                Path(directory, filename).write_bytes((SAMPLES/filename).read_bytes())
            with self.assertRaises(discovery.DiscoveryError):
                discovery.discover(FixtureTransport(directory), [])

    def test_empty_explicit_environment_does_not_inherit_host_transport(self):
        with patch.dict('os.environ', {'IGA_TRANSPORT': 'invalid'}):
            self.assertEqual(from_env({}).describe(), 'local')


class ConnectorAPIAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        setting = patch.multiple(api, MAP_PATH=str(SAMPLES/'entitlement_map.json'), SOURCE='linux-lab',
                                 STATE_PATH=str(self.root/'state.db'), TOKEN_HASH=hashlib.sha256(TOKEN.encode()).hexdigest())
        setting.start(); self.addCleanup(setting.stop)
        link = patch.object(api.tp, 'from_env', side_effect=lambda: FixtureTransport(str(SAMPLES)))
        self.factory = link.start(); self.addCleanup(link.stop)
        self.client = TestClient(api.app)
        self.addCleanup(self.client.close)
        self.headers = {'Authorization': f'Bearer {TOKEN}'}

    def test_authentication_and_strict_request_validation(self):
        self.assertEqual(self.client.post('/scans', json={}).status_code, 401)
        for payload in ({'request_id': 'x'}, {'request_id': ['invalid']},
                        {'request_id': 'x', 'assignment_ids': [], 'grant_path_ids': []}):
            self.assertEqual(self.client.post('/revocations', json=payload, headers=self.headers).status_code, 422)
        self.assertFalse(self.factory.called)
        self.assertEqual(self.client.post('/scans', json={'source': 'linux-lab', 'request_id': 42}, headers=self.headers).status_code, 422)

    def test_malformed_mapping_fails_before_native_access(self):
        base = load('entitlement_map.json')
        malformed = [[], {}, {**base, 'source': 42}, {**base, 'entitlements': []},
                     {**base, 'entitlements': {'ent:test': None}},
                     {**base, 'entitlements': {'ent:test': {'native_type': 'sudo', 'native_id': []}}}]
        for document in malformed:
            with self.subTest(document=document), patch.object(api.json, 'load', return_value=document):
                response = self.client.post('/scans', json={'source': 'linux-lab'}, headers=self.headers)
                self.assertEqual(response.status_code, 503)
        self.assertFalse(self.factory.called)

    def test_fixture_removal_refusal_is_idempotent_and_never_changes_capture(self):
        before = (SAMPLES/'group').read_bytes()
        scan = self.client.post('/scans', json={'source': 'linux-lab'}, headers=self.headers).json()
        target = scan['assignments'][0]
        request = {'request_id': 'audit-request', 'source': 'linux-lab', 'identity': target['identity'],
                   'entitlement': target['entitlement'], 'approved_by': 'test-reviewer',
                   'approved_at': scan['scanned_at'], 'reason': 'Synthetic fixture test only.',
                   'scan_id': scan['scan_id'], 'mapping_version': scan['mapping_version'],
                   'assignment_ids': [target['id']], 'grant_path_ids': target['grant_path_ids']}
        headers = {**self.headers, 'Idempotency-Key': request['request_id']}
        first = self.client.post('/revocations', json=request, headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()['status'], 'failed')
        self.assertIn('fixture_is_read_only', first.json()['message'])
        self.assertEqual(self.client.post('/revocations', json=request, headers=headers).json(), first.json())
        request['reason'] = 'Different approval.'
        self.assertEqual(self.client.post('/revocations', json=request, headers=headers).status_code, 409)
        self.assertEqual((SAMPLES/'group').read_bytes(), before)

    def test_real_loopback_http_module3_to_module4_import_and_audit(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(api.app, log_level='error'))
        thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(server.started, 'Loopback connector did not start')
            with httpx.Client(trust_env=False) as client:
                connector = HTTPConnector(f'http://127.0.0.1:{port}', TOKEN, client=client)
                scan = connector.scan('linux-lab', 'audit:scan')
                Scan.model_validate(scan)
                payload = {'name': 'Offline captured Linux review', 'scan': scan,
                           'identities': json.loads((HR/'identities.json').read_text(encoding='utf-8')),
                           'policies': json.loads((HR/'policies.json').read_text(encoding='utf-8')),
                           'correlations': load('correlations.json')['correlations']}
                admin = User('audit-admin', 'Synthetic administrator', 'admin', None,
                             hashlib.sha256(b'ui-audit-test-token').hexdigest())
                service = ReviewService(self.root/'review.db', [admin], fallback_reviewer_id=admin.id,
                                        connectors={'linux-lab': connector})
                with TestClient(create_app(service)) as app:
                    auth = {'Authorization': 'Bearer ui-audit-test-token'}
                    result = app.post('/api/campaigns', json=payload, headers=auth)
                    self.assertEqual(result.status_code, 201, result.text[:200])
                    campaign = result.json()
                    self.assertEqual(sum(f['kind'] == 'assignment' for f in campaign['findings']), 374)
                    exported = app.get(f'/api/campaigns/{campaign["id"]}/export', headers=auth).json()
                    self.assertTrue(exported['audit']['integrity'])
                    self.assertEqual(exported['decisions'], [])
                    self.assertEqual(exported['requests'], [])
                    self.assertEqual(app.get('/').status_code, 200)
                    self.assertEqual(app.get('/static/app.js').status_code, 200)
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            listener.close()
            self.assertFalse(thread.is_alive(), 'Loopback server failed to stop')
