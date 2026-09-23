"""Fresh campaign orchestration over real loopback HTTP and read-only captures."""
import hashlib
import json
import socket
import threading
import time
import unittest
from unittest.mock import patch

import httpx
import uvicorn
from fastapi.testclient import TestClient
import test_offline_audit as fixtures
from test_offline_audit import HR, NOW, TOKEN, api, normalize, load
from iga_review.api import create_app
from iga_review.connector import HTTPConnector
from iga_review.domain import User
from iga_review.service import ReviewService


class CampaignStartHTTPTests(unittest.TestCase):
    setUp = fixtures.ConnectorAPIAuditTests.setUp

    def test_backend_start_scans_connector_and_creates_review(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        server = uvicorn.Server(uvicorn.Config(api.app, log_level='error'))
        thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(server.started)
            docs = {'identities': json.loads((HR/'identities.json').read_text()),
                    'policies': json.loads((HR/'policies.json').read_text()),
                    'correlations': load('correlations.json')['correlations']}
            admin = User('admin', 'Admin', 'admin', None, hashlib.sha256(b'test-admin').hexdigest())
            with httpx.Client(trust_env=False) as http:
                connector = HTTPConnector(f'http://127.0.0.1:{listener.getsockname()[1]}', TOKEN, client=http)
                service = ReviewService(self.root/'review.db', [admin], fallback_reviewer_id='admin',
                    connectors={'linux-lab': connector}, clock=lambda: NOW,
                    environments={'linux-lab': {'mode': 'captured_fixture', 'correlation_mode': 'linux-posix',
                                                'load_inputs': lambda now: docs}})
                with TestClient(create_app(service, run_campaign_worker=False)) as client:
                    auth = {'Authorization': 'Bearer test-admin', 'Idempotency-Key': 'http-start'}
                    env = client.get('/api/environments', headers=auth).json()['sources'][0]
                    self.assertEqual(env['status'], 'never_scanned')
                    self.factory.assert_not_called()
                    started = client.post('/api/environments/linux-lab/campaign-runs', headers=auth,
                                          json={'name': 'Fresh captured Linux review'})
                    self.assertEqual(started.status_code, 202, started.text)
                    with patch.object(normalize, '_now', return_value=NOW):
                        service.runs.tick()
                    run = client.get('/api/campaign-runs/' + started.json()['id'], headers=auth).json()
                    self.assertEqual(run['state'], 'completed', run)
                    exported = client.get('/api/campaigns/' + run['campaign_id'] + '/export', headers=auth).json()
                    self.assertEqual(exported['inputs']['scan']['source'], 'linux-lab')
                    self.assertTrue(exported['inputs']['scan']['request_id'].startswith('campaign-scan:'))
                    self.assertTrue(exported['audit']['integrity'])
                    self.assertEqual(exported['requests'], [])
                    self.assertEqual(exported['decisions'], [])
                    # Metadata polling does not trigger further native discovery.
                    count = self.factory.call_count
                    view = client.get('/api/environments', headers=auth).json()['sources'][0]
                    self.assertEqual(self.factory.call_count, count)
                    self.assertEqual(view['inventory']['scan_id'], run['scan_id'])
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            listener.close()
            self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
