"""A recovered request must reject results from the worker it replaced."""
from datetime import timedelta
from unittest.mock import patch

from test_workflow import Case


class RemediationRecoveryTests(Case):
    def test_late_dispatch_success_or_failure_cannot_overwrite_recovered_result(self):
        for late_failure in (False, True):
            with self.subTest(late_failure=late_failure):
                # Each subcase needs its own approved request and fixture.
                self.setUp()
                request_id = self.decide()['request_id']
                original = self.connector.revoke
                calls, recovered = [], []

                def delayed(request):
                    calls.append(request['request_id'])
                    response = original(request)
                    if len(calls) == 1:
                        self.now += timedelta(seconds=121)
                        result = self.make_service()._work(request_id)
                        self.assertEqual(result['state'], 'verified')
                        recovered.append(self.export())
                        if late_failure:
                            raise RuntimeError('Old worker returned a late error')
                    return response

                with patch.object(self.connector, 'revoke', side_effect=delayed):
                    self.service._work(request_id)
                self.assertEqual(self.export(), recovered[0])
                self.assertEqual(calls, [request_id, request_id])

    def test_late_verification_cannot_replace_newer_verified_evidence(self):
        request_id = self.decide()['request_id']
        original = self.connector.scan
        calls, recovered = [], []

        def delayed(source, scan_id):
            calls.append(scan_id)
            snapshot = original(source, scan_id)
            if len(calls) == 1:
                self.now += timedelta(seconds=121)
                result = self.make_service()._work(request_id)
                self.assertEqual(result['state'], 'verified')
                recovered.append(self.export())
            return snapshot

        with patch.object(self.connector, 'scan', side_effect=delayed):
            self.service._work(request_id)
        self.assertEqual(self.export(), recovered[0])

    def test_expired_worker_cannot_commit_even_before_another_claim(self):
        request_id = self.decide()['request_id']
        original = self.connector.revoke

        def delayed(request):
            response = original(request)
            self.now += timedelta(seconds=121)
            return response

        with patch.object(self.connector, 'revoke', side_effect=delayed):
            result = self.service._work(request_id)
        self.assertTrue(result['busy'])
        self.assertEqual(self.export()['requests'][0]['state'], 'dispatching')
        self.assertEqual(self.make_service()._work(request_id)['state'], 'verified')

    def test_schema_upgrade_preserves_approval_and_audit(self):
        request_id = self.decide()['request_id']
        before = self.export()
        with self.service.store.transaction() as conn:
            columns = {row['name'] for row in conn.execute('PRAGMA table_info(requests)')}
            if 'lease_token' in columns:
                conn.execute('ALTER TABLE requests DROP COLUMN lease_token')
            conn.execute('UPDATE meta SET version=3')
        restored = self.make_service()
        self.assertEqual(restored.export(self.campaign['id'], self.admin), before)
        self.assertEqual(restored._work(request_id)['state'], 'verified')
