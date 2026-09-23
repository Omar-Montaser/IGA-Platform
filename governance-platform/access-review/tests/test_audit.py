"""Regression tests for the cross-module governance and AI safety audit."""
from copy import deepcopy
import json
import unittest

import httpx
from pydantic import ValidationError

from iga_review.ai import GroqReviewer, configured_reviewer
from iga_review.domain import Scan
from iga_review.service import ReviewService, ServiceError
from test_explanations import assessment, case
from test_workflow import Case


class GovernanceAuditTests(Case):
    def test_unresolved_ownership_is_blocked_by_service_not_only_prompt(self):
        payload = deepcopy(self.payload)
        payload['correlations'] = [c for c in payload['correlations'] if c['account_id'] != self.target['account_id']]
        campaign = self.service.create_campaign(payload, self.admin)
        target = next(f for f in campaign['findings'] if f['account_id'] == self.target['account_id'] and f['entitlement_id'] == self.target['entitlement_id'])
        self.assertFalse(target['can_decide'])
        self.assertEqual(target['allowed_actions'], [])
        for action in ('certify', 'revoke'):
            self.error(403, lambda: self.decide(item=target, action=action, acknowledge_risk=True))
        self.assertEqual(self.service.export(campaign['id'], self.admin)['requests'], [])

    def test_hard_constraint_is_reflected_in_available_actions(self):
        self.assertEqual(self.target['allowed_actions'], ['revoke'])
        self.error(422, lambda: self.decide(action='certify', acknowledge_risk=True))

    def test_mandatory_review_requires_explicit_risk_acknowledgement_even_when_ai_says_retain(self):
        target = next(f for f in self.campaign['findings'] if f['policy_result'] == 'expected')
        self.assertEqual(target['recommendation'], 'certify')
        self.assertTrue(target['mandatory_human_review'])
        self.error(422, lambda: self.decide(item=target, action='certify'))
        self.assertEqual(self.decide(item=target, action='certify', acknowledge_risk=True)['action'], 'certify')

    def test_real_data_cannot_leave_demo_or_direct_service_without_consent(self):
        class Spy:
            provider = 'gemini'
            calls = 0
            def review(self, case):
                self.calls += 1
                raise AssertionError('Must not send employee data')
        reviewer = Spy()
        service = ReviewService(self.root/'privacy.db', self.users, fallback_reviewer_id='admin',
                                explainer=reviewer, clock=lambda: self.now, demo=True)
        payload = deepcopy(self.payload)
        payload['identities']['synthetic'] = payload['policies']['synthetic'] = False
        with self.assertRaises(ServiceError) as got:
            service.create_campaign(payload, self.admin)
        self.assertEqual(got.exception.code, 'ai_data_consent_required')
        self.assertEqual(reviewer.calls, 0)
        self.assertEqual(service.list_campaigns(self.admin)['campaigns'], [])

    def test_null_grant_dates_and_group_classification_are_preserved(self):
        payload = deepcopy(self.payload)
        payload['scan']['scan_id'] = 'scan:unknown-evidence'
        for row in payload['scan']['assignments']:
            row['timestamp'] = None
        for row in payload['scan']['groups']:
            row['privileged'] = None
        campaign = self.service.create_campaign(payload, self.admin)
        target = next(f for f in campaign['findings'] if f['key'] == self.target['key'])
        self.assertIn('evidence_gaps', target['human_review_reasons'])
        self.assertTrue(any('Grant time is unknown' in gap for gap in target['evidence_gaps']))
        self.assertTrue(all(a['timestamp'] is None for a in target['review_evidence']['assignments']))
        self.assertEqual({a['id'] for a in target['review_evidence']['assignments']}, set(target['assignment_ids']))

    def test_orphan_and_cyclic_paths_cannot_hide_access(self):
        scan = deepcopy(self.payload['scan'])
        scan['assignments'].pop()
        with self.assertRaisesRegex(ValidationError, 'Every observed grant path'):
            Scan.model_validate(scan)
        scan = deepcopy(self.payload['scan'])
        path = scan['grant_paths'][0]
        path['path'].insert(1, deepcopy(path['path'][0]))
        path['grant_type'] = 'inherited'
        with self.assertRaisesRegex(ValidationError, 'Intermediate grant nodes'):
            Scan.model_validate(scan)


class GroqAuditTests(unittest.TestCase):
    def review(self, body, status=200, observer=None):
        def handler(request):
            if observer:
                observer(request)
            return httpx.Response(status, json=body)
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return GroqReviewer('synthetic-test-key', client=client, interval=0).review(case())

    def body(self, **changes):
        choice = {'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': json.dumps(assessment())}}
        choice.update(changes)
        return {'choices': [choice]}

    def test_llama_uses_supported_json_mode_and_local_validation(self):
        def check(request):
            payload = json.loads(request.content)
            self.assertEqual(payload['response_format'], {'type': 'json_object'})
            self.assertIn('item_assessments', payload['messages'][0]['content'])
            self.assertEqual(json.loads(payload['messages'][1]['content']), case())
            self.assertEqual(request.headers['authorization'], 'Bearer synthetic-test-key')
            self.assertEqual(str(request.url), 'https://api.groq.com/openai/v1/chat/completions')
        self.assertEqual(self.review(self.body(), observer=check)['status'], 'ready')

    def test_truncation_refusal_and_tool_output_are_rejected(self):
        for reason in ('length', 'content_filter', 'tool_calls', None):
            self.assertEqual(self.review(self.body(finish_reason=reason))['status'], 'fallback')
        for extra in ({'refusal': 'No'}, {'tool_calls': [{'name': 'revoke'}]}, {'function_call': {'name': 'revoke'}}):
            body = self.body()
            body['choices'][0]['message'].update(extra)
            self.assertEqual(self.review(body)['status'], 'fallback')

    def test_wrong_item_evidence_cannot_pass_shared_validator(self):
        body = self.body()
        result = assessment()
        result['item_assessments'][0]['evidence_refs'] = ['path:path:one']
        body['choices'][0]['message']['content'] = json.dumps(result)
        self.assertEqual(self.review(body)['fallback_reason'], 'invalid_response')

    def test_quota_cooldown_prevents_repeat_calls_and_paid_fallback(self):
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(429)
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            reviewer = GroqReviewer('synthetic-test-key', client=client, interval=0)
            for _ in range(3):
                self.assertEqual(reviewer.review(case())['fallback_reason'], 'rate_limited')
        self.assertEqual(len(requests), 1)
        self.assertEqual(configured_reviewer({'IGA_AI_PROVIDER': 'groq', 'GROQ_API_KEY': 'test'}).provider, 'groq')

    def test_groq_response_body_is_bounded(self):
        with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b'x' * 131073))) as client:
            self.assertEqual(GroqReviewer('test', client=client, interval=0).review(case())['status'], 'fallback')
