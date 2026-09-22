"""Independent AI case-review tests; HTTP is mocked."""
import copy
import json
import unittest

import httpx

from iga_review.explanations import OpenAIReviewer, RuleReviewer


def case():
    item = {'key': 'item-key', 'kind': 'assignment', 'policy_result': 'restricted',
            'privileged': True, 'policy_fact': {'code': 'restricted', 'rule_id': 'policy:engineer',
                                               'text': 'Deployment is restricted.'},
            'constraints': [{'code': 'hard_policy_remove', 'effect': 'non_discretionary',
                             'required_action': 'remove', 'text': 'Deployment is restricted.'}]}
    return {'key': 'case-key',
            'identity_context': {'identity': {'id': 'id:person', 'name': 'PRIVATE PERSON'},
                                 'role_policy': {'id': 'policy:engineer'}},
            'accounts': [{'id': 'acct:person', 'username': 'PRIVATE LOGIN'}],
            'applications': [{'id': 'app:engineering', 'name': 'Engineering'}],
            'items': [item], 'assignments': [{'id': 'assignment:one',
                                              'business_justification': 'Emergency release coverage.'}],
            'grant_paths': [{'id': 'path:one', 'path': [{'kind': 'account', 'ref': 'acct:person'},
                                                        {'kind': 'entitlement', 'ref': 'ent:deploy'}]}],
            'exceptions': [], 'history': [], 'relevant_entitlements': [], 'warnings': [],
            'evidence_refs': ['identity:id:person', 'account:acct:person', 'item:item-key', 'path:path:one']}


def assessment(**changes):
    result = {'recommended_action': 'retain', 'confidence': 0.86,
              'evidence_refs': ['item:item-key', 'path:path:one'],
              'open_questions': ['Confirm the exception owner.'], 'missing_evidence': [],
              'reasoning': 'The recorded emergency justification supports temporary retention.',
              'item_assessments': [{'item_key': 'item-key', 'action': 'retain',
                                    'evidence_refs': ['item:item-key', 'path:path:one'],
                                    'reasoning': 'The time-bound context warrants retention.'}]}
    result.update(changes)
    return result


def response(result=None, **changes):
    body = {'status': 'completed', 'output': [{'type': 'message', 'role': 'assistant',
            'content': [{'type': 'output_text', 'text': json.dumps(result or assessment())}]}]}
    body.update(changes)
    return body


class ReviewerTests(unittest.TestCase):
    def client(self, handler):
        value = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
        self.addCleanup(value.close)
        return value

    def run_review(self, body, value=None, status=200):
        client = self.client(lambda request: httpx.Response(status, json=body))
        return OpenAIReviewer('test-key', 'test-model', client).review(value or case())

    def test_ai_can_independently_disagree_with_hard_policy(self):
        original = case()
        before = copy.deepcopy(original)
        result = self.run_review(response(), original)
        self.assertEqual(result['provider'], 'openai')
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(result['recommended_action'], 'retain')
        self.assertEqual(result['item_assessments'][0]['action'], 'retain')
        self.assertEqual(original, before)

    def test_full_case_evidence_is_sent_without_tools_or_storage(self):
        def handler(request):
            payload = json.loads(request.content)
            evidence = json.loads(payload['input'][0]['content'])
            self.assertEqual(evidence['identity_context']['identity']['name'], 'PRIVATE PERSON')
            self.assertEqual(evidence['grant_paths'][0]['id'], 'path:one')
            self.assertEqual(evidence['assignments'][0]['business_justification'], 'Emergency release coverage.')
            self.assertNotIn('tools', payload)
            self.assertIs(payload['store'], False)
            self.assertEqual(str(request.url), 'https://api.openai.com/v1/responses')
            return httpx.Response(200, json=response())
        result = OpenAIReviewer('test-key', 'test-model', self.client(handler)).review(case())
        self.assertEqual(result['status'], 'ready')

    def test_unconfigured_provider_is_explicit_fallback(self):
        fallback = OpenAIReviewer(None, None).review(case())
        self.assertEqual(fallback['provider'], 'rules')
        self.assertEqual(fallback['status'], 'fallback')
        self.assertEqual(fallback['fallback_reason'], 'not_configured')
        self.assertEqual(fallback['confidence'], 0.0)
        self.assertEqual(fallback['missing_evidence'], [])

    def test_rule_fallback_obeys_non_discretionary_constraint(self):
        result = RuleReviewer().review(case())
        self.assertEqual(result['item_assessments'][0]['action'], 'remove')
        self.assertNotIn('recommendation', case()['items'][0])

    def test_invalid_item_coverage_and_evidence_references_fall_back(self):
        bad = assessment(item_assessments=[])
        self.assertEqual(self.run_review(response(bad))['fallback_reason'], 'invalid_response')
        bad = assessment(evidence_refs=['invented:reference'])
        self.assertEqual(self.run_review(response(bad))['fallback_reason'], 'invalid_response')

    def test_refusal_incomplete_http_and_malformed_output_fall_back(self):
        refusal = response()
        refusal['output'][0]['content'] = [{'type': 'refusal', 'refusal': 'secret'}]
        self.assertEqual(self.run_review(refusal)['fallback_reason'], 'refused')
        self.assertEqual(self.run_review(response(status='incomplete'))['fallback_reason'], 'incomplete_response')
        self.assertEqual(self.run_review({'error': 'secret'}, status=500)['fallback_reason'], 'request_failed')
        malformed = response()
        malformed['output'][0]['content'][0]['text'] = 'not json'
        self.assertEqual(self.run_review(malformed)['fallback_reason'], 'invalid_response')

    def test_redirect_is_not_followed(self):
        calls = []
        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(307, headers={'Location': 'https://example.invalid/steal'})
        result = OpenAIReviewer('test-key', 'test-model', self.client(handler)).review(case())
        self.assertEqual(result['fallback_reason'], 'request_failed')
        self.assertEqual(calls, ['https://api.openai.com/v1/responses'])


if __name__ == '__main__':
    unittest.main()
