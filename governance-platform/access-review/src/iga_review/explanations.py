"""Evidence explanations; neither provider can decide or remediate access.

Responses format reference:
https://developers.openai.com/api/docs/guides/structured-outputs
"""

import json
import math
import re
import unicodedata

import httpx


_ENDPOINT = 'https://api.openai.com/v1/responses'
_TIMEOUT = 10.0
_MAX_RESPONSE_BYTES = 64 * 1024
_POLICY_RESULTS = frozenset({
    'expected', 'permitted_privileged', 'restricted', 'lifecycle_restricted',
    'unauthorized_privilege', 'unlisted', 'unknown_entitlement', 'unmatched',
    'ambiguous', 'missing_expected', 'coverage_gap',
})
_SIGNAL_CODES = _POLICY_RESULTS | {
    'catalog_mismatch', 'sensitivity', 'privileged', 'disabled_account_grants',
    'peer_rare',
}
_ENUMS = {
    'kind': {'assignment', 'missing_access', 'account', 'coverage'},
    'policy_result': _POLICY_RESULTS,
    'recommendation': {'certify', 'review', 'revoke', 'acknowledge'},
    'risk_level': {'low', 'medium', 'high', 'critical'},
    'sensitivity': {'unknown', 'low', 'medium', 'high', 'critical'},
    'employment_status': {'active', 'on_leave', 'pre_hire', 'terminated', 'unknown'},
}
_INSTRUCTIONS = (
    'Explain only the supplied access-review evidence in at most three concise '
    'sentences. The risk score is a project heuristic, not a probability. '
    'Lifecycle and explicit policy restrictions take precedence over peer '
    'frequency. Peer rarity is not by itself a policy violation. Missing expected '
    'access is a review signal, never an instruction to provision it. Unknown or '
    'ambiguous ownership needs resolution. Disabled accounts can retain grants. '
    'A catalog mismatch means source and policy classifications differ. '
    'Preserve the exact supplied recommendation and include every supplied '
    'signal code exactly once in evidence_codes. Do not invent identities, '
    'systems, observations, approvals, or completed changes. A recommendation '
    'requires authorized human review; you cannot grant approval or execute '
    'anything. When actionable is false, explain that decisions are blocked. '
    'Return only the requested structured object.'
)


class RuleExplainer:
    """Present the engine's actual signal messages without claiming AI use."""

    provider = 'rules'

    def explain(self, finding: dict) -> dict:
        signals = finding.get('signals', [])
        messages = list(dict.fromkeys(item['message'] for item in signals))
        return {
            'provider': self.provider,
            'status': 'ready',
            'summary': ' '.join(messages) if messages else 'No evidence signals were supplied.',
            'recommendation': finding['recommendation'],
            'evidence_codes': sorted({item['code'] for item in signals}),
        }


class _InvalidExplanation(ValueError):
    pass


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidExplanation('duplicate_key')
        result[key] = value
    return result


def _reject_constant(value):
    raise _InvalidExplanation('nonfinite_number')


def _json(text):
    return json.loads(text, object_pairs_hook=_strict_object, parse_constant=_reject_constant)


def _minimal_evidence(finding):
    """Whitelist typed facts; never copy names, free text, identifiers or notes."""
    evidence = {}
    for field, allowed in _ENUMS.items():
        value = finding[field]
        if not isinstance(value, str) or value not in allowed:
            raise _InvalidExplanation('invalid_evidence')
        evidence[field] = value
    score = finding['risk_score']
    if type(score) is not int or not 0 <= score <= 100:
        raise _InvalidExplanation('invalid_evidence')
    evidence['risk_score'] = score
    for field in ('privileged', 'actionable'):
        if type(finding[field]) is not bool and not (field == 'privileged' and finding[field] is None):
            raise _InvalidExplanation('invalid_evidence')
        evidence[field] = finding[field]
    signals = finding['signals']
    if not isinstance(signals, list) or not 1 <= len(signals) <= len(_SIGNAL_CODES):
        raise _InvalidExplanation('invalid_evidence')
    evidence['signals'] = []
    for signal in signals:
        code, points = signal['code'], signal['points']
        if not isinstance(code, str) or code not in _SIGNAL_CODES:
            raise _InvalidExplanation('invalid_evidence')
        if type(points) is not int or not 0 <= points <= 100:
            raise _InvalidExplanation('invalid_evidence')
        evidence['signals'].append({'code': code, 'points': points})
    if len({s['code'] for s in evidence['signals']}) != len(signals):
        raise _InvalidExplanation('invalid_evidence')
    peer = finding.get('peer', {})
    available = peer.get('available', False)
    if type(available) is not bool:
        raise _InvalidExplanation('invalid_evidence')
    evidence['peer'] = {'available': available}
    if available:
        count, holders, ratio = peer['count'], peer['holders'], peer['ratio']
        if type(count) is not int or type(holders) is not int or not 0 <= holders <= count or count < 1:
            raise _InvalidExplanation('invalid_evidence')
        if type(ratio) not in (int, float) or not math.isfinite(ratio) or not 0 <= ratio <= 1:
            raise _InvalidExplanation('invalid_evidence')
        evidence['peer'].update(count=count, holders=holders, ratio=ratio)
    return evidence


class OpenAIExplainer:
    """Optional explanation with strict factual fields and explicit fallback.

    The injected client remains caller-owned. No request is made when a key or
    model is absent. This class does not discover credentials or choose a model.
    """

    provider = 'openai'

    def __init__(self, api_key: str | None, model: str | None, client: httpx.Client | None = None):
        self._api_key = api_key
        self.model = model
        self._client = client

    def _fallback(self, finding, reason):
        result = RuleExplainer().explain(finding)
        result.update(status='fallback', fallback_reason=reason)
        return result

    def explain(self, finding: dict) -> dict:
        if (not isinstance(self._api_key, str) or not self._api_key.strip()
                or self._api_key != self._api_key.strip()
                or any(unicodedata.category(c).startswith('C') for c in self._api_key)
                or not isinstance(self.model, str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}', self.model)):
            return self._fallback(finding, 'not_configured')
        try:
            evidence = _minimal_evidence(finding)
        except (KeyError, TypeError, ValueError):
            return self._fallback(finding, 'invalid_evidence')
        codes = sorted(s['code'] for s in evidence['signals'])
        schema = {
            'type': 'object',
            'additionalProperties': False,
            'properties': {
                'summary': {'type': 'string'},
                'recommendation': {'type': 'string', 'enum': [evidence['recommendation']]},
                'evidence_codes': {'type': 'array', 'items': {'type': 'string', 'enum': codes}},
            },
            'required': ['summary', 'recommendation', 'evidence_codes'],
        }
        payload = {
            'model': self.model,
            'instructions': _INSTRUCTIONS,
            'input': [{'role': 'user', 'content': json.dumps(evidence, sort_keys=True, allow_nan=False)}],
            'text': {'format': {'type': 'json_schema', 'name': 'access_review_explanation', 'strict': True, 'schema': schema}},
            'store': False,
            'max_output_tokens': 600,
        }
        try:
            if self._client is None:
                with httpx.Client(timeout=_TIMEOUT, follow_redirects=False, trust_env=False) as client:
                    response = self._request(client, payload)
            else:
                response = self._request(self._client, payload)
        except (httpx.HTTPError, OSError, ValueError):
            # Remote messages, URLs and exception strings may include secrets.
            return self._fallback(finding, 'request_failed')
        try:
            if len(response.content) > _MAX_RESPONSE_BYTES:
                raise _InvalidExplanation('invalid_response')
            body = _json(response.content)
            if not isinstance(body, dict):
                raise _InvalidExplanation('invalid_response')
            if body.get('status') == 'incomplete':
                return self._fallback(finding, 'incomplete_response')
            if body.get('status') != 'completed' or body.get('error') is not None:
                raise _InvalidExplanation('invalid_response')
            output = body.get('output')
            if not isinstance(output, list):
                raise _InvalidExplanation('invalid_response')
            texts = []
            for item in output:
                if not isinstance(item, dict):
                    raise _InvalidExplanation('invalid_response')
                if item.get('type') == 'reasoning':
                    continue
                if (item.get('type') != 'message' or item.get('role', 'assistant') != 'assistant'
                        or item.get('status', 'completed') != 'completed'
                        or not isinstance(item.get('content'), list)):
                    raise _InvalidExplanation('invalid_response')
                for content in item['content']:
                    if not isinstance(content, dict):
                        raise _InvalidExplanation('invalid_response')
                    if content.get('type') == 'refusal':
                        return self._fallback(finding, 'refused')
                    if content.get('type') != 'output_text' or not isinstance(content.get('text'), str):
                        raise _InvalidExplanation('invalid_response')
                    texts.append(content['text'])
            if len(texts) != 1:
                raise _InvalidExplanation('invalid_response')
            result = _json(texts[0])
            if not isinstance(result, dict) or set(result) != {'summary', 'recommendation', 'evidence_codes'}:
                raise _InvalidExplanation('invalid_response')
            summary = result['summary']
            if (not isinstance(summary, str) or not 1 <= len(summary) <= 2000
                    or summary != summary.strip()
                    or any(unicodedata.category(c).startswith('C') for c in summary)):
                raise _InvalidExplanation('invalid_response')
            returned_codes = result['evidence_codes']
            if (not isinstance(returned_codes, list)
                    or not all(isinstance(code, str) for code in returned_codes)
                    or len(returned_codes) != len(codes) or set(returned_codes) != set(codes)
                    or result['recommendation'] != finding['recommendation']):
                raise _InvalidExplanation('invalid_response')
            return {'provider': self.provider, 'status': 'ready', 'summary': summary,
                    'recommendation': finding['recommendation'], 'evidence_codes': codes}
        except (KeyError, TypeError, ValueError, RecursionError):
            return self._fallback(finding, 'invalid_response')

    def _request(self, client, payload):
        response = client.post(
            _ENDPOINT, json=payload,
            headers={'Authorization': f'Bearer {self._api_key}'},
            timeout=_TIMEOUT, follow_redirects=False,
        )
        response.raise_for_status()
        return response
