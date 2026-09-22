"""Free-tier Gemini review integration and environment-only configuration.

No provider SDK, paid fallback, model routing, tools, or automatic decisions.
"""
import json
import os
import threading
import time

import httpx

from .explanations import (StructuredReviewer, OpenAIReviewer, RuleReviewer,
                           _INSTRUCTIONS, _InvalidReview, _MAX_RESPONSE_BYTES)

GEMINI_MODEL = 'gemini-3.8-flash'
GEMINI_ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/interactions'


class GeminiReviewer(StructuredReviewer):
    provider = 'gemini'

    def __init__(self, api_key, model=GEMINI_MODEL, client=None, *, interval=6.0):
        super().__init__(api_key, model, client)
        if not 0 <= interval <= 60:
            raise ValueError('Gemini request interval must be between 0 and 60 seconds')
        self._interval = interval
        self._lock = threading.Lock()
        self._next_request = 0.0
        self._limited_until = 0.0

    def review(self, case):
        # Serialize this provider's calls, including overlapping campaign imports.
        # A quota failure does not trigger a retry storm or a paid-model fallback.
        with self._lock:
            if time.monotonic() < self._limited_until:
                return self._fallback(case, 'rate_limited')
            return super().review(case)

    def _payload(self, evidence, schema):
        return {
            'model': self.model,
            'system_instruction': _INSTRUCTIONS + (
                ' Assess every supplied item exactly once. Cite at least one supplied '
                'evidence reference for the case and for each item. Explain why access '
                'is or is not justified using lifecycle, job needs, privilege, grant '
                'paths, exceptions and history. Peer prevalence is context, not '
                'authorization. Do not invent approvals, usage, dates or policy. '
                'Identify absent evidence and uncertainty; confidence is your '
                'self-assessment, not a calibrated probability. Keep each reasoning '
                'field concise, under 4000 characters, with no line breaks.'),
            'input': json.dumps(evidence, sort_keys=True, allow_nan=False),
            'response_format': {'type': 'text', 'mime_type': 'application/json', 'schema': schema},
            'generation_config': {'thinking_level': 'high', 'thinking_summaries': 'none',
                                  'max_output_tokens': 16384},
            'store': False,
        }

    def _request(self, client, payload):
        delay = self._next_request - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self._next_request = time.monotonic() + self._interval
        # Read in bounded chunks, never follow redirects with the API key.
        with client.stream('POST', GEMINI_ENDPOINT, json=payload,
                           headers={'x-goog-api-key': self._api_key},
                           timeout=httpx.Timeout(120.0, connect=10.0),
                           follow_redirects=False) as response:
            if response.status_code == 429:
                self._limited_until = time.monotonic() + 60.0
            response.raise_for_status()
            chunks, size = [], 0
            for chunk in response.iter_bytes(chunk_size=8192):
                size += len(chunk)
                if size > _MAX_RESPONSE_BYTES:
                    raise ValueError('response_too_large')
                chunks.append(chunk)
            return httpx.Response(response.status_code, content=b''.join(chunks))

    def _output_text(self, body):
        if body.get('status') == 'incomplete':
            raise _InvalidReview('incomplete_response')
        if body.get('status') != 'completed' or body.get('error') is not None:
            raise _InvalidReview('invalid_response')
        texts = []
        for step in body.get('steps', []):
            if step.get('type') == 'thought':
                continue
            if step.get('type') != 'model_output':
                raise _InvalidReview('invalid_response')
            for content in step.get('content', []):
                if content.get('type') != 'text':
                    raise _InvalidReview('invalid_response')
                texts.append(content.get('text'))
        if len(texts) != 1:
            raise _InvalidReview('invalid_response')
        return texts[0]


def configured_reviewer(environ=None):
    env = os.environ if environ is None else environ
    mode = env.get('IGA_AI_PROVIDER', 'auto')
    key = env.get('GEMINI_API_KEY') or env.get('GOOGLE_API_KEY')
    if mode == 'auto':
        mode = 'gemini' if key else 'rules'
    if mode == 'rules':
        return RuleReviewer()
    if mode == 'gemini':
        if not key:
            raise ValueError('Gemini requires GEMINI_API_KEY (or GOOGLE_API_KEY). Use setup_gemini.ps1.')
        model = env.get('IGA_AI_MODEL') or GEMINI_MODEL
        # Intentionally pinned to the verified free-tier model. No paid upgrade.
        if model != GEMINI_MODEL:
            raise ValueError(f'Gemini mode supports only {GEMINI_MODEL}; no automatic paid upgrade is allowed.')
        return GeminiReviewer(key, model, interval=float(env.get('IGA_AI_INTERVAL_SECONDS', '6')))
    if mode == 'openai':
        key, model = env.get('OPENAI_API_KEY'), env.get('IGA_AI_MODEL')
        if not key or not model:
            raise ValueError('Explicit OpenAI mode requires OPENAI_API_KEY and IGA_AI_MODEL')
        return OpenAIReviewer(key, model)
    raise ValueError('IGA_AI_PROVIDER must be auto, gemini, rules or openai')


def check_connection(reviewer):
    """One real generation with synthetic evidence, never employee data."""
    case = {
        'key': 'synthetic-connection-check', 'identity_context': None,
        'accounts': [], 'applications': [], 'assignments': [], 'grant_paths': [],
        'roles': [], 'groups': [], 'exceptions': [], 'history': [],
        'relevant_entitlements': [], 'warnings': ['Synthetic connection test only.'],
        'evidence_refs': ['item:connection-check'],
        'items': [{'key': 'connection-check', 'kind': 'coverage',
                   'policy_result': 'coverage_gap', 'privileged': False,
                   'constraints': [], 'policy_fact': {
                       'text': 'No source access evidence is available in this synthetic connection test.'}}],
    }
    result = reviewer.review(case)
    return {key: result[key] for key in
            ('provider', 'model', 'status', 'fallback_reason', 'attempted_provider') if key in result}
