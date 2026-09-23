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

GROQ_MODEL = 'llama-3.3-70b-versatile'
GROQ_ENDPOINT = 'https://api.groq.com/openai/v1/chat/completions'


class GeminiReviewer(StructuredReviewer):
    provider = 'gemini'
    endpoint = GEMINI_ENDPOINT

    def __init__(self, api_key, model=GEMINI_MODEL, client=None, *, interval=6.0):
        super().__init__(api_key, model, client)
        if not 0 <= interval <= 60:
            raise ValueError('AI request interval must be between 0 and 60 seconds')
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

    def _headers(self):
        return {'x-goog-api-key': self._api_key}

    def _request(self, client, payload):
        delay = self._next_request - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self._next_request = time.monotonic() + self._interval
        # Read in bounded chunks, never follow redirects with the API key.
        with client.stream('POST', self.endpoint, json=payload,
                           headers=self._headers(),
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


class GroqReviewer(GeminiReviewer):
    """Groq JSON mode with local schema validation, pacing and bounded transport."""
    provider = 'groq'
    endpoint = GROQ_ENDPOINT

    def __init__(self, api_key, model=GROQ_MODEL, client=None, *, interval=6.0):
        super().__init__(api_key, model, client, interval=interval)

    def _payload(self, evidence, schema):
        return {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': _INSTRUCTIONS + (
                    ' Assess every supplied item exactly once. Cite at least one supplied '
                    'evidence reference for the case and for each item. Explain why access '
                    'is or is not justified using lifecycle, job needs, privilege, grant '
                    'paths, exceptions and history. Peer prevalence is context, not '
                    'authorization. Do not invent approvals, usage, dates or policy. '
                    'Identify absent evidence and uncertainty; confidence is your '
                    'self-assessment, not a calibrated probability. Keep each reasoning '
                    'field concise, under 4000 characters, with no line breaks. '
                    'Return one JSON object following this schema exactly: ') + json.dumps(schema)},
                {'role': 'user', 'content': json.dumps(evidence, sort_keys=True, allow_nan=False)}
            ],
            # Llama 3.3 does not support Groq's strict json_schema mode.
            # JSON mode plus the same local validator fails closed on bad output.
            'response_format': {'type': 'json_object'},
            'temperature': 0.1,
            'max_tokens': 4000,
        }

    def _headers(self):
        return {'Authorization': f'Bearer {self._api_key}'}

    def _output_text(self, body):
        if body.get('error'):
            raise _InvalidReview('invalid_response')
        choices = body.get('choices', [])
        if len(choices) != 1:
            raise _InvalidReview('invalid_response')
        if choices[0].get('finish_reason') == 'length':
            raise _InvalidReview('incomplete_response')
        if choices[0].get('finish_reason') != 'stop':
            raise _InvalidReview('invalid_response')
        message = choices[0].get('message', {})
        if message.get('refusal'):
            raise _InvalidReview('refused')
        if message.get('tool_calls') or message.get('function_call'):
            raise _InvalidReview('invalid_response')
        if message.get('role') != 'assistant':
            raise _InvalidReview('invalid_response')
        content = message.get('content')
        if not isinstance(content, str) or not content:
            raise _InvalidReview('invalid_response')
        return content


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
    if mode == 'groq':
        key = env.get('GROQ_API_KEY')
        if not key:
            raise ValueError('Groq mode requires GROQ_API_KEY')
        model = env.get('IGA_AI_MODEL') or GROQ_MODEL
        return GroqReviewer(key, model, interval=float(env.get('IGA_AI_INTERVAL_SECONDS', '6')))
    raise ValueError('IGA_AI_PROVIDER must be auto, gemini, groq, rules or openai')


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
