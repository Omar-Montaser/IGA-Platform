# Module 4 core verification

Verified on 2026-09-21 with Python 3.13:

- Module 4: 87 acceptance tests passed with `ResourceWarning` promoted to an
  error.
- Module 1 regression: 67 tests passed.
- Every Module 4 source file parsed using the Python 3.11 grammar.
- The package built as `iga_access_review-1.0.0-py3-none-any.whl` and the wheel
  contained all eleven runtime modules and its console entry point.
- The installed `iga-review --help` command ran from outside the source tree.
- `git diff --check` reported no whitespace errors.

The tests cover strict input parsing, correlation ambiguity, policy and
lifecycle precedence, peer cohorts, missing-access inference, risk evidence,
explanation isolation and privacy, authentication and authorization, decision
idempotency and concurrency, immutable retained evidence, audit integrity,
durable connector retries, supersession, dispatch-time authorization, and
fresh-scan verification.

No claim is made here about browser usability, a live Module 3 service, an
organizational identity provider, a live OpenAI call, or production operations.
Those require their own acceptance environments.
