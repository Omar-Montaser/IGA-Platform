# Module 4 core verification

Verified on 2026-09-21 with Python 3.13:

- Module 4: 103 acceptance tests passed with `ResourceWarning` promoted to an
  error (87 original core tests + 16 UI tests).
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

UI tests verify static file serving, security headers, path traversal protection,
CSP enforcement, HTML accessibility attributes, JavaScript security patterns
(no eval, strict mode, XSS prevention), token storage security (no localStorage),
focus state CSS, 401 logout handling, and idempotency key generation.

Manual verification confirmed:
- Reviewer UI renders at http://127.0.0.1:8040
- Login accepts bearer token from `.demo-review/reviewer-token.txt`
- Campaign list displays with filters and navigation
- Finding detail shows all sections (identity, entitlement, risk, signals, peer analysis, explanation)
- Decision form enforces validation (action required, reason 8-2000 chars, risk acknowledgment)
- Admin features (process, export, audit) visible only to admin role
- Keyboard navigation functional (Tab, Enter)
- Focus indicators visible (2px blue outline)
- Responsive layout adapts to narrow screens
- Security headers present (CSP, X-Content-Type-Options, Referrer-Policy, Cache-Control)
- Bearer token not persisted (cleared on logout/refresh)

No claim is made here about comprehensive browser automation testing (Selenium,
Playwright, Cypress), a live Module 3 service, an organizational identity provider,
a live OpenAI call, or production operations. Those require their own acceptance
environments. Current UI tests verify HTML structure, JavaScript security, and
API integration without requiring a browser runtime.
