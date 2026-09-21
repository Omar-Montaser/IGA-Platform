# Module 4 implementation contract

Version 1.0.0. Module 4 consumes validated Module 1 documents and normalized
Module 3 scans. It contains no native system commands. Python package
`iga_review` uses FastAPI and SQLite. The implemented core exposes an HTTP API;
the browser reviewer UI is follow-on work.

## Scan and correlation

A scan requires `schema_version: "1.0.0"`, `scan_id`, `source`, `scanned_at`
(UTC ISO timestamp ending Z, optional fractional seconds), `complete` (boolean),
`mapping_version`, `scope_entitlements` (unique ID strings), `request_id`
(nullable string; the requested correlation ID for verification scans), and
arrays `identities`, `entitlements`, `assignments`. Unknown fields are rejected.
All objects are source independent; strings are trimmed, bounded, no controls.

- Account: `id`, `username`, `enabled` (boolean), `source`.
- Entitlement: `id`, `name`, `type` (`permission`), `sensitivity`
  (`low|medium|high|critical|unknown`), `privileged` (boolean or null), `source`.
- Assignment: `id`, `identity` (account ID), `entitlement` (catalog ID),
  `source`, `timestamp` (UTC; not after scanned_at).

All object IDs are unique within their own collection, references resolve,
source equals scan.source, discovered entitlements are in scope, and every
scope ID has a scan entitlement definition. Empty scans are valid. Multiple
assignments can confer the same capability; review groups by account+entitlement
and removal verification requires all grants of that capability to disappear.
Complete means all accounts and all grants for declared scope were read.

Import payload: `name`, `identities` (M1 document), `policies` (M1 document),
`scan` (above), `correlations` (array of `account_id`, `identity_id`, `evidence`).
Only administrators import. Bindings are explicit, never inferred from username.
References resolve; duplicate identical bindings are invalid, multiple distinct
HR candidates for one account remain ambiguous review evidence. Canonical input
and SHA-256 digests are retained; API also retains the exact submitted JSON.

## Engine API

`domain.Scan.model_validate(data)` validates normalized scans. `domain.Correlation`
validates binding records. `domain.EngineConfig` is a frozen dataclass with
`max_hr_age_days=30`, `max_scan_age_hours=24`, `max_clock_skew_seconds=300`,
`min_peer_count=5`, `peer_rarity_threshold=0.2`. `domain.utcnow()` and
`domain.timestamp(datetime)` supply UTC time. `domain.InputError(ValueError)`
represents semantic input problems. M1 uses its existing BundleValidationError.

`engine.evaluate(bundle, scan, correlations, *, now, config=EngineConfig())`
returns `{findings: [...], warnings: [...], actionable: bool}`. Finding dict:
`key` stable within scan, `kind` (`assignment|missing_access|account|coverage`),
`account_id` nullable, `identity_id` nullable, `identity_name`, `username`,
`department`, `role`, `employment_status`, `entitlement_id` nullable,
`entitlement_name`, `source`, `assignment_ids` list, `sensitivity`, `privileged`,
`policy_result` (`expected|permitted_privileged|restricted|lifecycle_restricted|
unauthorized_privilege|unlisted|unknown_entitlement|unmatched|ambiguous|
missing_expected|coverage_gap`), `signals` list of `{code, message, points}`,
`risk_score` integer 0..100, `risk_level` (`low|medium|high|critical`),
`recommendation` (`certify|review|revoke|acknowledge`), `peer` object,
`evidence` JSON object, `actionable` bool.

Each actual assignment is reviewable, even expected access. Nonactive status
wins, then restricted, then expected/permitted privilege, then unauthorized
privilege/unlisted/unknown. Unknown and ambiguous accounts remain visible even
with zero assignments. Missing expected access is computed over the union of
all accounts explicitly bound to a person, only for active identities with an
observed account, complete in-scope scan and fresh HR/scan data. Disabled account
state never erases retained grants. Peer denominator counts distinct other
active, unambiguously matched, observed HR people of same department, role and
employment_type, excludes subject; use all their accounts, suppress on partial
scans or fewer than min_peer_count. Peer rarity is explanatory, never an allow
rule. Baseline absence is not a provisioning action.

Stale inputs, future skew, scan before HR snapshot or policy effective date,
and partial scans produce warnings and block decisions for the campaign;
findings remain inspectable, missing/peer inferences are suppressed. Risk is a
versioned heuristic with explicit contributions, not a probability. M1 catalog
classification is authoritative; higher scan sensitivity/privilege is retained
conservatively, discrepancies are visible. Evaluation never invokes AI or a
connector. All display strings must be rendered as text by consumers.

## HTTP and service interface

Bearer credentials identify server-configured principals. No submitted reviewer
name grants authority. `User` has id, name, role (`admin|reviewer`),
hr_identity_id nullable, token_hash. Reviewers access assigned findings only;
admins may access all, but nobody may approve their own HR identity. Manager
principals are resolved from HR manager_id; otherwise an explicitly configured
fallback principal is used, or routing remains unresolved.

- `GET /` public core API status, no secrets.
- `GET /api/health` public liveness, no secrets.
- `GET /api/me` authenticated principal plus `demo` and `ai_provider`.
- `GET /api/campaigns` -> `{campaigns: [...]}`.
- `POST /api/campaigns` import -> campaign including findings (admin).
- `GET /api/campaigns/{id}` -> campaign including authorized `findings`.
- `GET /api/findings/{id}` -> finding with state and explanation.
- `POST /api/findings/{id}/decisions` JSON `action`, `reason`,
  `expected_version`, `acknowledge_risk`; header `Idempotency-Key`.
- `POST /api/findings/{id}/explanation` -> explanation (never a decision).
- `POST /api/campaigns/{id}/process` dispatch queued approvals and verify (admin).
- `POST /api/remediations/{id}/retry` retry same approved request (admin).
- `GET /api/campaigns/{id}/audit` -> `{events: [...], integrity: bool}`.
- `GET /api/campaigns/{id}/export` -> retained inputs, findings, decisions,
  requests, verification scans, audit (admin).
- `GET /api/schemas/scan` -> generated JSON schema (authenticated).

Errors use `{error: {code, message}}` with HTTP 400/401/403/404/409/422/503.
Finding responses add `id`, `campaign_id`, `version` starting 1,
`status` starting `pending`, `reviewer_id`, `routing_reason`, `explanation`,
`can_decide` and `allowed_actions`. Decision body allows `certify|revoke` only
for assignment findings and `acknowledge` for other findings. Risky certification
requires acknowledge_risk=true. Every decision needs a nonblank reason of 8..2000
characters. Only pending, fresh, routed items can be decided. Concurrent/repeated
updates use expected_version and idempotency keys; duplicate identical requests
return original decision, conflicting key reuse fails. Decision+audit+revoke
outbox entry commit together. No AI or connector call occurs in that transaction.

## Connector and explanation boundary

`connector.Connector.revoke(request: dict) -> dict` returns `request_id`,
`status` (`succeeded|failed`), `message`. Request contains `request_id`, `source`,
`identity` (source account ID), `entitlement`, `approved_by`, `approved_at`,
`reason`, `scan_id`, `mapping_version`, `assignment_ids`. Identical request_id
must be idempotent. No browser-supplied command or endpoint is accepted.
`Connector.scan(source, request_id) -> dict` returns a normalized scan with
that request_id. HTTP adapter POSTs `/revocations` and `/scans` to an explicitly
configured base URL with a separate service credential; no redirects.

Outbox states queued/dispatching/verification_pending/failed/verification_failed/
verified. Claims are transactional and leased; retry keeps request_id. Success
from revoke is only an acknowledgement. Verification requires a different scan
ID, matching source, request_id and mapping version, a timestamp after the scan
request and approval, complete scope covering the target entitlement, and no
assignment for the exact target account+entitlement. Store successful and failed
verification evidence. Fixture connector operates on clearly labeled simulated
state; it is not Module 3 or a real target scan.

`explanations.RuleExplainer.explain(finding) -> dict` returns provider `rules`,
summary, recommendation, evidence_codes, status. Optional
`OpenAIExplainer(api_key, model, client=None)` uses Responses structured output,
no tools, no names/usernames/raw source text, store=false, bounded timeout/output.
Unconfigured/unavailable/invalid AI output falls back explicitly to rules.
AI may explain evidence but cannot change signals, scores, allowed actions, or
approve/dispatch requests. UI identifies rule text separately from AI text.
