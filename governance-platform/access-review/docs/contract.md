# Module 4 implementation contract

Version 2.0.0. Module 4 consumes validated Module 1 HR/policy documents and a
normalized Module 3 evidence scan. It contains no native system commands.

## Normalized scan v2

`Scan` requires `schema_version: "2.0.0"`, immutable scan/source/mapping IDs,
UTC `scanned_at`, completeness and request-correlation fields, plus these
source-owned collections:

- `applications`: ID, name, criticality and source.
- `identities` (source accounts): ID, username, enabled state, application ID,
  account type and source.
- `roles`: business or application role, optional application ID, privileged
  classification and source.
- `groups`: application-owned group and nullable privileged classification.
- `entitlements`: permission, sensitivity, privileged classification and
  application ID.
- `grant_paths`: account-to-entitlement paths whose intermediate nodes may be
  business roles, application roles, or groups.
- `assignments`: observed account/entitlement assignment, grant time when known,
  one or more exact grant-path IDs, optional business justification and
  approved-exception ID.
- `exceptions`: approver, approval/expiry times and reason.
- `history`: granted/revoked/changed/reviewed events.

Unknown fields and type coercion are rejected. IDs are unique, all references
resolve, every object belongs to the scan source, each path begins at its
declared account and ends at its declared entitlement, and event/assignment
times cannot be later than the scan. `scope_entitlements` must exactly match
the discovered entitlement catalog. Complete means all accounts and grants in
the declared scope were read.

Assignment `timestamp` and group `privileged` are required but nullable. Unknown
grant time is `null`; `scanned_at` is the observation time, not a substitute grant
time. These nullable extensions retain the current `2.0.0` version; older v2
consumers requiring a timestamp string or group boolean must be updated before
using this connector. Every grant path must be referenced by an assignment;
interior nodes are roles/groups only, and repeated nodes are rejected.

Campaign input also includes Module 1 documents and explicit account-to-HR
correlations. Ownership is never inferred from usernames. The local demo loads
access observations from the checked-in `normalized-evidence.json`; it does not
derive grants from policy expectations. This is a stable synthetic fixture,
not proof of live discovery. A separate Module 3 connector is implemented and
tested with captured native evidence and localhost HTTP; live target operations
were not exercised in the current audit.

## Deterministic engine

`engine.evaluate(...)` returns `cases`, compatibility `findings`, evidence
warnings and campaign actionability. There is one case per correlated HR
identity; unresolved accounts and coverage failures have separate cases. Each
case contains full relevant identity/role context, applications, accounts,
entitlements, assignments, direct/inherited paths, justifications, exceptions,
history, policy facts and evidence references.

The engine classifies policy facts and creates safety constraints. It does not
return a recommendation. Hard restrictions, lifecycle restrictions and
unauthorized privilege produce a non-discretionary `remove` constraint.
Privileged access produces a mandatory-human constraint. Unresolved ownership
and stale/incomplete evidence block decisions. Risk remains a transparent,
versioned triage heuristic rather than a probability or authorization result.

## Independent review

Campaign creation invokes `review(case)` once for every case. Gemini uses the
fixed Google Interactions endpoint with `gemini-3.8-flash`, high reasoning,
JSON-schema output and `store=false`. The optional OpenAI reviewer uses the
Responses endpoint. Groq uses Chat Completions with JSON-object output and local
schema validation. No provider has tools or decision/connector authority.
Cases include relevant role/group definitions, scan/review timestamps and
references for assignments, applications, entitlements, exceptions and history.
All providers validate structured results locally and may independently return:

- case `recommended_action`: `retain|remove|investigate|escalate`;
- confidence from 0 through 1;
- evidence references, open questions, missing evidence and reasoning;
- exactly one assessment for every access item, with its own action, evidence
  references and reasoning.

The model is not forced to match deterministic constraints. Invalid, refused,
incomplete or failed model responses become an explicit `provider: rules`,
`status: fallback` result; fallback is never labeled as AI. Review cases and
assessments are persisted and included in campaign export. Successful results
include `model`. Provider failures include `attempted_provider`, `model` and a
sanitized `fallback_reason`; upstream error bodies and keys are never persisted.
Evidence-reference lists must be nonempty and contain only supplied references;
each item assessment must cite its own item reference.
Free-tier quota failures are not retried against a paid model. See the README
for activation, quota behavior, data handling and the synthetic `ai-check`.

Mandatory human-review reasons are explicit data: `privileged_access`,
`ai_engine_disagreement`, `low_ai_confidence`, `missing_evidence`,
`open_questions`, `evidence_gaps`, `non_discretionary_constraint`, and
`ai_fallback`. A disagreement is retained
for audit and human inspection. Confidence below the recorded campaign
threshold (currently 0.7) is low. Confidence is model self-report, not a calibrated
probability. Disagreement never weakens a hard constraint. Missing usage or
history is reported as an evidence gap, not inferred inactivity or no changes.

## Human decisions and remediation

Authenticated, routed reviewers still decide item-level `certify`, `revoke`,
or `acknowledge` actions with a reason, expected version and idempotency key.
Self-review, stale evidence and unresolved routing remain blocked. Certification
against a non-discretionary remove constraint is rejected even when risk is
acknowledged. Decision-blocking constraints are enforced by the service, not
only shown in the UI. Certification that requires human review needs explicit
risk acknowledgement even when AI recommends retention. AI never approves or
dispatches work.

A revoke transaction stores the exact approved account, entitlement,
assignment IDs and grant-path IDs. The fixture connector rejects changed target
sets, removes only those approved paths/assignments, and remains idempotent.
Connector acknowledgement is not proof of removal. Verification requires a
newer, complete Module 3 scan with the same source/mapping, correct request ID,
coverage of the target entitlement, and no remaining assignment for the exact
account/entitlement, including newly appearing paths outside the original
approval. Verification evidence and all decisions are audited.

## HTTP surface

### Environment-first campaign runs

All of these routes require an authenticated administrator. Reviewers retain
their existing scoped campaign/finding routes.

| Method and route | Behavior |
| --- | --- |
| `GET /api/environments` | Configured sources, setup readiness, mode, saved inventory, latest run/events and campaign. Does not call connectors. |
| `POST /api/environments/{source}/campaign-runs` | Body `{"name":"Quarterly access review"}` and required `Idempotency-Key`; returns the persisted run with HTTP 202. Unknown body fields are rejected. |
| `GET /api/campaign-runs/{run_id}` | Durable stage, timestamps, attempt count, scan/campaign IDs, sanitized error, `can_retry`, retry guidance, events and completed review provider/fallback counts. |
| `POST /api/campaign-runs/{run_id}/retry` | Requeues an eligible failed run; returns HTTP 202. Active/completed runs return their current state. Blocked/exhausted runs return 409. |

Source, connector URL/token, input paths, and evidence are resolved from server
configuration. The same actor/key/name/source returns the original run even
after completion; changed content with that key returns 409. A SQLite partial
unique index and transactional source checks prevent simultaneous active starts
across tabs/processes. Source checks also exclude in-flight remediation and
unresolved dispatch/verification even after its lease expires. Legacy
imports cannot supersede a source while a campaign run is active. Starting a
review never grants or revokes access; queued human-approved remediation remains
subject to the existing freshness, supersession and exact-target checks.

Stages are `queued`, `scanning`, `validating`, `reviewing`, `completed`, `failed`
and `blocked`. Append-only run events record failures before any campaign exists;
these are separate from the campaign hash-chain audit. The UI displays actual
stages and recorded events, without inferred percentages. A completed campaign
can contain unresolved ownership findings whose decisions are blocked. A run
blocked by global evidence quality creates no campaign and supersedes nothing.

The ASGI lifespan of `serve` and `demo` starts the durable campaign runner.
No additional process is required for campaign generation. The existing `worker`
and `work` commands still process approved remediation, not campaign runs.
Each claimed attempt has a fenced 30-second renewable lease, one-second
heartbeat, 30-minute deadline and a maximum of three claims including recovery.
Expired leases/deadlines recover automatically; ordinary connector/processing
failures require explicit retry. Shutdown fences active work for recovery.
Blocking calls are supervised separately so a stalled call cannot stall the
runner indefinitely. Python cannot forcibly cancel a call already executing;
its late result cannot commit after fencing. External AI calls may be repeated
after crashes, so exactly-once inference is not promised.

Inputs and their SHA-256 digests are pinned when the run is accepted. Each scan
attempt uses a new request ID: the connector's `/scans` endpoint does not dedupe
observations by request ID. Source/request identity, schema, declared scope,
new scan ID, observation time and any configured mapping version are checked.
Observations must be at or after the scan request and within clock-skew limits.
Structurally valid correlated observations are stored independently of review
success, including partial scans that subsequently block review. Inventory
labels retain completeness; last-known data is not a health assertion. Counts
come from accounts/assignments in scans, never from findings or HR-person counts.
Newer legacy-import evidence can also be the last-known inventory.

Review retries reuse accepted evidence and pinned inputs and recheck freshness;
expired/partial/invalid evidence blocks the run rather than silently replacing
it. A failure before acceptance requires a fresh observation on retry. Linux
`linux-posix` correlations require captured username/UID evidence and reject
disagreement with the scanned account. Missing/ambiguous ownership remains
visible with blocked decisions. Real-data AI consent is enforced before review.
Campaign insertion, findings, supersession, audit and run completion commit in
one transaction, so a lost return after commit recovers the same campaign.

The additive SQLite schema migration to version 3 creates run, event and
immutable inventory tables without rewriting existing campaigns or audit hashes.
Public responses omit input documents, filesystem paths, URLs and credentials.
Existing `POST /api/campaigns` full-payload imports remain supported.
`GET /api/environment` remains the legacy active-scan endpoint (five-second
in-memory cache); the new UI polls only `/api/environments` every three seconds,
without overlapping requests. Leaving the view or signing out stops polling.
Tokens stay in memory: reload requires sign-in, then server-side discovery
restores active/completed run status and the campaign link.

The existing campaign, finding, decision, processing, retry, audit, export and
scan-schema endpoints remain. `POST /api/findings/{id}/explanation` now returns
the assessment created during campaign import; it does not trigger optional
case work. Finding responses retain compatibility `recommendation` values for
the current UI, but those values are projections of the independent item
assessment, never deterministic-engine output. They also expose `case_id`,
`recommended_action`, `case_assessment`, `item_assessment`,
`mandatory_human_review`, and `human_review_reasons`.
