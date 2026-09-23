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

The existing campaign, finding, decision, processing, retry, audit, export and
scan-schema endpoints remain. `POST /api/findings/{id}/explanation` now returns
the assessment created during campaign import; it does not trigger optional
case work. Finding responses retain compatibility `recommendation` values for
the current UI, but those values are projections of the independent item
assessment, never deterministic-engine output. They also expose `case_id`,
`recommended_action`, `case_assessment`, `item_assessment`,
`mandatory_human_review`, and `human_review_reasons`.
