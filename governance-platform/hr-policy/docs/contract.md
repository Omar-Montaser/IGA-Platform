# Module 1 contract version 1.0.0

Module 1 publishes two UTF-8 JSON documents: `identities.json` and
`policies.json`. Module 4 loads them as one validated bundle. Module 1 neither
discovers access nor grants, evaluates, or revokes it. Policy interpretation
below is a contract for Module 4, not an implemented review engine.

## Shared envelope

Both documents require `schema_version` (`1.0.0`), `dataset_id` (a lowercase
slug), `snapshot_at` (UTC `YYYY-MM-DDTHH:MM:SSZ`), and `synthetic` (boolean).
All four values must agree across the pair. Unknown fields are rejected.
Strings must be nonempty and trimmed; ASCII control characters, DEL, and
unpaired Unicode surrogates are rejected in every string field.
The snapshot is explicit; validation never depends on the machine's clock.
The supplied demo is synthetic and frozen at `2026-09-21T00:00:00Z`.

## Identity document

`identities` is a nonempty array. Every identity requires these fields:

| Field | Meaning |
| --- | --- |
| `id` | Stable opaque ID matching `id:[a-z0-9][a-z0-9-]*`; never reused. |
| `username` | Canonical lowercase login correlation hint, 1–64 ASCII letters/digits/dot/underscore/hyphen, starting with a letter. Not the primary key. |
| `name` | Nonempty trimmed Unicode display name; not unique. |
| `department`, `role` | Lowercase slugs; together identify exactly one role policy. |
| `status` | `active`, `on_leave`, `pre_hire`, or `terminated`. |
| `employment_type` | `employee` or `contractor`. |
| `manager_id` | Existing identity ID or null; no self-management or cycles. |
| `start_date` | ISO calendar date. |
| `end_date` | ISO calendar date or null; mandatory for contractors and terminated people. |

IDs and usernames must be unique. Display names may collide. Employee IDs
survive renames, transfers, and rehires. Date windows are **start-inclusive and
end-exclusive**, evaluated on the snapshot's UTC calendar date. Active and
on-leave people must have started and must not have reached their end date.
Pre-hires start strictly after the snapshot date. Terminated people have
started and have an end date on or before the snapshot date. Any end date is
strictly after the start date. An active/on-leave/pre-hire person's manager,
if set, must be active. Null means no HR manager is recorded, not auto-approval;
Module 4 must route review to an explicitly configured fallback reviewer.

Only authoritative HR context belongs here. Actual accounts, assignments,
source-native groups, passwords, risk scores, and scenario labels do not.
Personal contact, salary, and demographic data are unnecessary and omitted.

## Policy document

The remaining required fields are `effective_from` (ISO date, not after the
snapshot), `unlisted_access` (always `review`), `entitlements`, `role_policies`,
and `status_rules`. All three arrays are nonempty.

Each entitlement has a unique `id` matching
`ent:[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9-]*`, a trimmed `name` unique under Unicode
case folding, a trimmed
`description`, `type` equal to `permission`, `sensitivity` of `low`, `medium`,
`high`, or `critical`, and a boolean `privileged`. These are generic business
capabilities. Module 3 owns all mappings to native access. Sensitivity and
privilege are independent classifications; high sensitivity alone does not
mean administrative privilege.

Each role policy requires a unique `id` with prefix `pol:`, `department`,
`role`, and arrays of entitlement IDs called `expected`, `restricted`, and
`privileged`. Every department/role pair is unique. References must exist;
duplicates inside arrays are errors.

| Field | Meaning for an active identity |
| --- | --- |
| `expected` | Baseline access normally needed for the job. Missing access is a review signal, never a provisioning instruction. |
| `restricted` | Explicitly forbidden access. Must not overlap either allowed list. |
| `privileged` | Elevated access permitted for this profile when present, not automatically required. Each reference must have catalog `privileged: true`. |

An expected entitlement marked privileged in the catalog must also appear in
the profile's privileged list. Thus expected/privileged overlap is intentional;
restricted/allowed overlap is invalid. Catalog privilege remains global: an
elevated entitlement outside an identity's allowed list is still privileged.
Known entitlements outside all three lists require review; they are never
implicitly certified. Unknown discovered entitlements also require review.

Each status rule has only `status` and `access`: exactly one rule for every
supported status. `active` uses `role_policy`; all other statuses use `none`.
This is the prototype's conservative lifecycle policy, including suspended
access during leave and no pre-start provisioning. It is an explicit project
choice, not an external standard or a claim about every employer.

Module 4 applies lifecycle restriction before role rules, then explicit
restriction, then allowed access; other access remains reviewable. Nothing
here authorizes automatic remediation, even for terminated identities.

## Consumer API and validation

Python package `iga_hr` supports Python 3.11+. `load_bundle(identities_path,
policies_path)` and `validate_documents(identities_dict, policies_dict)` return
an immutable `Bundle` or raise `BundleValidationError`. Its `issues` tuple
contains records with `code`, `path`, and `message`. Parsing rejects duplicate
JSON keys, non-finite numbers, malformed UTF-8/JSON, files over 10 MiB each, and
unsupported schemas. JSON Schema Draft 2020-12 validation is followed by
cross-record and cross-document semantic checks. No partial bundle is returned.
At most 100 issues are reported per call; rejection is never relaxed by that cap.

Bundle has `schema_version`, `dataset_id`, `snapshot_at`, `synthetic`,
`effective_from`, `unlisted_access`, `identities`, `entitlements`,
`role_policies`, and `status_rules`. Nested records are frozen dataclasses;
collection fields are tuples. `identity_by_id(id)` and
`identity_by_username(username)` return an identity or None.
`policy_for(identity_id)` returns the matching role policy, raising KeyError
for an unknown identity. `context_for(identity_id)` returns a fresh JSON-ready
dictionary with `identity`, `role_policy`, and `status_rule`; it does not judge
any actual assignment. `summary()` returns JSON-ready counts and metadata.

CLI commands are `iga-hr validate IDENTITIES POLICIES [--json]` and
`iga-hr context IDENTITIES POLICIES ID`. Invalid inputs exit 1; usage errors
exit 2. Validation success exits 0. `python -m iga_hr` is equivalent.

## Handoff to later modules

Module 4 must associate source accounts with stable HR IDs through an explicit,
auditable correlation step. The username is only a candidate in a configured
source namespace; account reuse, multiple accounts, and unmatched accounts
must not be silently merged. Unknown accounts remain visible for review.
Module 3 owns native-to-generic entitlement mappings and real scan evidence.

Peer groups should use active identities with the same department and role;
contractors can be separated using employment_type. Small cohorts must not
be treated as statistically strong evidence. The demo intentionally includes
singleton manager cohorts to exercise this limitation later. Peer agreement
cannot override explicit restrictions. All actual findings, scores, decisions,
audit trails, and approved changes belong to Module 4 and the connector.

Loading a snapshot does not establish its freshness, authenticity, or historical
ID continuity. Module 4 must check these at ingestion and retain the exact
bundle/version used for each review. Moving employees requires a new snapshot;
retain the same ID and compare prior and current context, while checking current
discovered access against the current policy. M1 emits no access assignments.
