# Module 1 handoff and future acceptance scenarios

Module 1 supplies validated HR identities and policy intent to **Module 4**.
It has no data-flow dependency into Module 2 or Module 3. Discovery belongs to
the environment/connector path; Module 3 normalizes actual access and owns
native-to-generic entitlement mappings. Module 4 combines the independent
inputs for findings, scoring, AI-assisted explanations, review decisions, and
audit evidence. Approved target changes belong to the authorized connector
workflow.

The scenarios below are a **planned acceptance specification for later
modules**. They are not implemented findings, scan output, real VM results,
or evidence that the complete prototype has passed end-to-end testing.
Module 1 emits no actual access assignments.

## Loading and retaining the HR context

Use `iga_hr.load_bundle(identities_path, policies_path)` to load the pair, or
`validate_documents(...)` for already parsed JSON values. Handle
`BundleValidationError` as a rejected bundle. Do not evaluate access against
one accepted file and one rejected or older file.

Use stable identity IDs when requesting `bundle.context_for(identity_id)`.
The context contains `identity`, `role_policy`, and `status_rule`; it is policy
input rather than a conclusion about an account's assignments. See
[contract.md](contract.md) for field and API definitions.

Before real reviews, Module 4 needs to:

1. Check publisher provenance, configured freshness limits, schema version,
   and snapshot suitability for the scan period. A valid old snapshot is
   still old; this validator intentionally does not use the machine's clock.
2. Preserve the exact identity and policy payloads used for a review, along
   with their metadata and content digests. Record scan time and mapping
   version separately. Digest storage is a future consumer responsibility,
   not a signature or authenticity feature of Module 1.
3. Resolve source accounts to HR IDs through an auditable correlation step.
   Preserve the source namespace and immutable native account identifier
   where the connector provides one. Treat a username as candidate evidence.
4. Retain unmatched and ambiguous accounts for review instead of dropping
   them or inventing an HR identity. Keep multiple source accounts distinct
   even when they are linked to one person.
5. Retain native access evidence and mapping provenance. Unknown capabilities
   must remain visible; they must not disappear because no catalog ID exists.
6. Route reviews to an explicitly configured fallback when `manager_id` is
   null. An absent manager is not permission to approve an item automatically.

Neither Module 1 nor this handoff defines risk weights, automatic remediation,
exception approval, or a statistical anomaly threshold. Module 4 must make
those choices explicitly before claiming those behaviors are supported.

## Policy interpretation for later tests

Apply the identity's status rule before the role policy. For active identities,
explicit restrictions override allowance. Expected access is the baseline;
privileged-list access is permitted but optional unless also expected. Known
access outside the three lists and unknown discovered access require review.
The global catalog privilege flag remains meaningful even when a role does not
allow that entitlement. Missing expected access is a review signal and never
an instruction to grant access automatically.

Lifecycle examples use the bundle's UTC snapshot day. To test a later day,
produce a new internally consistent snapshot; do not silently substitute the
test runner's current date. End dates are exclusive. An active expired
contractor is invalid HR input, not a successful access-review test case.

## Planned scan acceptance matrix

For each scenario, a later test should construct source evidence separately,
normalize it through Module 3, and compare it with a validated Module 1
bundle. Select suitable identities and entitlement IDs from that bundle;
the scenario descriptions do not add fields to the HR contract.

| Scenario | Future test setup | Required observable outcome in Module 4 |
| --- | --- | --- |
| Expected access present | Active person has a capability in `expected`, with no lifecycle restriction. | Recognize expected access as allowed by this policy; preserve evidence. Do not treat this fact alone as whole-account certification. |
| Expected access missing | A complete, applicable scan lacks one expected capability. | Produce a missing-baseline review signal. Distinguish absence from failed or incomplete scan coverage; do not provision it. |
| Explicitly restricted access | Active person has a capability in `restricted`. | Produce a policy-conflict finding with the relevant profile and capability. Peer prevalence cannot override it. |
| Allowed optional privilege | Active person has a catalog-privileged capability in the profile's `privileged` list but not `expected`. | Recognize permitted elevated access. Its absence in a companion test must not become missing-baseline access. |
| Required privilege | A privileged capability is in both `expected` and `privileged`. Test once present and once absent. | Allow its presence under the role policy; treat its absence as missing baseline. Preserve its elevated classification in either case. |
| Unauthorized privilege | Active person has a catalog-privileged capability outside that profile's allowed lists. | Surface elevated access without role permission; do not lose its privilege flag. If explicitly restricted, retain that conflict too. |
| Known unlisted access | Active person has a nonprivileged catalog capability outside all three policy lists. | Require review under `unlisted_access: review`; do not implicitly certify it or mislabel it as explicitly restricted. |
| On leave | Consistent `on_leave` person still has otherwise expected or allowed privileged access. | Apply `access: none` ahead of the role lists and flag retained access. Do not report baseline access as missing while leave restrictions apply. |
| Leaver | Consistent `terminated` person has discovered access after their exclusive end date. | Surface retained access under the lifecycle restriction, with date context and source evidence. Do not execute revocation solely from this finding. |
| Pre-hire | `pre_hire` person's start date is after the snapshot and an account already has access. | Apply `access: none` under the prototype's no-pre-start-access rule. |
| Contractor expiry boundary | Compare a contractor's valid active snapshot before the end date with a valid terminated snapshot on that end date; retain actual access in both scans. | Apply role context before expiry and lifecycle restriction at expiry. Reject an active snapshot on the end date at ingestion. |
| Unknown account | A discovered account has no reliable HR match. | Keep an unmatched-account review item with source identity evidence; do not discard it or assign someone else's role. |
| Reused username | An old account and a new HR person share a login string, but stable identity/history evidence does not establish ownership. | Require explicit correlation resolution; do not attach old access or prior review decisions to the new person by username alone. |
| Multiple accounts per person | Two distinct source accounts are explicitly correlated to the same HR ID. | Preserve each account and its evidence while evaluating the person's context; avoid overwriting one account with the other. |
| Duplicate display name | Two people share a display name, with distinct stable IDs and usernames. | Keep the identities separate and correlate through account evidence, not the display name. |
| Unknown entitlement | Discovery yields a native permission with no supported generic mapping. | Preserve the unmapped native evidence and require review; do not silently drop it or guess its sensitivity/privilege. |
| Mover snapshots | Same stable HR ID changes department/role in a second valid snapshot while the current scan retains an old capability. | Evaluate current access against the new profile; record the context change and old/new snapshot references. Classify old access according to the new rules, rather than assuming every transfer revokes every old capability. |
| Policy-only change | Same identity and access; a later valid policy snapshot newly restricts a capability. | Use the correct policy snapshot and explain the changed result without inventing an HR move. |
| Peer anomaly | One active person differs from same-department/same-role active peers; include a separate singleton cohort. | Expose cohort definition, count, and evidence. Suppress unsupported strong statistical conclusions for sparse cohorts; do not treat rarity alone as a policy violation. |
| Shared prohibited access | Every peer has the same restricted capability. | Preserve the restriction finding despite peer agreement. |
| Missing reviewer | A reviewable person's `manager_id` is null. | Route to a configured fallback; otherwise mark review routing unresolved and preserve the item. |
| Invalid HR or mismatched files | Pair files from different snapshots, break a manager reference, or assign an unknown role profile. | Reject the bundle before evaluating access; make the validation issues inspectable. |
| Stale or incomplete evidence | Supply structurally valid old HR data or a scan with incomplete source coverage. | Apply configured freshness/coverage handling and expose the limitation; do not report absence of evidence as proven absence of access. |

## Evidence needed before moving beyond the prototype

Module 1 checks can establish that its dataset and consumer contract work.
The later modules must separately demonstrate account correlation, native
mapping accuracy, scan coverage, lifecycle precedence, review routing,
explanations linked to evidence, and approved-action auditing. A green Module
1 validation command is not a security assessment of a VM or target system.

When implementing the matrix, record actual test results in the owning
module. Keep this document as the scenario specification and do not replace
missing integration evidence with synthetic success reports.
