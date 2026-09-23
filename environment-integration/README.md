# Environment Integration

Owns Module 2 (the Linux IAM environment under review) and Module 3 (discovery,
normalization, and approved remediation against it).

| Module | Scope | Status |
| --- | --- | --- |
| 2 | Linux IAM environment seeded from the Module 1 bundle | Implemented; pure planning/classification checked against Module 4. Native seeding/reset not run in this audit. |
| 3 | Discovery, normalization, remediation service | Implemented; 14 offline audit tests cover captured discovery, strict requests, read-only remediation and localhost HTTP. Live SSH/local target operations not run in this audit. |

## Layout

```
environment-integration/
  linux-lab/
    lab.py          Module 2 seeder / reset / capture
  connector/        Module 3 service
    src/iga_connector/
      transport.py    how the target is reached: ssh | local | fixture
      discovery.py    native read - Linux-shaped, no judgement
      normalize.py    the boundary - generic objects out
      remediation.py  approved removal via the guarded helper
      api.py          POST /scans, POST /revocations
    tests/          offline audit tests and an opt-in live lab script
    README.md
  samples/          captured raw system state (committed, for offline parser work)
```

## Module 2 in one paragraph

`lab.py` reads Module 1's `identities.json` and `policies.json` and builds a real
Ubuntu access landscape from them: one POSIX account per HR identity that should
have one, group memberships matching each role's `expected` list, and a set of
deliberate access problems layered on top. It then derives the answer key from
Module 1's own policy rather than restating it, so the lab cannot disagree with
the policy it is supposed to violate.

Current dataset (`access-review-demo-2026-09-21`): 67 accounts, 22 POSIX groups,
3 sudo grants, **367 assignments of which 48 violate policy (13%)**.

| Expected policy result | Count |
| --- | --- |
| `lifecycle_restricted` | 34 |
| `restricted` | 9 |
| `unlisted` | 5 |
| `unauthorized_privilege` | 0 |

These values are taken from Module 4's `policy_result` vocabulary, so the
comparison is a direct field match rather than a translation. The audit checks
all 367 assignment classifications against Module 4, including the 319 expected
ones. This is deterministic policy agreement, not AI accuracy.

Five explicitly restricted privileged grants were previously mislabeled
`unauthorized_privilege` by the lab classifier; explicit restriction now takes
precedence, matching Module 4's engine. Ground-truth files already written to a
target are not retrospectively regenerated - re-seed to refresh them.

`unauthorized_privilege` is therefore **zero, and cannot be anything else with
this dataset**. Module 4 reserves that label for elevated access a role policy
does not mention in any of its three lists, and all twelve of Module 1's role
policies name all five privileged entitlements explicitly. The branch is
unreachable here. That is a property of the policy data, not a gap in the lab -
worth stating, because a reader will otherwise assume the category was missed.

## Two scenarios

`--scenario b` rebuilds the same company with a different set of planted
problems. The answer key is re-derived from Module 1 policy either way, so
switching costs nothing to maintain - there is no second truth file to keep in
step.

```
sudo python3 lab.py reset --bundle ~/bundle --scenario b
```

| | A | B |
| --- | --- | --- |
| accounts | 67 | 69 |
| assignments | 367 | 374 |
| violations | 48 (13%) | 55 (14%) |
| `lifecycle_restricted` | 34 | 41 |
| `restricted` | 9 | 8 |
| `unlisted` | 5 | 6 |

B is not a tweak of A. Different people hold the extra grants, and the
lifecycle cases are inverted: everyone cleaned up correctly in A is a leftover
in B, and everyone left behind in A is cleaned up in B. A review that was
reproducing a remembered answer rather than reading the machine would be
exposed by that inversion, which is the point of having the second scenario at
all.

## The native mapping is the architectural boundary

Generic entitlement IDs (`ent:finance:invoices-read`) are not native group names.
They may appear in mapping artifacts and comments; native access is represented
by POSIX groups and sudoers drop-in files. `entitlement_map.json` is the
translation table, and Module 3 owns it.

```
ent:finance:invoices-read     ->  posix_group  finance_invoices_read
ent:it:infrastructure-admin   ->  sudo         /etc/sudoers.d/90-iga-<username>
```

One entitlement is deliberately mapped to **sudo** rather than a group. Same
generic entitlement, completely different native representation — which is the
clearest single demonstration of why the normalization boundary exists.

Under scan schema v2 this shows up in the output shape as well as the
vocabulary: a group membership is reported as an **inherited** grant path
(account → group → entitlement) and a sudoers drop-in as a **direct** one
(account → entitlement). Module 4 sees the structural difference and never
learns the word *sudoers*.

## Artefacts written to `/opt/iga-lab/`

| File | Consumer | Purpose |
| --- | --- | --- |
| `entitlement_map.json` | Module 3 | Native-to-generic mapping, `mapping_version` 1.0.0 |
| `correlations.json` | Module 4 | Explicit account-to-HR bindings for the import payload |
| `ground_truth.json` | Module 2 only | Derived answer key — withhold until measurement |
| `managed_groups.txt` | `iga-remediate` | Removal allow-list |
| `seed_manifest.json` | `lab.py destroy` | What was created |

`correlations.json` matters more than it looks. Module 4's contract states
bindings are explicit and **never inferred from username**, and this dataset
contains two distinct people both named *Alex Morgan* (`alex.morgan.0002` in
engineering, `alex.morgan.0014` in finance). Name-based correlation would merge
them.

Its `account_id` values must match the account IDs in the scan exactly
(`linux-lab:uid:<uid>`), and each entry carries exactly the three keys Module 4's
`Correlation` model declares — it sets `extra='forbid'`, so a helpfully-added
`username` key is rejected outright. The username lives in the `evidence` string
instead.

## Privileged surface

The connector authenticates as `iga_svc`, which can run exactly two commands:

```
iga_svc ALL=(root) NOPASSWD: /usr/local/sbin/iga-inspect, /usr/local/sbin/iga-remediate
```

`iga-inspect sudo` reads the sudoers drop-ins (privileged read).
`iga-remediate` performs removals behind guards that refuse system accounts
(uid < 1000), the service account itself, primary-group removal, groups outside
the managed mapping, and any change that fails `visudo -c` — which is rolled back.

That is the entire privilege surface of the connector. Not a service account
with blanket root.

## Scan schema v2.0.0

Module 4 moved the contract from v1 to v2 after the connector was built. The
connector now emits all nine required collections:

| Collection | Content |
| --- | --- |
| `applications` | One — the Linux host. A department prefix inside an entitlement ID is Module 1's vocabulary, not an application boundary this connector can observe. |
| `identities` | Accounts, with `application_id` and `account_type`. |
| `roles` | Empty. Linux has no role layer between an account and a group. |
| `groups` | The managed POSIX groups, as generic group nodes. |
| `entitlements` | The mapping scope, with `application_id`. |
| `grant_paths` | How each holding was reached — direct or inherited. |
| `assignments` | One per account+entitlement, citing every path that carries it. |
| `exceptions` | Empty. The target records no approved exceptions. |
| `history` | Empty. The target records no grant history. |

The normalizer owns the generic output shape. This audit also tightened
discovery and transport behavior: malformed or partial reads must fail rather
than produce a falsely complete scan. Unknown grant timestamps and group
privilege are emitted as `null`, not fabricated from file times or defaults.

Their model sets `extra='forbid'` and `strict=True`, so three rules apply:
unknown fields are rejected, nothing is coerced (`enabled` must be a real
boolean), and a nullable field has no default — it must be **present** as `null`
rather than omitted.

The connector's test suite imports Module 4's own `Scan` model and validates
against it, so the next contract change fails in our tests rather than during a
live campaign.
