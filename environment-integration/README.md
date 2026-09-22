# Environment Integration

Owns Module 2 (the Linux IAM environment under review) and Module 3 (discovery,
normalization, and approved remediation against it).

| Module | Scope | Status |
| --- | --- | --- |
| 2 | Linux IAM environment seeded from the Module 1 bundle | Implemented: seeder, native mapping, derived ground truth, reset. |
| 3 | Discovery, normalization, remediation service | Implemented: agentless SSH connector, FastAPI service, idempotent revocation, 38 tests passing on all three transports. |

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
    tests/          38 assertions against the live lab
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
| `unauthorized_privilege` | 5 |
| `unlisted` | 5 |
| `restricted` | 4 |

Those four values are taken from Module 4's `policy_result` vocabulary, so the
accuracy comparison at the end is a direct field match, not a translation.

## The native mapping is the architectural boundary

Generic entitlement IDs (`ent:finance:invoices-read`) never appear on the target
system. The box has POSIX groups and sudoers drop-in files. `entitlement_map.json`
is that translation table, and Module 3 owns it.

```
ent:finance:invoices-read     ->  posix_group  finance_invoices_read
ent:it:infrastructure-admin   ->  sudo         /etc/sudoers.d/90-iga-<username>
```

One entitlement is deliberately mapped to **sudo** rather than a group. Same
generic entitlement, completely different native representation — which is the
clearest single demonstration of why the normalization boundary exists.

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

## Module 3 — what still has to be built

Module 4 expects an **HTTP service**, not a CLI. From
`governance-platform/access-review/docs/contract.md` and `connector.py`:

- `POST /scans` — body `{source, request_id}` → a normalized scan document
- `POST /revocations` — body `{request_id, source, identity, entitlement, approved_by, approved_at, reason, scan_id, mapping_version, assignment_ids}` → `{request_id, status, message}`
- Bearer service token, `Idempotency-Key` header, no redirects, HTTP only on loopback

The scan document requires `schema_version` `1.0.0`, `scan_id`, `source`,
`scanned_at`, `complete`, `mapping_version`, `scope_entitlements`, `request_id`,
and arrays `identities` (accounts: `id`, `username`, `enabled`, `source`),
`entitlements`, and `assignments` (`id`, `identity`, `entitlement`, `source`,
`timestamp`). Unknown fields are rejected.

Two contract points worth building around from the start:

**`revoke` success is only an acknowledgement.** Verification requires a
*separate* scan with a different `scan_id`, matching `source`, `request_id` and
`mapping_version`, a timestamp after the request, complete scope covering the
target entitlement, and no assignment for that account+entitlement pair.

**Idempotency is required.** The same `request_id` must return the original
result; the same key with different content must fail.
