# Synthetic HR and policy dataset

The two JSON files are a reproducible demo of authoritative HR context and
generic business policy, frozen at **2026-09-21T00:00:00Z**. All identities and
employment histories were invented for this project. No employee export,
public people dataset, personal contact information, or observed access was
used. A coincidental match to a real name does not identify a real person.

The contract is [contract.md](contract.md); the rationale and primary-source
research are in [research.md](research.md). JSON is the interchange format so
that arrays, null manager/end-date values, booleans, and versioned metadata are
represented directly and checked before later modules consume them.

## Dataset composition

The dataset contains **72 identities, 23 generic entitlements, 12 role
policies, and four lifecycle rules**. The policy effective date is 2026-09-01.
Every department contains eight active specialists, one active manager, one
specialist on leave, one terminated specialist, and one pre-hire specialist.

| Department | Specialist role | Manager ID | Specialist ID range |
| --- | --- | --- | --- |
| engineering | software-engineer | id:person-0001 | id:person-0002–0012 |
| finance | financial-analyst | id:person-0013 | id:person-0014–0024 |
| hr | people-operations-specialist | id:person-0025 | id:person-0026–0036 |
| sales | account-executive | id:person-0037 | id:person-0038–0048 |
| marketing | marketing-specialist | id:person-0049 | id:person-0050–0060 |
| it | service-desk-analyst | id:person-0061 | id:person-0062–0072 |

Manager role names are `<department>-manager`. Policy IDs are
`pol:<department>-specialist` and `pol:<department>-manager`.

| Dimension | Counts |
| --- | --- |
| Status | 54 active; 6 on_leave; 6 terminated; 6 pre_hire |
| Employment type | 60 employees; 12 contractors |
| Active department/role cohort | 8 specialists; 1 manager per department |
| Active specialists, separated by employment type | 6 employees and 2 contractors per department |
| Catalog privilege | 5 privileged; 18 nonprivileged entitlements |
| Manager references | 66 references to active managers; 6 roots with null manager |

The managers represent department leadership, with no higher manager recorded
in this demo. Each specialist reports to their department's active manager;
there are no self-links, cycles, or inferred cross-department reporting lines.
A null manager requires a separately configured fallback reviewer in Module 4.

## Cases for downstream development

Within each 12-person department block, the first person is the manager, the
next eight are active specialists, then come the on-leave, terminated, and
pre-hire specialists. For example, engineering has active specialists
`id:person-0002` through `id:person-0009`, on-leave `id:person-0010`, terminated
`id:person-0011`, and pre-hire `id:person-0012`.

- Engineering `id:person-0002` and finance `id:person-0014` both display
  **Alex Morgan**, with distinct usernames `alex.morgan.0002` and
  `alex.morgan.0014`. Names cannot establish identity or account correlation.
  `id:person-0003` (**Zoë Bennett**) and `id:person-0015` (**Renée Nguyen**)
  exercise UTF-8 display names while keeping canonical usernames ASCII.
- The final two active specialists in every department are contractors with
  end date **2027-03-31**. The final active specialist started **2026-09-20**;
  the other contractor started **2026-06-01**. Engineering examples are
  `id:person-0008` and `id:person-0009`. Recent start dates supply context for
  a later review; they are not an anomaly label or permission exemption.
- Terminated people have end date **2026-09-21**, the exact snapshot boundary.
  The end date is exclusive, so their employment has ended on the snapshot
  date. Pre-hires start **2026-10-05**. Both groups, and people on leave, have
  lifecycle access policy `none`, regardless of the role baseline.
- Finance managers are expected and permitted to have the privileged
  `ent:finance:payments-approve` capability. IT managers likewise have
  expected and permitted `ent:it:infrastructure-admin`. This exercises the
  intentional overlap of `expected` and `privileged` lists.
- Engineering managers may hold `ent:engineering:production-deploy`, HR
  managers may hold `ent:hr:payroll-admin`, and finance managers may hold
  `ent:finance:ledger-admin`; these optional privileged permissions are not
  expected baselines. Specialists are explicitly restricted from all five
  catalog privileges. None of these rules grants access automatically.
- High-sensitivity employee records, customer records, and source code are
  not marked privileged merely because the data is sensitive. Privilege is
  explicitly modeled separately. `ent:security:audit-read` is deliberately
  unlisted for every profile, supplying a known catalog capability that
  always needs review if encountered later.

The departments and role matrices are prototype choices, not a complete
enterprise role design or a segregation-of-duties engine. Real policy owners
must approve organization-specific rules before production use.

## Planning for subsequent snapshots and modules

Stable IDs are the join keys. Preserve an ID across a rename, department/role
change, or rehire; never recycle it. The numeric IDs do not encode authority,
department, username, or account ownership. Their demo allocation order is
not a rule consumers should depend on.

A future mover fixture can copy a snapshot, retain an identity's ID, and
change its department, role, and manager together. Advance `snapshot_at`,
version the dataset, and retain the prior snapshot for comparison. The
current dataset does not claim to contain a recorded transfer or employment
event history. Leave return, pre-hire activation, and contractor expiry also
require explicit subsequent HR snapshots. Do not simply advance the date
of this file: its fixed statuses and dates are mutually validated.

Peer grouping can use the eight active specialists per department/role,
excluding non-active identities. Separating contractors creates smaller
groups of six and two. Manager cohorts contain one person. These sizes are
useful for deterministic development cases, not statistical assurance;
peer frequency cannot override explicit restrictions. No actual grant
distribution, peer outlier, account scan, revocation, or finding is asserted
by these HR files. Later modules must supply their own clearly identified
source evidence and test fixtures.

Keep actual accounts and assignments, native group mappings, risk scores,
scenario labels, and review outcomes outside the HR dataset. Module 3 owns
native-to-generic mappings; Module 4 owns account correlation and comparison
against this context. An unmatched account remains visible for review.

## Reproduction and safe changes

From the `hr-policy` project directory, using Python 3.11 or later:

```sh
python3 scripts/generate_demo.py --check
python3 scripts/generate_demo.py --output-dir /tmp/iga-hr-demo
```

Generation uses only the Python standard library and no clock, random seed,
network service, or third-party dataset. The default output directory is
resolved relative to the generator file, so changing the working directory
cannot redirect it. Files use deterministic UTF-8 JSON, two-space indentation,
and one final newline. `--check` compares both files byte for byte and writes
nothing; it exits 1 for any missing or different file and 0 for an exact match.

Generation leaves identical files untouched. It refuses to overwrite a
differing file unless `--force` is explicitly supplied and refuses output-file
symlinks even with that flag. Both destinations are checked before writing,
and each replacement is staged and atomic. The two-file pair is not a
transaction across filesystem failures, so validate the pair after generation
and distribute both documents together. Never use `--force` on a real HR export.

To intentionally revise this frozen demo, edit the generator, regenerate with
`--force`, validate both JSON files with the Module 1 CLI, and run its tests.
Commit the generator and resulting data together. Reproduction verifies source
consistency; it does not prove the freshness or authenticity of imported HR.
