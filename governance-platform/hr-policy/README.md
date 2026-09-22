# Module 1 HR identities and policies

Module 1 is implemented as the architecture's two data files plus their
validation and consumer interface. It supplies authoritative HR context and
generic policy intent to Module 4. It never connects to Linux or evaluates
actual access.

The [identity dataset](data/identities.json) contains **72 fictional people**
across six departments: 54 active, six on leave, six terminated, and six
pre-hires. Twelve people are contractors. The [policy dataset](data/policies.json)
defines 23 generic entitlements, sensitivity and privilege classifications,
12 department/role profiles, and explicit lifecycle rules. The snapshot is
frozen at **2026-09-21T00:00:00Z** for reproducible demonstrations.

## Run from a fresh checkout

Python 3.11 or newer is required. From this directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/iga-hr validate data/identities.json data/policies.json
.venv/bin/iga-hr validate data/identities.json data/policies.json --json
.venv/bin/iga-hr context data/identities.json data/policies.json id:person-0002
```

The validator reads both files and returns success only after every structural
and semantic check passes. It checks dates against the declared snapshot,
not today's date. JSON Schema validation alone is insufficient: always use
the bundle loader to enforce references, lifecycle rules, policy coverage,
and consistency between the files. Format checkers explicitly validate real
calendar dates and UTC timestamps without optional format dependencies.

Validation errors are printed to stderr with codes and document paths; exit
status is 1. Command usage errors return 2. Success returns 0. The commands
are read-only. `python -m iga_hr` provides the same interface.

## Consume from Module 4

Install this package into the platform's environment. Pass file paths explicitly;
the package includes the schemas, while demo data remains in this repository.

```python
from iga_hr import BundleValidationError, load_bundle

try:
    bundle = load_bundle("data/identities.json", "data/policies.json")
except BundleValidationError as error:
    for issue in error.issues:
        print(issue.code, issue.path, issue.message)
    raise

identity = bundle.identity_by_id("id:person-0002")
context = bundle.context_for(identity.id)
# context contains identity, role_policy, and status_rule.
# Actual assignments, findings, and decisions are Module 4 responsibilities.
```

The returned bundle is immutable. Each context request returns a new JSON-ready
dictionary; editing it cannot change the authoritative bundle. Unknown IDs
return `None` from identity lookups and raise `KeyError` from context/policy
lookups. Username lookup expects the canonical exact string and provides only
a correlation hint, not proof of account ownership.

## Verify and reproduce

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/generate_demo.py --check
.venv/bin/python scripts/generate_demo.py --output-dir /tmp/iga-hr-demo
.venv/bin/iga-hr validate /tmp/iga-hr-demo/identities.json /tmp/iga-hr-demo/policies.json
```

The generator is deterministic, uses only Python's standard library, and reads
no real employee data. It refuses to overwrite differing files unless `--force`
is passed. `--check` compares bytes without writing. Default output is this
project's `data` directory, independent of the working directory. Both files
are staged before replacement, but filesystem replacement of a pair is not a
transaction. Publish new data into a fresh directory, validate the pair, and
then switch the consumer to that immutable snapshot directory.

The test suite includes independently authored fixtures as well as the demo.
It exercises invalid structures and references, employment boundaries,
management cycles, policy conflicts, strict parsing, consumer immutability,
CLI exit codes, and generator reproducibility. Run these checks locally with
the command in this README.

## Design and scope

- [Research rationale](docs/research.md): primary sources and project decisions.
- [Data contract](docs/contract.md): exact fields, policy semantics, API, and versioning.
- [Dataset guide](docs/dataset.md): cohorts, identity examples, and policy coverage.

This is a custom contract informed by SCIM and NIST guidance; it is not a SCIM
server. HR lifecycle policy is explicit: only active people use role policy;
leave, pre-hire, and terminated statuses require no access. Missing expected
access is a review signal, not an instruction to provision it. Privileged
access may be optional, restrictions are explicit, and unlisted access requires
review. No rule authorizes automatic revocation.

Version 1 contains one employment interval and one department/role per person
per snapshot. Historical transitions require retaining prior snapshots. Account
correlation, native entitlement mapping, and actual scans remain responsibilities
of their owning modules. Module 4 consumes this context for review and controlled
remediation; successful Module 1 validation alone does not demonstrate those
later behaviors.
