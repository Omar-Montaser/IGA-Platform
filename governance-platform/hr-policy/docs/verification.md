# Module 1 verification record

Verified locally on 2026-09-21 using CPython 3.13.0 on macOS and
`jsonschema` 4.26.0. This records the completed Module 1 checks, not the status
of the future Linux environment, connector, or access-review engine.

## Architecture coverage

| Architecture requirement | Delivered implementation |
| --- | --- |
| HR identities with id, username, name, department, role, status | `data/identities.json`, with employment dates/type and manager context for later lifecycle and review routing. |
| Expected, restricted, and privileged entitlements by department and role | Twelve explicit profiles in `data/policies.json`. |
| Entitlement sensitivity | Twenty-three generic catalog entries with sensitivity and separate privilege classification. |
| Module 1 sends identity context and rules to Module 4 | Versioned JSON contract, immutable Python bundle loader, context API, and read-only CLI. |
| Module 1 has no Linux dependency | No native group mappings, discovery, source credentials, target commands, or remediation code. |

## Results

| Check | Observed result |
| --- | --- |
| Demo bundle validation | Passed: 72 identities, six departments, 12 role policies, 23 entitlements. |
| Independently authored acceptance tests | 67 tests passed; includes subcases covering malformed inputs and lifecycle/policy boundaries. |
| Management graph robustness | Valid 1,500-person chain accepted; cyclic variant rejected. |
| Frozen fixture reproduction | Generator `--check` passed with byte-for-byte equality. |
| Package build and installation | Wheel built and installed successfully. |
| Installed consumer outside source directory | CLI validated both files from `/private/tmp` using the package in site-packages. |
| Packaged schemas | Both JSON Schema resources present in the built wheel. |
| Minimum-version syntax | All Python files parsed with Python 3.11 grammar; this is a syntax check, not a Python 3.11 runtime test. |
| Independent review | Repository, test, dataset, and runtime reviews completed; no blocking issue remained in the reviewed Module 1 scope. |

Regression coverage includes duplicate JSON keys, malformed UTF-8/JSON,
non-finite values, oversized/deeply nested input, control characters, invalid
dates, duplicate IDs/usernames/catalog names, manager references/cycles,
uncovered roles, dangling entitlement references, conflicting policy lists,
privilege classification, lifecycle boundaries, mismatched bundle metadata,
immutable records, detached context dictionaries, CLI exit behavior, and
generator reproducibility. Deliberately invalid test input remains outside
the authoritative dataset.

The GitHub Actions workflow is configured for Python 3.11, 3.12, 3.13, and
3.14 on Ubuntu, including an installed-package smoke check. It has not been
run remotely during this task. Local runtime results above are for Python
3.13 only. No commit, push, deployment, or live target scan is implied by
this verification record.

## Remaining work belongs to later modules

Module 1's implementation and local acceptance checks are complete. Modules
2–4 still need their own implementation and integration evidence, including
native access discovery, reliable account correlation, policy evaluation,
peer analysis, scoring, AI explanations, reviewer decisions, audit records,
approved revocation, and verification through a fresh scan. The
[handoff specification](handoff.md) supplies concrete cases for those tests.

The synthetic role matrix and conservative lifecycle choices are prototype
defaults. Validation establishes internal consistency; it does not establish
real HR accuracy, freshness, authenticity, production policy approval, or
absence of all defects.
