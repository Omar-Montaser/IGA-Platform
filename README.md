# IGA Platform

An evidence-led access review platform.

It combines HR context, observed environment access and human decisions in one
auditable workflow:

```text
HR and policy data
        ↓
Environment scan
        ↓
Policy evaluation
        ↓
Access review campaign
        ↓
Human decision
        ↓
Remediation and fresh-scan verification
```

The current product is centered on environment-first access reviews. An admin
can see configured sources before a campaign exists, start a durable run, follow
its progress, review findings, record decisions and inspect the audit trail.

## Start here

| Goal | Guide |
| --- | --- |
| Run the complete local demo | [Setup and Run Guide](docs/SETUP-AND-RUN-GUIDE.md) |
| Prepare a presentation | [Presentation Runbook](docs/PRESENTATION-RUNBOOK.md) |
| Understand the API and recovery rules | [Module 4 contract](governance-platform/access-review/docs/contract.md) |
| Read the product comparison and roadmap | [IGA comparison and roadmap](docs/IGA-PLATFORM-COMPARISON-AND-ROADMAP.md) |
| Understand the HR and policy input contract | [Module 1 README](governance-platform/hr-policy/README.md) |
| Understand discovery and remediation | [Connector README](environment-integration/connector/README.md) |

## Modules

| Module | Responsibility | Current state |
| --- | --- | --- |
| 1. HR policy | Identities, lifecycle status, roles and policy expectations | Implemented with strict schemas, validation, CLI and tests |
| 2. Linux IAM lab | Synthetic users, groups and policy scenarios | Planning and classification helpers implemented |
| 3. Connector | Discovery, normalization, HTTP/SSH transport and approved changes | Fixture and localhost HTTP paths tested; live SSH needs revalidation |
| 4. Access review | Campaigns, findings, decisions, remediation, verification and audit | Implemented with authenticated API, browser UI and durable runs |

Module 1 publishes the context used by Module 4. Module 3 owns native discovery,
mappings and target changes. Module 4 stays source-independent and consumes the
normalized scan contract.

## Offline demo

From PowerShell at the repository root:

```powershell
Set-Location 'C:\Users\MONTASER YOUSUF\Documents\IGA-Platform'
$env:IGA_AI_PROVIDER = 'rules'
& '.\governance-platform\access-review\.venv-ai\Scripts\python.exe' -m iga_review.cli demo --empty --state-dir '.\governance-platform\access-review\.demo-review\presentation' --identities '.\governance-platform\hr-policy\data\identities.json' --policies '.\governance-platform\hr-policy\data\policies.json' --port 8042
```

Open `http://127.0.0.1:8042`. The command prints the path to the generated
reviewer token. Keep that token local and paste it into the sign-in form.

For a clean starting screen, use a new state directory. The `--empty` option
does not delete an existing directory or reset previous simulated removals.

### Demo flow

1. Sign in as the administrator and open **Environment**.
2. Confirm the source is visible before any campaign exists.
3. Enter a campaign name and choose **Start access review**.
4. Follow **Queued**, **Scanning**, **Validating**, **Reviewing** and **Review ready**.
5. Open the findings, inspect evidence and record a human decision.
6. Open **Audit trail** to review the recorded action.
7. Reload, sign in again and confirm that the run and campaign remain available.

Rules mode is an offline fallback. It does not represent a successful external
model review.

## Design rules

- HR data says who the person is, their role and whether they should be active.
- The environment scan says which accounts, entitlements and grant paths exist.
- Ownership is never inferred from a matching name or username.
- Every run pins its input files and accepted scan evidence.
- Human decisions are authenticated, versioned and idempotent.
- AI output is advisory and cannot override hard policy constraints.
- A removal is verified only by a later complete scan that proves all target
  grant paths are gone.
- Audit events and accepted inventory snapshots are append-only.

## Verification status

Verified on 2026-09-24:

| Check | Result |
| --- | ---: |
| Module 1 contract and generator suite | 67 passed |
| Module 4 access-review suite | 164 passed |
| Offline connector and integration suite | 14 passed |
| JavaScript runtime suite | 8 passed |
| Total automated tests | **253 passed** |
| JavaScript syntax | Passed |

The Module 4 suite covers durable runs, lease recovery, shutdown, retries,
idempotency, freshness, correlation checks, atomic completion, authorization,
consent, remediation and verification behavior. Provider calls are mocked or
rules-only.

Run the checks from the repository root:

```powershell
& '.\governance-platform\access-review\.venv-ai\Scripts\python.exe' -m unittest discover -s governance-platform/hr-policy/tests
& '.\governance-platform\access-review\.venv-ai\Scripts\python.exe' -m unittest discover -s governance-platform/access-review/tests
& '.\governance-platform\access-review\.venv-ai\Scripts\python.exe' -m unittest discover -s environment-integration/connector/tests -p test_offline_audit.py
node --test governance-platform/access-review/tests/ui_runtime.test.cjs
node --check governance-platform/access-review/static/app.js
```

The captured fixture contains 367 assignments: 319 expected, 34 lifecycle-
restricted, 9 restricted and 5 unlisted. This is a deterministic fixture check,
not an AI accuracy result.

## Scope limits

The following still need separate validation:

- Native Linux seeding, live SSH discovery and native access changes
- Live external model availability, quota behavior and review quality
- A fresh real-browser pass after the latest UI stage-rail polish
- Cross-browser accessibility testing
- Production SSO, backups, metrics, rate limiting and worker supervision

Existing campaign history and local live-state files are preserved. The tested
setup uses editable installs; packaged-wheel UI assets need separate acceptance.
