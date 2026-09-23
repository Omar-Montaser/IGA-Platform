# IGA access review prototype

The platform separates HR context and policies from the systems under review
and their connectors. The governance core consumes generic identity and
entitlement data.

| Module | Scope | Status |
| --- | --- | --- |
| 1 | HR identities and generic policies | Implemented with synthetic data, schemas, validation, consumer API, CLI, and tests. |
| 2 | Linux IAM environment | Seeder/helpers implemented. Pure planning/classification checked; native provisioning not run in this audit. |
| 3 | Integration and access discovery | SSH/local/fixture connector implemented. Captured discovery and real localhost HTTP tested; live SSH/removal not revalidated. |
| 4 | AI access review platform | Core implemented: person-level independent AI review, deterministic safety constraints, authenticated reviewer UI/API, durable decisions, exact grant-path remediation, fresh-scan verification, audit trail, CLI, and tests. |

Start with [Module 1](governance-platform/hr-policy/README.md) for the HR and
policy contract, then [Module 4](governance-platform/access-review/README.md)
for campaign ingestion, review decisions, and verified remediation.

The [governance platform](governance-platform/README.md) owns HR policy inputs,
access reviews, and the reviewer application. Module 1 publishes context to
Module 4; Module 3 owns native discovery, mappings and approved target changes.

## Verified audit outcomes — 2026-09-23

| Check executed | Outcome |
| --- | --- |
| Module 1 contract/generator suite | 67 tests passed. Fixed Windows line-ending reproducibility without changing data; `.gitattributes` keeps generated fixtures LF-only. |
| Module 4 suite | 133 tests passed. Includes AI protocol validation, privacy consent, ownership blockers, approvals, persistence and simulated revoke/rescan verification. Provider responses are mocked. |
| Offline connector/integration suite | 14 tests passed. Real localhost HTTP connector plus authenticated Module 4 import/export, persistence and audit integrity. No Linux target changes. |
| JavaScript runtime suite | 3 tests passed with a minimal DOM stub: safe attribute/text escaping, logout cleanup and stale-session response rejection. |
| Syntax checks | JavaScript and both PowerShell setup scripts passed. |
| Live AI check | Nonzero exit: `provider=rules`, `status=fallback`, `fallback_reason=not_configured`. No provider key was available. |

**367/367 captured assignments match the corrected Module 2 policy labels:**
319 expected, 34 lifecycle-restricted, 9 restricted and 5 unlisted. This is a
deterministic fixture consistency result, **not an AI accuracy measurement**.

### Fixes implemented

- Unresolved ownership now blocks decisions in the service. Hard policy rules
  remove invalid UI actions. Mandatory review requires risk acknowledgement
  even when the model recommends retaining access.
- Unknown Linux grant dates/group privilege remain `null`. Missing usage,
  history and justification are evidence limits, not invented facts. Reviewers
  can inspect per-item source evidence and model citations.
- Non-synthetic imports require consent before external inference, including
  imports through demo mode or direct service calls.
- Orphan/cyclic paths and incomplete/malformed native captures fail closed.
  Revocation payloads are validated before target access; UID lookup and helper
  exit-code checks cannot silently select/approve the wrong target.
- Preserved and repaired the Groq integration: Llama 3.3 uses JSON-object mode
  with strict local validation; truncated/refused/tool outputs are rejected.
  Gemini/Groq use bounded reads, request pacing and quota cooldown, with no
  automatic paid fallback. [Groq output-mode documentation](https://console.groq.com/docs/structured-outputs).
- Fixed HTML attribute escaping and clearing private review data on logout.
  Late responses from previous sessions are discarded.

### Reproduce the checks

From the repository root on Windows, with the Module 4 environment installed:

```powershell
.\governance-platform\access-review\.venv-ai\Scripts\python.exe -m unittest discover -s governance-platform/hr-policy/tests
.\governance-platform\access-review\.venv-ai\Scripts\python.exe -m unittest discover -s governance-platform/access-review/tests
.\governance-platform\access-review\.venv-ai\Scripts\python.exe -m unittest discover -s environment-integration/connector/tests -p test_offline_audit.py
node --test governance-platform/access-review/tests/ui_runtime.test.cjs
```

The separate legacy live connector script is skipped during test discovery.
It requires explicit execution, a disposable configured lab, and
`IGA_ALLOW_LIVE_MUTATIONS=1` for non-fixture transports.

### Not verified / remaining limitations

Live model availability, free quota and semantic review quality are **not
demonstrated**. Use the secure setup and synthetic inference check in the
[Module 4 guide](governance-platform/access-review/README.md) to activate AI.

This audit did not run native Linux seeding, SSH changes, RSA integration or
real-browser visual/accessibility testing. Existing lab helpers/ground-truth
files are not redeployed automatically by editing this repository. Production
SSO, operational hardening, large-scale scans and model-quality evaluation remain
follow-on work. The tested setup uses editable installs; packaged-wheel UI
assets still need acceptance work. Existing campaign history was preserved.
Passing tests cover specific cases, not a guarantee of zero bugs.
