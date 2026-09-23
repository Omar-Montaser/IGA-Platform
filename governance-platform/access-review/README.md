# Module 4 access review core

This project implements the core of the AI-assisted access review platform in
the system architecture. It consumes Module 1 identities and policies plus a
normalized Module 3 scan. It evaluates access, creates review findings, records
human decisions, queues approved revocations, and accepts a removal as verified
only after a new complete scan proves the capability is absent.

The core is source independent. It has no Linux commands, native group names,
or connection to Module 2. Module 3 owns native discovery, mapping, changes,
and fresh scans.

## Implemented

- Administrator Environment landing page before any campaign exists, with
  server-managed setup, saved inventory, start/progress/retry, and reload recovery.
- Durable SQLite campaign runs with fenced leases, pinned inputs/snapshots,
  bounded recovery and atomic campaign completion/supersession.

- Strict normalized scan v2 contract covering applications, accounts,
  business/application roles, groups, entitlements, assignments, direct and
  inherited grant paths, approved exceptions, and access history.
- Deterministic lifecycle and policy facts, hard safety constraints, peer
  evidence, and heuristic risk evaluation. The deterministic engine does not
  issue an access recommendation.
- Preservation of unknown, unmatched, ambiguous, and multiply granted access.
- Freshness, coverage, clock-skew, and lifecycle-boundary decision gates.
- SQLite persistence for retained input evidence, findings, decisions,
  remediation requests, verification scans, and hash-chained audit events.
- Bearer-principal authentication, role and object authorization, reviewer
  routing, self-review prevention, optimistic versions, and idempotency keys.
- Durable connector requests with leases and retry behavior.
- Verification requiring a different, later, complete scan with the same
  source and mapping version and coverage of the target entitlement.
- One independent review case per identity. When configured, Gemini (free-tier
  default) or the optional OpenAI reviewer receives the complete normalized case and independently
  returns retain/remove/investigate/escalate assessments, confidence, evidence
  references, questions, missing evidence, reasoning, and per-item actions.
- Explicit non-AI fallback when no provider is configured or a review fails.
  Fallback, low confidence, missing evidence, privileged access, hard
  constraints, and AI/engine disagreement are marked for mandatory human review.
- A persistent simulated connector and checked-in normalized evidence fixture for local
  end-to-end checks. It never modifies the host operating system.
- A secure same-origin reviewer browser interface with keyboard accessibility,
  visible focus states, proper ARIA labels, and responsive layout. The UI
  supports campaign listing, finding review with filtering, decision workflows,
  explanation requests, remediation processing, and audit log viewing. Bearer
  tokens are kept in memory only and never persisted to localStorage. All
  authorization checks remain server-side.

The risk score is a versioned project heuristic. It is not a probability or an
authorization decision. Peer rarity is evidence only and cannot override an
explicit restriction. AI assessment is advisory: it may disagree visibly with
the deterministic facts, but cannot override hard constraints, approve access,
or initiate connector requests.

## Local setup

Python 3.11 or newer is required. From `governance-platform/access-review`:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e ../hr-policy -e .
PYTHONPATH=src:../hr-policy/src .venv/bin/python -m unittest discover -s tests -v
```

Start the simulated demonstration with current Module 1 data:

```sh
iga-review demo --state-dir .demo-review
```

The command prints the path to a generated reviewer token and starts the core
API at `http://127.0.0.1:8040`. The reviewer UI is available at the root URL.
Open a web browser and navigate to `http://127.0.0.1:8040`, then paste the
token from `.demo-review/reviewer-token.txt` to sign in.

To begin with **no campaigns**, use `iga-review demo --empty --state-dir
.demo-review/environment-first` with a new directory. `--empty` only affects
first initialization; subsequent starts preserve campaigns and simulated
removals. Administrators land on Environment, choose a name, click **Start access
review**, inspect **Recorded progress**, then **Open review findings**. Refresh
status never scans the target. Reload requires signing in again; the saved run
and campaign return. Reviewers land on their authorized campaigns.

For exact Windows commands and server input configuration, see the
[environment-first quick start](../../SETUP-AND-RUN-GUIDE.md#environment-first-quick-start-windows).
Synthetic demo HR dates are rebased only in a pinned copy for each new run; real
input files and historical evidence are never refreshed automatically. New demo
JSON is UTF-8; old Windows cp1252 demo-import files remain readable.

Use the HTTP contract in [contract.md](docs/contract.md) for API integration.
The generated `.demo-review` state contains credentials and is ignored by Git.

For a non-demo deployment, initialize state with `iga-review init`, edit its
protected `config.json` to add configured principals and connector entries,
provide connector tokens through the named environment variables, then run
`iga-review serve`. Production identity-provider integration is intentionally
not claimed by this prototype configuration.

## Activate AI (Gemini or Groq)

The default integration is **Gemini 3.8 Flash with high reasoning**, selected for
strong reasoning and schema-constrained responses on a free API tier. This is
not a claim that it wins every benchmark. Model and free-tier availability were
checked on 2026-09-22 against Google's
[model documentation](https://ai.google.dev/gemini-api/docs/models/gemini-3.8-flash)
and [pricing](https://ai.google.dev/gemini-api/docs/pricing).

On Windows, install into a working environment first (Python 3.11+):

```powershell
# From governance-platform/access-review. Skip installation if already installed.
python -m venv .venv-ai
.\.venv-ai\Scripts\python.exe -m pip install -e ../hr-policy -e .
.\setup_ai.ps1 -Provider gemini
.\.venv-ai\Scripts\python.exe -m iga_review.cli demo --state-dir .demo-review/gemini
```

For Groq, use `./setup_ai.ps1 -Provider groq`; its default model is
`llama-3.3-70b-versatile`, and its printed demo command uses `.demo-review/groq`.
It uses JSON-object mode plus shared local validation, not unsupported strict
JSON-schema mode. See [Groq output modes](https://console.groq.com/docs/structured-outputs).
`setup_gemini.ps1` remains a compatibility entry point.

The setup script prompts privately for a [Google AI Studio key](https://aistudio.google.com/api-keys)
or [Groq key](https://console.groq.com/keys),
keeps it only in the current PowerShell environment, and performs one real
structured generation with synthetic evidence. It does not print/store the key,
delete review history, or start a campaign automatically. Use `-Python <path>`
to select another interpreter with Module 4 installed. Run the demo from this
module's directory, in the same PowerShell session.

Use a project **without billing enabled**. A model having a free tier does not
make calls free when your key belongs to a billed project. The application
cannot inspect billing status and never switches models or providers on quota
failure. Free quota varies by project/region and is not unlimited. Calls are
serialized and spaced at least six seconds apart; 429 responses open a 60-second
cooldown and remaining cases receive an explicit non-AI fallback. Large campaigns
can take several minutes or exceed free quota. No automatic retry/reassessment
of persisted fallbacks is performed; import a fresh scan after quota recovers.

Manual configuration is also supported:

- `IGA_AI_PROVIDER=gemini`, `GEMINI_API_KEY` (or `GOOGLE_API_KEY`).
- `IGA_AI_MODEL=gemini-3.8-flash` (the pinned default; no paid model routing).
- `IGA_AI_PROVIDER=groq`, `GROQ_API_KEY`, and optional `IGA_AI_MODEL`
  (default `llama-3.3-70b-versatile`). Groq is explicitly selected, not auto-routed.
- `IGA_AI_INTERVAL_SECONDS=6` controls pacing (0–60 seconds).
- `iga-review ai-check` succeeds only after a validated AI response, not merely
  a successful authentication request. It returns nonzero on missing keys,
  quota/authentication failures, or invalid output.
- Without an explicit provider, `auto` selects Gemini only if a Gemini/Google
  key exists; otherwise it uses clearly labeled rules. `IGA_AI_PROVIDER=rules`
  disables external inference. The existing OpenAI adapter remains opt-in via
  `IGA_AI_PROVIDER=openai`, `OPENAI_API_KEY`, and `IGA_AI_MODEL`; it is not free.

**Data handling:** the entire person-level case is sent to the selected provider, including
identity/account data, justification, relevant roles/groups, history and
exceptions. Free-tier data may be used to improve Google's products. Use
synthetic data for this prototype. Non-demo startup requires explicit
`IGA_AI_ALLOW_REAL_DATA=1` after obtaining data-owner approval; this flag is not
an anonymization or compliance mechanism. `store=false` disables interaction
retrieval storage, not Google's broader data-use terms. Consent is also checked
on each non-synthetic import, so demo mode/direct service calls cannot bypass it.
The synthetic flag is a data-owner declaration, not automatic anonymization.
Keys never enter the UI,
campaign exports, or the review database.

The application preserves existing campaign assessments: enabling AI does **not** rewrite
their rules-only results. Use a new child directory under `.demo-review/` for a
new synthetic campaign, or import a genuinely fresh normalized scan. The UI
shows actual persisted provider/model/fallback information, not just the current
server configuration. A ready response means it passed structural validation;
it does not prove the assessment is correct. Humans retain decision authority.

## API flow

1. An administrator starts a campaign run for a configured environment. The
   backend pins HR/policy/correlation inputs and requests fresh connector evidence.
   Full-payload JSON import remains available for integrations.
2. The engine records immutable input digests, policy facts, and safety
   constraints, then the configured reviewer analyzes each person-level case.
3. An assigned human reviewer records `certify`, `revoke`, or `acknowledge` with a
   reason, current item version, and idempotency key.
4. A revoke decision atomically creates a connector request and audit event.
5. An administrator or worker processes the durable queue. Connector success
   means only that the request was accepted.
6. Module 4 requests a new scan and marks the item verified only when the
   scan passes every verification condition.

The exact schemas, response shapes, state machine, and security boundaries are
in [contract.md](docs/contract.md). Design research is in
[research.md](docs/research.md).

## Verified outcomes — 2026-09-23

- 163 Module 4 tests passed; provider calls are mocked or rules-only. This
  includes 28 campaign-run tests for idempotency, lease recovery, stalled-call
  shutdown/deadlines, atomic rollback/completion, freshness, immutable evidence,
  prior simulated removals, source-busy checks, authorization and consent.
- Prior Module 1 audit: all 67 tests passed, including fixture reproducibility;
  that suite was not rerun for the environment-first follow-up.
- 14 offline connector tests passed, including real localhost HTTP and
  authenticated campaign import/export with all 367 captured assignments.
- The separate captured-connector campaign-start test passed over real loopback
  HTTP: Module 4 → Module 3 fixture discovery/normalization → persisted campaign.
- 8 JavaScript runtime tests passed (DOM stub): submission idempotency, concurrent
  click suppression, polling, session cleanup, recovery, retry and escaping.
  JavaScript syntax checking passed.
- Browser: restarted empty synthetic demo, administrator sign-in, Environment
  before campaigns, stable input focus through polling, Start, recorded stages,
  campaign/finding access and completed-run recovery after reload/sign-in passed.
  A temporary delayed fixture/rules harness also verified reload during scanning
  and recovery while reviewing; this delay is not part of the shipped demo.
- No live Linux connection, native access change, paid call, external model review
  or AI accuracy evaluation was performed. Earlier `ai-check` reported not
  configured; it was not rerun here.

The service now enforces ownership blockers and hard-policy actions. Mandatory
review requires risk acknowledgement even when AI recommends retain. Each AI
item assessment must cite its own item reference. Unknown grant dates/group
privilege remain null; missing evidence is independently flagged and displayed
beside item-level source evidence. Orphan/cyclic paths are rejected and removal
verification checks all remaining target paths. Session cleanup and HTML
attribute escaping were hardened. Existing review history was not deleted.

See the [root README](../../README.md) for reproducible commands and scope.

## Intentionally left for follow-on work

- Integration with the organization's identity provider and user lifecycle.
- Deployment/revalidation of the implemented Module 3 connector against an
  authorized real target. Captures and local HTTP are tested; live SSH/RSA is not.
- Background worker supervision, production database choice, backups,
  deployment manifests, metrics, rate limiting, and operational alerting.
- Live model evaluation using an authorized project key and labeled review cases
  (mocked integration tests are not a quality or live-availability evaluation).
- Comprehensive cross-browser/accessibility testing beyond the verified local
  environment-first browser walkthrough. Runtime tests still use a DOM stub.

These items must not be represented as completed by simulated connectors or
mocked tests. Editable installation is the tested UI deployment; packaged-wheel
static assets and production deployment need separate acceptance work.
