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
- One independent review case per identity. When configured, the OpenAI
  Responses reviewer receives the complete normalized case and independently
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

Use the HTTP contract in [contract.md](docs/contract.md) for API integration.
The generated `.demo-review` state contains credentials and is ignored by Git.

For a non-demo deployment, initialize state with `iga-review init`, edit its
protected `config.json` to add configured principals and connector entries,
provide connector tokens through the named environment variables, then run
`iga-review serve`. Production identity-provider integration is intentionally
not claimed by this prototype configuration.

## API flow

1. An administrator imports one JSON object containing validated Module 1
   documents, a normalized scan, and explicit account-to-HR correlations.
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

## Intentionally left for follow-on work

- Integration with the organization's identity provider and user lifecycle.
- A deployed Module 3 connector. The normalized v2 consumer contract and a
  stable synthetic fixture exist; live source discovery does not.
- Background worker supervision, production database choice, backups,
  deployment manifests, metrics, rate limiting, and operational alerting.
- Live OpenAI evaluation with an explicitly selected model and project key.
- Comprehensive browser-based UI testing (current tests verify HTML structure,
  accessibility attributes, JavaScript security patterns, and API integration
  without requiring a browser runtime).

These items must not be represented as completed by the simulated connector or
mocked tests. The continuation prompt supplied with this implementation defines
the next core milestones and acceptance gates.
