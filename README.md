# IGA access review prototype

The platform separates HR context and policies from the systems under review
and their connectors. The governance core consumes generic identity and
entitlement data.

| Module | Scope | Status |
| --- | --- | --- |
| 1 | HR identities and generic policies | Implemented with synthetic data, schemas, validation, consumer API, CLI, and tests. |
| 2 | Linux IAM environment | Planned. |
| 3 | Integration and access discovery | Normalized evidence contract implemented in Module 4 with a stable fixture; live discovery connector remains planned. |
| 4 | AI access review platform | Core implemented: person-level independent AI review, deterministic safety constraints, authenticated reviewer UI/API, durable decisions, exact grant-path remediation, fresh-scan verification, audit trail, CLI, and tests. |

Start with [Module 1](governance-platform/hr-policy/README.md) for the HR and
policy contract, then [Module 4](governance-platform/access-review/README.md)
for campaign ingestion, review decisions, and verified remediation.

The [governance platform](governance-platform/README.md) owns HR policy inputs,
access reviews, and the reviewer application. Module 1 publishes context to
Module 4; a future live Module 3 connector will own native discovery, mappings,
and approved target changes.
