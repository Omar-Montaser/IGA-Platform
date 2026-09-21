# IGA access review prototype

The platform separates HR context and policies from the systems under review
and their connectors. The governance core consumes generic identity and
entitlement data.

| Module | Scope | Status |
| --- | --- | --- |
| 1 | HR identities and generic policies | Implemented with synthetic data, schemas, validation, consumer API, CLI, and tests. |
| 2 | Linux IAM environment | Planned. |
| 3 | Integration and access discovery | Planned. |
| 4 | AI access review platform | Planned. |

Start with [Module 1](governance-platform/hr-policy/README.md) for setup,
the dataset, the contract, and verification commands.

[Environment integration](environment-integration/README.md) owns environment
setup, discovery, normalization, and approved remediation. The
[governance platform](governance-platform/README.md) owns HR policy inputs,
access reviews, and the future reviewer application. Module 1 publishes only
to Module 4; native access mappings and changes belong to Module 3.
