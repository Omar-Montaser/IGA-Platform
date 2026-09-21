# Module 4 design research

Research was checked during implementation. External guidance informs the
design; the repository contract and architecture remain the source of the
prototype's behavior.

## Authorization and decisions

FastAPI's security mechanisms supply building blocks, while permission checks
remain application behavior. OWASP recommends deny-by-default access and
authorization on every object request. The service therefore derives the
actor from a configured bearer credential, checks campaign/finding visibility
on reads and writes, routes findings to a server-side reviewer, and prevents a
principal from reviewing their own HR identity.

- [FastAPI OAuth2 scopes](https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/)
- [OWASP authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

OWASP's transaction guidance says the final authorization gate should apply to
the exact operation being executed. Module 4 rechecks the approving principal,
evidence freshness, and campaign status when it claims queued work. A decision
and connector request commit together; connector I/O happens afterward.

- [OWASP transaction authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

## Persistence and audit

SQLite `BEGIN IMMEDIATE` is used to serialize decision and queue claims. Every
connection enables foreign-key enforcement. A hash chain and database triggers
make application-level audit modification detectable and block ordinary update
or delete statements. This is useful prototype evidence, not an external
append-only log or protection against a database administrator replacing the
entire file.

- [SQLite transactions](https://www.sqlite.org/lang_transaction.html)
- [SQLite foreign keys](https://www.sqlite.org/foreignkeys.html)
- [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

Audit events record actor, time, action, finding/campaign references, outcome,
and request correlation. Credentials and remote error bodies are excluded.

## AI explanation boundary

The optional OpenAI adapter uses the Responses API with Structured Outputs.
Official documentation states that Structured Outputs constrain the response
to the supplied JSON schema. The adapter additionally validates the returned
recommendation and evidence-code set against deterministic engine output.

- [OpenAI Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)

Only enumerated categories, integer contributions, a boolean/null privilege
classification, and aggregate peer counts may leave through this adapter.
Names, usernames, source/account/entitlement IDs, correlation notes, raw scan
text, and reviewer reasons are not sent. `store` is false, tools are absent,
redirects are disabled, and failures use a clearly labeled local rule fallback.
AI output cannot authorize a decision or initiate remediation.

No real OpenAI request was made in the implementation verification. The adapter
was tested using mock HTTP transports. Live use requires an explicit model,
project API key, privacy review, deployment controls, and quality evaluation.

## Local policy choices

Risk weights, freshness windows, the five-peer minimum, rarity threshold, and
the conservative lifecycle precedence are project rules. They are versioned
and visible as evidence contributions. They are not NIST-calibrated risk
probabilities or universal employer policies. Module 1 remains authoritative
for HR state and generic policy; Module 3 remains authoritative for normalized
source evidence and target operations.
