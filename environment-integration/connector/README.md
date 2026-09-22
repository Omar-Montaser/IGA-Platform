# Module 3 — Integration and Access Discovery

The only component that touches the Linux target system. Discovers access,
normalizes it into generic objects, and executes approved removals.

Implements the connector interface defined in
`governance-platform/access-review/docs/contract.md`.

## Architecture

```
transport.py     how the target is reached      SSH | local | captured fixture
discovery.py     native read                    Linux-shaped, no interpretation
normalize.py     ← THE BOUNDARY →               native in, generic out
remediation.py   generic instruction → native operation
api.py           HTTP surface
```

**Only `discovery.py` and `remediation.py` are Linux-specific.** Swap the target
for Active Directory and those two are rewritten; `normalize.py`'s output shape
and the API do not change. That is the generic-core claim made structural rather
than asserted.

**Transport is separate from discovery** because *how* you reach a system is
orthogonal to *what you read from it*. One parser serves all three transports,
and the fixture transport means the entire discovery path is unit-testable in CI
with no VM and no network.

**The safety guards live on the target, not in this package.** `iga-remediate`
sits on the box behind a two-command sudoers allow-list. If this connector were
compromised entirely it could still only invoke those two commands. Guards
implemented here would be one bug away from a full bypass.

## Transports

| `IGA_TRANSPORT` | Pattern | Use |
| --- | --- | --- |
| `ssh` | Agentless — the standard IGA pattern | **Demo and default.** Connector runs beside Module 4, reaches the target over SSH. |
| `local` | Agent-based | Connector runs on the target itself. |
| `fixture` | Read-only capture | CI. Serves `samples/`; revocation is refused by construction. |

Agentless is the pattern real IGA products use for Unix targets, because an
organisation can hold one credential but cannot deploy an agent to 500 servers.
Host keys are verified with paramiko's `RejectPolicy` — never `AutoAddPolicy`,
because an unknown host key means the target is not the machine we were told to
review.

### SSH setup

On the target, give the service account a key:

```bash
sudo mkdir -p /home/iga_svc/.ssh
sudo tee /home/iga_svc/.ssh/authorized_keys      # paste the public key, Ctrl-D
sudo chown -R iga_svc:iga_svc /home/iga_svc/.ssh
sudo chmod 700 /home/iga_svc/.ssh && sudo chmod 600 /home/iga_svc/.ssh/authorized_keys
```

Where the connector runs:

```bash
ssh-keyscan -p 2222 127.0.0.1 >> ~/.ssh/known_hosts
export IGA_TRANSPORT=ssh IGA_SSH_HOST=127.0.0.1 IGA_SSH_PORT=2222
export IGA_SSH_USER=iga_svc IGA_SSH_KEY=~/.ssh/id_ed25519
export IGA_TOKEN_SHA256=$(printf '%s' "$YOUR_TOKEN" | sha256sum | cut -d' ' -f1)
python3 -m iga_connector
```

## Endpoints

```
POST /scans        {source, request_id}   → normalized scan document
POST /revocations  approved request       → {request_id, status, message}
GET  /health       no credential          → liveness, mapping version, target
```

Both POST routes require `Authorization: Bearer <token>`, compared in constant
time against a SHA-256 hash. The token itself is never stored.

| Variable | Default | Purpose |
| --- | --- | --- |
| `IGA_TOKEN_SHA256` | — | SHA-256 of the service credential. Required. |
| `IGA_TRANSPORT` | `local` | `ssh` \| `local` \| `fixture` |
| `IGA_SSH_HOST/PORT/USER/KEY/KNOWN_HOSTS` | — | SSH transport settings |
| `IGA_FIXTURE_DIR` | `./samples` | Fixture transport source |
| `IGA_SOURCE` | `linux-lab` | Source name; must match the scan request |
| `IGA_MAPPING` | `/opt/iga-lab/entitlement_map.json` | Native↔generic mapping |
| `IGA_STATE` | `/var/lib/iga-connector/state.db` | Idempotency receipts |

## Deliberate decisions

**HTTP is our choice, not Module 4's requirement.** Module 4's actual contract is
the Python protocol `revoke(request)->dict` / `scan(source, request_id)->dict`;
`HTTPConnector` is one implementation and they also ship `FixtureConnector`. We
chose HTTP because it makes the module boundary *physical* — an importable class
is one careless import away from Module 4 reaching into connector internals.

**`sensitivity: "unknown"`, `privileged: null` — always.** A Linux connector has
no idea whether `finance_invoices_read` is business-critical. Module 1's catalog
is authoritative; the connector observes access and declines to offer a competing
opinion. The contract permits these values.

**Revocation success is an acknowledgement, never proof.** The response message
says so in words. Verification is a separate scan.

**Every change goes through `iga-remediate`.** This package never runs `gpasswd`
or edits sudoers itself.

**Accounts with no HR identity are still reported.** The scan includes every
non-system account, including service accounts with no HR match. Dropping them
would hide exactly the orphans a review exists to find, and Module 1's handoff
requires unmatched accounts stay visible.

**A managed group held as a PRIMARY group is still reported.** The lab never
creates that shape, but a real system can, and dropping it would under-report.

## Limitations we identified in the interface

Worth stating in the report rather than being caught by them in questions.

**Assignment `timestamp` is a fiction on Linux.** The source records no grant
time. We report the modification time of the file carrying the grant, clamped so
it is never after `scanned_at` — but `/etc/group`'s mtime is identical for every
group assignment on the box. The field should arguably be nullable; requiring it
invites connectors to fabricate precision they do not have.

**The scan asks the connector to classify entitlements.** `sensitivity` and
`privileged` are fields a source-system connector cannot honestly populate.
`unknown`/`null` is permitted and is what we emit, but the fields' existence
invites guessing that would silently compete with Module 1's catalog.

**Full snapshot per scan, no pagination.** Fine at 69 accounts, wrong at 50,000.
There is no cursor or incremental-scan concept in the contract.

**`complete` is a single boolean.** There is no way to express "accounts read
fully, sudo partially." Real connectors have patchy visibility; a coverage object
would carry more.

## Tests

```bash
python3 tests/test_connector.py
```

38 assertions against a live seeded lab: authentication, exact contract key sets,
referential integrity, the complete seeded truth discovered with nothing
invented, idempotent replay, conflicting key reuse, stale mapping version, wrong
source, and a revoke-then-verify cycle proving one assignment disappeared and
nothing else changed.

Verified on all three transports:

| Transport | Result |
| --- | --- |
| `ssh` | **38 passed, 0 failed** — 367/367 assignments discovered |
| `local` | **38 passed, 0 failed** — 367/367 assignments discovered |
| `fixture` | Runs offline; revocation refused as `fixture_is_read_only` |

The least-privilege boundary was checked by hand over SSH: `iga-inspect` and
`iga-remediate` succeed, and `sudo -n cat /etc/shadow` is refused.
