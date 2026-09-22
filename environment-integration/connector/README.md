# Module 3 — Integration and Access Discovery

The only component that touches the Linux target system. Discovers access,
normalizes it into generic objects, and executes approved removals.

Implements the connector interface defined in
`governance-platform/access-review/docs/contract.md`, **scan schema v2.0.0**.

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

The claim was tested in practice when Module 4 moved from scan schema v1 to v2.
The contract gained four collections and changed three object shapes. Every line
that had to change was in `normalize.py`. `transport.py` and `discovery.py` were
not touched.

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
| `IGA_SERVICE_ACCOUNTS` | `iga_svc` | Comma-separated. Accounts reported as `account_type: service` |
| `IGA_MAPPING` | `/opt/iga-lab/entitlement_map.json` | Native↔generic mapping |
| `IGA_STATE` | `/var/lib/iga-connector/state.db` | Idempotency receipts |

## Scan v2: paths, not just holdings

v1 asked *what* access an account holds. v2 also asks *how it was reached*, as
`grant_paths`. Our two native representations produce two different path shapes:

```
POSIX group membership  →  inherited  [account, group, entitlement]
sudoers drop-in         →  direct     [account, entitlement]
```

Their validator enforces the correspondence — `direct` must be exactly two hops —
so the distinction cannot rot silently. This is the sharpest demonstration in the
project of why the normalization boundary exists: one generic entitlement,
`ent:it:infrastructure-admin`, reached by a structurally different route from
every other entitlement, and Module 4 never learns the word *sudoers*.

One assignment is emitted per account+entitlement pair, citing every route that
carries it. Two groups mapping to one entitlement is one assignment with two
grant paths, not two assignments.

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

**The approved target set is checked against a fresh reading.** v2 requires an
approval to name the exact assignment and grant paths it covers. Access can
change between the scan a reviewer saw and the moment a revocation executes, so
`remediation.py` re-reads the target and refuses if the approved set no longer
describes what is there. Refusing and asking for a re-scan is correct; removing
something nobody approved is not.

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

**`Group.privileged` is a required boolean; `Entitlement.privileged` is
nullable.** The same contract lets a connector decline to classify an
entitlement but forces it to assert true or false about a group. We emit
`false`, which is an assertion we have no basis for. The two fields should agree,
and `bool | None` is the right shape for both.

**`account_type` has no source on Linux.** POSIX records no such attribute. The
service accounts are named in connector configuration (`IGA_SERVICE_ACCOUNTS`)
and everything else above the system UID floor is reported as `human`. Inferring
it from the login shell would be worse than useless — a deprovisioned human has
`nologin` and would be silently reclassified as a service account, hiding the
lifecycle leftovers a review exists to find.

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

59 assertions against a live seeded lab: authentication, exact contract key sets
for all seven object types, referential integrity, grant-path structure, the
complete seeded truth discovered with nothing invented, idempotent replay,
conflicting key reuse, stale mapping version, wrong source, rejection of an
approved target set that no longer matches, and a revoke-then-verify cycle
proving one assignment and its grant path disappeared and nothing else changed.

The suite imports **Module 4's own `Scan` model** from the sibling package and
validates the scan document against it. Hand-written assertions say what we
believe their contract means; that one check is the contract itself. When it
moves again, this suite fails here rather than during a live campaign. If
`iga_review` cannot be imported the check reports SKIP rather than passing
silently.

Verified on all three transports:

| Transport | Result |
| --- | --- |
| `ssh` | 367/367 assignments, 367 grant paths (3 direct, 364 inherited) |
| `local` | 367/367 assignments |
| `fixture` | Runs offline; revocation refused as `fixture_is_read_only` |

The least-privilege boundary was checked by hand over SSH: `iga-inspect` and
`iga-remediate` succeed, and `sudo -n cat /etc/shadow` is refused.
