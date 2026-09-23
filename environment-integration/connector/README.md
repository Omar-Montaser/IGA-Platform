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

**Native parsing, mapping and remediation are Linux-specific.** A different
target, such as Active Directory or RSA, needs its own transport/discovery,
normalization mapping and approved-remediation implementation. The generic
scan shape and review API are the reusable boundary; changing environments is
not just changing credentials or a URL.

The claim was tested in practice when Module 4 moved from scan schema v1 to v2.
The contract gained four collections and changed three object shapes. Every line
that had to change was in `normalize.py`. `transport.py` and `discovery.py` were
not touched.

**Transport is separate from discovery** because *how* you reach a system is
orthogonal to *what you read from it*. One parser serves all three transports,
and the fixture transport means the entire discovery path is unit-testable in CI
with no VM and no network.

**Privileged native safety guards also live on the target.** `iga-remediate`
is designed to sit behind a two-command sudoers allow-list. The connector
validates requests and fresh target sets too. The allow-list limits privileged
commands, not every possible action of a compromised service account. Target
configuration and helper deployment were not revalidated in this audit.

## Transports

| `IGA_TRANSPORT` | Pattern | Use |
| --- | --- | --- |
| `ssh` | Agentless | Explicitly configured; connector reaches the target over SSH. |
| `local` | Agent-based | Configuration default; connector runs on the target itself. |
| `fixture` | Read-only capture | CI. Serves `samples/`; revocation is refused by construction. |

SSH avoids installing the connector service on each target, although the lab's
privileged helpers still need deployment. Host keys are verified with
paramiko's `RejectPolicy` — never `AutoAddPolicy`,
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

Verify the target's host-key fingerprint through a trusted channel before
trusting the result of `ssh-keyscan` below.

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

Requests reject unknown fields and type coercion. Revocations require the
approval metadata and unique, nonempty assignment/path target lists before any
native access. Malformed or incomplete discovery fails the request; it does not
produce a complete scan. The mapping source must match the configured source.

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

One assignment is emitted per account+entitlement pair, citing every observed
route. The generic contract supports multiple paths per assignment; this lab's
mapping format currently supports only one native entry per entitlement.

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

## Evidence limits and compatibility

**Unknown group privilege is `null`.** Both group and entitlement privilege
are nullable in the current Module 4 validator. The fields remain required;
unknown is not the same as non-privileged.

**`account_type` has no source on Linux.** POSIX records no such attribute. The
service accounts are named in connector configuration (`IGA_SERVICE_ACCOUNTS`)
and everything else above the system UID floor is reported as `human`. Inferring
it from the login shell would be worse than useless — a deprovisioned human has
`nologin` and would be silently reclassified as a service account, hiding the
lifecycle leftovers a review exists to find.

**Unknown grant time is `null`.** Linux snapshots do not establish when an
individual grant was made. Assignment `timestamp` is no longer fabricated from
file modification time; `scanned_at` records when evidence was observed. These
nullable extensions retain schema version `2.0.0`; older consumers requiring
timestamp strings or group booleans must be updated before using this connector.

**The scan asks the connector to classify entitlements.** `sensitivity` and
`privileged` are fields a source-system connector cannot honestly populate.
`unknown`/`null` is permitted and is what we emit, but the fields' existence
invites guessing that would silently compete with Module 1's catalog.

**Full snapshot per scan, no pagination.** There is no cursor or incremental-scan
concept in the contract. Large-directory scale has not been tested.

**`complete` is a single boolean.** There is no way to express "accounts read
fully, sudo partially." Real connectors have patchy visibility; a coverage object
would carry more.

## Verified tests — 2026-09-23

From the project root, with the HR, review and connector packages installed:

```powershell
& '.\governance-platform\access-review\.venv-ai\Scripts\python.exe' -m unittest discover -s environment-integration/connector/tests -p test_offline_audit.py
```

All **14 offline audit tests passed**. They validate 367 captured assignments and
367 paths using Module 4's actual `Scan` model, compare every policy result with
the Module 2 planner, reject malformed/partial native reads and ambiguous
mappings, exercise strict API validation and idempotent read-only revocation,
and start a real localhost HTTP connector for Module 4 import/export and audit
verification. Fixture revocation remains `fixture_is_read_only`; no native
access was removed.

`tests/test_connector.py` is a legacy live-lab script, skipped by ordinary test
discovery. Run it explicitly only against a disposable lab; non-fixture execution
also requires `IGA_ALLOW_LIVE_MUTATIONS=1`. It can remove real target grants.
Live SSH/local transport, deployed helper permissions and native revoke-then-scan
behavior were **not rerun** in this audit. Updated helper code in `lab.py` has not
been deployed to any target.
