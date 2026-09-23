# IGA Platform - Complete Setup and Run Guide

## Overview
This guide covers the complete end-to-end setup for the IGA Platform, including:
- Linux VM setup and seeding
- Connector service
- Review portal with real access governance

---

## Environment-first quick start (Windows)

This is the current minimal workflow. The Linux deployment walkthrough below is
separate; it is not required for the simulated demonstration. From PowerShell:

```powershell
Set-Location 'C:\Users\MONTASER YOUSUF\Documents\IGA-Platform'
$env:IGA_AI_PROVIDER = 'rules'
& './governance-platform/access-review/.venv-ai/Scripts/python.exe' -m iga_review.cli demo --empty --state-dir './governance-platform/access-review/.demo-review/environment-first-walkthrough' --identities './governance-platform/hr-policy/data/identities.json' --policies './governance-platform/hr-policy/data/policies.json' --port 8042
```

Use a **new** state directory for an empty starting point. This command preserves
an existing directory; `--empty` never clears campaigns or resets simulated
removals. Stop with Ctrl+C and run the same command to resume. The installed
environment above already contains the editable modules. For a fresh checkout,
create a Python 3.11+ venv and install `-e governance-platform/hr-policy -e
governance-platform/access-review` before starting.

Open [the review portal](http://127.0.0.1:8042). Open the generated
`governance-platform/access-review/.demo-review/environment-first-walkthrough/reviewer-token.txt`
locally and paste its credential into the sign-in form. Do not paste credentials
into issue reports or documentation.

1. An administrator lands on **Environment**. With no campaigns, the configured
   **Simulated demo environment** says **Not scanned yet** and counts are unknown.
2. Enter a campaign name and click **Start access review**. The backend records a
   durable run, scans the current fixture, validates it and reviews the evidence.
3. Progress uses **Queued → Scanning → Validating → Reviewing → Review ready**.
   Rules processing may finish between polls; **Recorded progress** retains the
   actual timestamped stages. Errors show retry/setup guidance.
4. **Open review findings** opens the resulting campaign. Account inventory and
   finding counts are separate. Starting a campaign does not change any access.
5. Reload, sign in again and see the same saved run and campaign. Tokens are
   deliberately memory-only. **Refresh status** reads saved state and does not
   rescan. A second **Start access review** requests genuinely new evidence.

`rules` makes this walkthrough entirely offline with respect to AI. **Rules
fallbacks** are not successful model reviews. A genuine provider review records
its provider/model with `status: ready`; failed calls retain an explicit fallback
reason. **Simulated source** operates only on persistent fixture data. **Captured
fixture** means a read-only native capture, not a live host. **Live connector
(configured)** is configured metadata, not proof that the host is reachable;
successful observations have their own timestamps and completeness.

### Server-managed inputs for a configured connector

Keep the existing users, fallback reviewer, tokens and history in protected
state. Add these fields to the relevant entry in its `connectors` list; this is
an entry example, not a replacement `config.json`:

```json
{
  "source": "linux-lab",
  "name": "Linux review environment",
  "mode": "live",
  "base_url": "http://127.0.0.1:8000",
  "token_env": "IGA_CONNECTOR_TOKEN",
  "scan_timeout_seconds": 120,
  "correlation_mode": "linux-posix",
  "inputs": {
    "identities": "inputs/identities.json",
    "policies": "inputs/policies.json",
    "correlations": "inputs/correlations.json"
  }
}
```

Paths are relative to the state directory (absolute administrator-managed paths
are also accepted). Files must be UTF-8. Correlations may be a list or the capture
writer's `{"correlations": [...]}` wrapper. For a fixture transport set `mode` to
`captured_fixture`; supported non-demo modes are `live`, `captured_fixture` and
`unknown`. Optional `mapping_version` pins the expected connector mapping ID.
Use the actual version, not a made-up placeholder. Mode is descriptive only;
the connector's transport must also be configured correctly. Remote connector
URLs require HTTPS. Supply the service token through its named environment
variable, never through the browser or input files.

Run `python -m iga_review.cli serve --state-dir <existing-state-directory>` with
the installed interpreter and `IGA_AI_PROVIDER=rules`, or use an explicitly
approved external AI configuration. Real HR/policy timestamps must remain
authentic; stale evidence blocks a new run. Only synthetic demo copies are
rebased. Linux correlations are checked against both captured username and UID
to reject stale bindings. Ownership is never inferred from a matching name.

Missing/invalid inputs appear as a setup error. Existing connector entries
without the new input fields still load and expose their environment, but cannot
start backend-owned reviews until configured. The legacy full-payload campaign
import endpoint remains available. `serve`/`demo` own the campaign worker; no
extra worker command is required. Approved remediation still uses its existing
queue/worker. An unresolved dispatch or pending verification must recover before
a new campaign can start, including when its old lease has expired.

See [the API and recovery contract](governance-platform/access-review/docs/contract.md#environment-first-campaign-runs)
for routes, idempotency, retry limits, leases, snapshots and atomic completion.
The older Linux/setup sections below are deployment background, not evidence
that a live target or external AI was validated in the environment-first tests.

---

## Part 1: Linux VM Setup (Kali/Ubuntu)

### 1.1 Prerequisites
- Kali Linux or Ubuntu VM
- Root/sudo access
- Python 3.11+
- Network configured (Bridged or Port Forwarding)

### 1.2 Initial Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv openssh-server git

# Check Python version (need 3.11+)
python3 --version

# Enable SSH
sudo systemctl enable ssh
sudo systemctl start ssh

# Clone the repository
cd ~
git clone https://github.com/Omar-Montaser/IGA-Platform.git
cd IGA-Platform
```

### 1.3 Create Service Account

```bash
# Create iga_svc service account
sudo useradd -r -m -s /bin/bash iga_svc

# Setup directories
sudo mkdir -p /home/iga_svc/.ssh /var/lib/iga-lab /opt/iga-lab
sudo chmod 700 /home/iga_svc/.ssh

# Generate SSH keys
sudo chown -R iga_svc:iga_svc /home/iga_svc/.ssh
sudo -u iga_svc ssh-keygen -t rsa -b 4096 -f /home/iga_svc/.ssh/id_rsa -N ""
sudo -u iga_svc cat /home/iga_svc/.ssh/id_rsa.pub | sudo tee -a /home/iga_svc/.ssh/authorized_keys
sudo chmod 600 /home/iga_svc/.ssh/authorized_keys
sudo chown iga_svc:iga_svc /home/iga_svc/.ssh/authorized_keys

# Backup key
sudo cp /home/iga_svc/.ssh/authorized_keys /var/lib/iga-lab/service_authorized_keys
sudo chown -R iga_svc:iga_svc /var/lib/iga-lab
```

### 1.4 Install Helper Scripts

```bash
# Create iga-inspect helper
sudo tee /usr/local/sbin/iga-inspect > /dev/null << 'EOF'
#!/bin/bash
set -e
case "$1" in
  sudo)
    find /etc/sudoers.d -type f -name "90-iga-*" 2>/dev/null | while read f; do
      username=$(basename "$f" | sed 's/90-iga-//')
      [ -f "$f" ] && echo "$username:$(cat "$f")"
    done
    ;;
  *) echo "Usage: iga-inspect sudo" >&2; exit 1 ;;
esac
EOF

# Create iga-remediate helper
sudo tee /usr/local/sbin/iga-remediate > /dev/null << 'EOF'
#!/bin/bash
set -e
MANAGED_GROUPS="/opt/iga-lab/managed_groups.txt"

remove_group() {
  local username=$1 group=$2
  [ $(id -u "$username" 2>/dev/null || echo 1000) -lt 1000 ] && { echo "ERROR: system account" >&2; exit 1; }
  [ "$username" = "iga_svc" ] && { echo "ERROR: service account" >&2; exit 1; }
  grep -qx "$group" "$MANAGED_GROUPS" 2>/dev/null || { echo "ERROR: not managed" >&2; exit 1; }
  primary_gid=$(id -g "$username")
  target_gid=$(getent group "$group" | cut -d: -f3)
  [ "$primary_gid" = "$target_gid" ] && { echo "ERROR: primary group" >&2; exit 1; }
  gpasswd -d "$username" "$group" >/dev/null 2>&1 || true
  echo "Removed $username from $group"
}

remove_sudo() {
  local username=$1 dropfile="/etc/sudoers.d/90-iga-$username"
  [ $(id -u "$username" 2>/dev/null || echo 1000) -lt 1000 ] && { echo "ERROR: system account" >&2; exit 1; }
  [ "$username" = "iga_svc" ] && { echo "ERROR: service account" >&2; exit 1; }
  [ -f "$dropfile" ] && { rm -f "$dropfile"; visudo -c || { echo "ERROR: validation failed" >&2; exit 1; }; echo "Removed sudo for $username"; } || echo "No sudo file"
}

case "$1" in
  remove-group) [ $# -eq 3 ] || { echo "Usage: remove-group USER GROUP" >&2; exit 1; }; remove_group "$2" "$3" ;;
  remove-sudo) [ $# -eq 2 ] || { echo "Usage: remove-sudo USER" >&2; exit 1; }; remove_sudo "$2" ;;
  *) echo "Usage: iga-remediate {remove-group|remove-sudo} ..." >&2; exit 1 ;;
esac
EOF

# Make executable
sudo chmod 755 /usr/local/sbin/iga-{inspect,remediate}
```

### 1.5 Configure Sudo

```bash
# Configure sudo for iga_svc
echo "iga_svc ALL=(root) NOPASSWD: /usr/local/sbin/iga-inspect, /usr/local/sbin/iga-remediate" | sudo tee /etc/sudoers.d/50-iga-svc
sudo chmod 440 /etc/sudoers.d/50-iga-svc

# Configure sudo for current user (needed for local transport)
echo "$USER ALL=(root) NOPASSWD: /usr/local/sbin/iga-inspect, /usr/local/sbin/iga-remediate" | sudo tee /etc/sudoers.d/51-iga-$USER
sudo chmod 440 /etc/sudoers.d/51-iga-$USER

# Verify syntax
sudo visudo -c

# Test
sudo -n /usr/local/sbin/iga-inspect sudo
```

### 1.6 Seed the Lab

```bash
cd ~/IGA-Platform/environment-integration/linux-lab

# Seed with scenario B (374 assignments, 55 violations)
sudo python3 lab.py seed --bundle ../../governance-platform/hr-policy/data --scenario b

# Verify
sudo python3 lab.py status

# Expected output:
# ✓ 69 accounts created
# ✓ 22 managed groups
# ✓ 374 total assignments (55 violations)
```

---

## Part 2: Connector Setup (Linux VM)

### 2.1 Install Connector

```bash
cd ~/IGA-Platform/environment-integration/connector

# Create virtual environment
python3 -m venv .venv
.venv/bin/pip install -e .
```

### 2.2 Generate Token

```bash
# Generate secure token
CONNECTOR_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Display and save token
echo "=========================================="
echo "CONNECTOR TOKEN (save this!):"
echo "$CONNECTOR_TOKEN"
echo "=========================================="
echo "$CONNECTOR_TOKEN" > ~/.connector-token

# Generate SHA256 hash for the API
TOKEN_HASH=$(echo -n "$CONNECTOR_TOKEN" | sha256sum | cut -d' ' -f1)
echo "Token hash: $TOKEN_HASH"
```

### 2.3 Start Connector

```bash
cd ~/IGA-Platform/environment-integration/connector

# Set TOKEN_HASH from step 2.2 (replace with your actual hash)
TOKEN_HASH="your_token_hash_here"

# Start connector
IGA_TRANSPORT=local \
IGA_MAPPING=/opt/iga-lab/entitlement_map.json \
IGA_SOURCE=linux-lab \
IGA_TOKEN_SHA256="$TOKEN_HASH" \
.venv/bin/python -c "from iga_connector import api; import uvicorn; uvicorn.run(api.app, host='0.0.0.0', port=8030)"

# Expected output:
# INFO: Uvicorn running on http://0.0.0.0:8030
```

**Leave this terminal running.**

### 2.4 Network Configuration

**Option A: Port Forwarding (VirtualBox/VMware)**
- VM Settings → Network → Port Forwarding
- Add rule: Host Port `8030` → Guest Port `8030`
- Access from Windows: `http://localhost:8030`

**Option B: Bridged Network**
- VM Settings → Network → Bridged Adapter
- Get VM IP: `hostname -I`
- Access from Windows: `http://<vm-ip>:8030`

---

## Part 3: Windows - Test Connector

### 3.1 Test Health Endpoint

```powershell
# Test connectivity (use localhost if port forwarding, or VM IP if bridged)
Invoke-RestMethod "http://localhost:8030/health"

# Expected output:
# status mapping_version scope target
# ------ --------------- ----- ------
# ok     1.0.0              23 local
```

### 3.2 Scan the System

```powershell
# Set token (use your actual token from Linux step 2.2)
$token = "your_connector_token_here"

# Request scan
$headers = @{Authorization = "Bearer $token"}
$body = @{source = "linux-lab"; request_id = "scan-001"} | ConvertTo-Json

$scan = Invoke-RestMethod -Uri "http://localhost:8030/scans" -Method POST `
  -Headers $headers -Body $body -ContentType "application/json"

# Display results
Write-Host "`n✓ Scan completed!" -ForegroundColor Green
Write-Host "  Accounts: $($scan.identities.Count)" -ForegroundColor Cyan
Write-Host "  Assignments: $($scan.assignments.Count)" -ForegroundColor Cyan
Write-Host "  Groups: $($scan.groups.Count)" -ForegroundColor Cyan

# Expected output:
#   Accounts: 70
#   Assignments: 374
#   Groups: 22

# Save scan
$scan | ConvertTo-Json -Depth 20 | Out-File "C:\Users\MONTASER YOUSUF\Documents\IGA-Platform\kali-live-scan.json"
```

---

## Part 4: Windows - Review Portal

### 4.1 Start Demo Portal

```powershell
cd "C:\Users\MONTASER YOUSUF\Documents\IGA-Platform\governance-platform\access-review"

# Start demo with rules mode (no AI)
& .\.venv-ai\Scripts\python.exe -m iga_review.cli demo --state-dir .demo-review\rules

# Or with Gemini AI (if configured)
& .\.venv-ai\Scripts\python.exe -m iga_review.cli demo --state-dir .demo-review\gemini

# Expected output:
# ✓ Demo campaign imported: review:xxxxx
#   374 findings (55 policy violations)
#   
# → Open http://127.0.0.1:8040
#   Token: .demo-review/rules/reviewer-token.txt
```

### 4.2 Access Portal

```powershell
# Get login token
Get-Content .demo-review\rules\reviewer-token.txt
```

1. Open browser: `http://127.0.0.1:8040`
2. Paste the token
3. Click "Sign In"

### 4.3 Review Workflows

**A. Review Lifecycle Violations (41 findings)**
- Filter by `lifecycle_restricted`
- These are people who left/on leave but still have access
- Decision: **Revoke** → Add reason → Submit

**B. Review Restricted Access (8 findings)**
- Filter by `restricted`
- Wrong person has sensitive access
- Decision: **Revoke** → Submit

**C. Certify Expected Access (319 findings)**
- Filter by `expected`
- Access matches their role
- Check "I acknowledge the recorded risk"
- Decision: **Certify** → Submit

**D. Process Remediation (Admin only)**
- Click "Process Remediation"
- Connector will SSH into Linux and remove access
- Watch status: pending → processing → succeeded
- In demo mode: all succeed (fixture mode)
- In live mode: real SSH removals happen

**E. View Audit Log**
- Click "Audit" in navigation
- Select campaign
- See all decisions with timestamps
- Verify integrity hash chain

---

## Part 5: Run All Tests

### 5.1 On Windows

```powershell
cd "C:\Users\MONTASER YOUSUF\Documents\IGA-Platform"

# Module 1 (HR Policy) - 67 tests
& '.\governance-platform\access-review\.venv-ai\Scripts\python.exe' -m unittest discover -s governance-platform/hr-policy/tests

# Module 4 (Access Review) - 164 tests
& '.\governance-platform\access-review\.venv-ai\Scripts\python.exe' -m unittest discover -s governance-platform/access-review/tests

# Module 3 (Connector) - 14 tests
& '.\governance-platform\access-review\.venv-ai\Scripts\python.exe' -m unittest discover -s environment-integration/connector/tests -p test_offline_audit.py

# UI Tests - 8 tests
node --test governance-platform/access-review/tests/ui_runtime.test.cjs

# JavaScript Syntax Check
node --check governance-platform/access-review/static/app.js

# Total: 253 tests
```

---

## Quick Start Commands

### Linux VM - Start Connector
```bash
cd ~/IGA-Platform/environment-integration/connector
TOKEN_HASH="5ab96f4433d1283bd09273655af75156fdd540f662175893ae9fd47623efb5ed"
IGA_TRANSPORT=local IGA_MAPPING=/opt/iga-lab/entitlement_map.json IGA_SOURCE=linux-lab IGA_TOKEN_SHA256="$TOKEN_HASH" .venv/bin/python -c "from iga_connector import api; import uvicorn; uvicorn.run(api.app, host='0.0.0.0', port=8030)"
```

### Windows - Start Portal
```powershell
cd "C:\Users\MONTASER YOUSUF\Documents\IGA-Platform\governance-platform\access-review"
& .\.venv-ai\Scripts\python.exe -m iga_review.cli demo --state-dir .demo-review\rules
```

---

## Troubleshooting

### Connector: "sudo: a password is required"
```bash
# Check sudoers files exist
sudo cat /etc/sudoers.d/50-iga-svc
sudo cat /etc/sudoers.d/51-iga-$USER

# Test sudo works without password
sudo -n /usr/local/sbin/iga-inspect sudo

# If fails, recreate sudoers files (see section 1.5)
```

### Windows: "Unable to connect to remote server"
- Check VM network: Bridged or Port Forwarding configured
- Test from Linux: `curl http://localhost:8030/health`
- Check firewall: allow port 8030

### Portal: "No such file or directory: identities.json"
- Must run from `governance-platform/access-review` directory
- Use relative path: `../../hr-policy/data/`

---

## Architecture Summary

```
┌─────────────────────────────────────────────────┐
│            Windows Machine                       │
│                                                  │
│  ┌──────────────────────────────────────────┐  │
│  │  Review Portal (Module 4)                │  │
│  │  http://127.0.0.1:8040                   │  │
│  │  - Campaign management                   │  │
│  │  - Finding review                        │  │
│  │  - Decision recording                    │  │
│  │  - Audit trail                           │  │
│  └──────────────────────────────────────────┘  │
│                     │                            │
│                     │ HTTP/JSON                  │
│                     ▼                            │
└─────────────────────────────────────────────────┘
                      │
         Port Forwarding (8030)
                      │
┌─────────────────────────────────────────────────┐
│         Kali Linux VM                            │
│                                                  │
│  ┌──────────────────────────────────────────┐  │
│  │  Connector (Module 3)                    │  │
│  │  http://0.0.0.0:8030                     │  │
│  │  - Scan endpoint                         │  │
│  │  - Remediation endpoint                  │  │
│  └──────────────────────────────────────────┘  │
│                     │                            │
│                     │ Local/SSH                  │
│                     ▼                            │
│  ┌──────────────────────────────────────────┐  │
│  │  Linux Environment (Module 2)            │  │
│  │  /opt/iga-lab/                           │  │
│  │  - 69 user accounts                      │  │
│  │  - 22 POSIX groups                       │  │
│  │  - 374 access assignments                │  │
│  │  - 55 policy violations                  │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

---

## Key Files and Paths

### Linux VM
- `/opt/iga-lab/entitlement_map.json` - Native-to-generic mapping
- `/opt/iga-lab/correlations.json` - Account-to-HR bindings
- `/opt/iga-lab/ground_truth.json` - Answer key (for measurement)
- `/opt/iga-lab/managed_groups.txt` - Removal allow-list
- `/usr/local/sbin/iga-inspect` - Read-only inspection helper
- `/usr/local/sbin/iga-remediate` - Removal helper
- `~/.connector-token` - API token (keep secret)

### Windows
- `governance-platform/hr-policy/data/identities.json` - HR data
- `governance-platform/hr-policy/data/policies.json` - Role policies
- `governance-platform/access-review/.demo-review/` - Demo state
- `governance-platform/access-review/.venv-ai/` - Python environment
- `kali-live-scan.json` - Captured scan data

---

## Data Flow

1. **Seed** (Module 2): Creates 69 accounts with deliberate violations
2. **Scan** (Module 3): Discovers accounts → Normalizes to generic schema → Returns 374 assignments
3. **Evaluate** (Module 4): Matches against HR data and policies → Identifies 55 violations
4. **Review** (Module 4): Human reviewers make certify/revoke decisions
5. **Remediate** (Module 3): Executes approved removals via SSH
6. **Verify** (Module 3): New scan proves access is gone
7. **Audit** (Module 4): Immutable hash-chained event log

---

## Security Notes

- **Tokens**: Keep connector tokens secret, never commit to git
- **Sudo**: Helpers are scoped to managed entitlements only
- **SSH**: Connector uses service account with limited privileges
- **Helpers**: Input validation, uid checks, primary group protection
- **Audit**: All decisions logged with timestamps and integrity hashes

---

## Next Steps for Automation

1. **Infrastructure as Code**: Terraform/Ansible for VM provisioning
2. **CI/CD Pipeline**: Automated testing on every commit
3. **Container Images**: Docker for connector and portal
4. **Kubernetes**: Deploy to k8s for scaling
5. **Monitoring**: Prometheus metrics, Grafana dashboards
6. **Alerting**: Slack/Email notifications for critical findings
7. **API Integration**: Embed in existing HR/IT workflows
8. **RSA Connector**: Replace Linux connector with real IGA environment

---

## Support

- Repository: https://github.com/Omar-Montaser/IGA-Platform
- Documentation: `README.md` files in each module
- Tests: 219 automated tests covering all modules
- Contract: `governance-platform/access-review/docs/contract.md`

---

**Version**: 1.0.0  
**Last Updated**: 2024-09-23  
**Status**: Production-Ready Prototype
