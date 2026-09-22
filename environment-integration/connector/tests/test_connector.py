"""End-to-end tests against the real seeded Linux lab."""
import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

TOKEN = "test-service-token-0123456789"
os.environ["IGA_TOKEN_SHA256"] = hashlib.sha256(TOKEN.encode()).hexdigest()
os.environ["IGA_STATE"] = "/tmp/iga-connector-test/state.db"
subprocess.run(["rm", "-rf", "/tmp/iga-connector-test"], check=False)

from fastapi.testclient import TestClient          # noqa: E402
from iga_connector.api import app                  # noqa: E402

client = TestClient(app)
AUTH = {"Authorization": f"Bearer {TOKEN}"}
GT = json.load(open("/opt/iga-lab/ground_truth.json"))

ok = fail = 0


def check(label, condition, detail=""):
    global ok, fail
    if condition:
        ok += 1
        print(f"  PASS  {label}")
    else:
        fail += 1
        print(f"  FAIL  {label} {detail}")


print("\n--- authentication ---")
check("no credential is rejected", client.post("/scans", json={}).status_code == 401)
check("wrong credential is rejected",
      client.post("/scans", json={}, headers={"Authorization": "Bearer nope"}).status_code == 401)
check("health needs no credential", client.get("/health").status_code == 200)

print("\n--- scan document ---")
r = client.post("/scans", json={"source": "linux-lab", "request_id": None}, headers=AUTH)
check("scan returns 200", r.status_code == 200, r.text[:200])
scan = r.json()

required = {"schema_version", "scan_id", "source", "scanned_at", "complete",
            "mapping_version", "scope_entitlements", "request_id",
            "identities", "entitlements", "assignments"}
check("exactly the contract keys, no extras", set(scan) == required,
      f"got {sorted(set(scan) ^ required)}")
check("schema_version is 1.0.0", scan["schema_version"] == "1.0.0")
check("scanned_at ends with Z", scan["scanned_at"].endswith("Z"))
check("wrong source is rejected",
      client.post("/scans", json={"source": "other"}, headers=AUTH).status_code == 400)

acc_keys = {"id", "username", "enabled", "source"}
check("account objects match the contract",
      all(set(a) == acc_keys for a in scan["identities"]))
ent_keys = {"id", "name", "type", "sensitivity", "privileged", "source"}
check("entitlement objects match the contract",
      all(set(e) == ent_keys for e in scan["entitlements"]))
asg_keys = {"id", "identity", "entitlement", "source", "timestamp"}
check("assignment objects match the contract",
      all(set(a) == asg_keys for a in scan["assignments"]))

print("\n--- referential integrity (Module 4 rejects any of these) ---")
ids = {a["id"] for a in scan["identities"]}
ents = {e["id"] for e in scan["entitlements"]}
check("account IDs unique", len(ids) == len(scan["identities"]))
check("assignment IDs unique",
      len({a["id"] for a in scan["assignments"]}) == len(scan["assignments"]))
check("every assignment resolves to an account",
      all(a["identity"] in ids for a in scan["assignments"]))
check("every assignment resolves to an entitlement",
      all(a["entitlement"] in ents for a in scan["assignments"]))
check("every scope ID has a definition", set(scan["scope_entitlements"]) <= ents)
check("discovered entitlements are in scope",
      {a["entitlement"] for a in scan["assignments"]} <= set(scan["scope_entitlements"]))
check("source is consistent everywhere",
      all(o["source"] == scan["source"]
          for o in scan["identities"] + scan["entitlements"] + scan["assignments"]))
check("no assignment is stamped after the scan",
      all(a["timestamp"] <= scan["scanned_at"] for a in scan["assignments"]))
check("no Linux vocabulary leaks into entitlement IDs",
      all(e.startswith("ent:") for e in ents))

print("\n--- does the scan match the seeded truth? ---")
found = {(a["identity"], a["entitlement"]) for a in scan["assignments"]}
by_user = {a["username"]: a["id"] for a in scan["identities"]}
expected = {(by_user[t["username"]], t["entitlement"])
            for t in GT["assignments"] if t["username"] in by_user}
check(f"all {len(expected)} seeded assignments discovered",
      expected <= found, f"missing {len(expected - found)}")
check("no assignments invented", len(found - expected) == 0,
      f"extra {sorted(found - expected)[:3]}")

sudo_ent = "ent:it:infrastructure-admin"
check("the sudo-mapped entitlement is discovered as an entitlement, not a group",
      any(a["entitlement"] == sudo_ent for a in scan["assignments"]))

disabled = [a["username"] for a in scan["identities"] if not a["enabled"]]
check("deprovisioned accounts report enabled=false",
      "jules.malik.0047" in disabled, f"disabled={sorted(disabled)}")
check("active accounts report enabled=true",
      by_user.get("ada.bennett.0001") and
      next(a for a in scan["identities"] if a["username"] == "ada.bennett.0001")["enabled"])

print("\n--- revocation ---")
target_user = "casey.diaz.0004"
target_ent = "ent:hr:employee-records-read"
alex = "alex.morgan.0002"
req = {"request_id": "req-0001", "source": "linux-lab",
       "identity": by_user[alex], "entitlement": target_ent,
       "approved_by": "user:admin", "approved_at": scan["scanned_at"],
       "reason": "Engineering user holding a restricted HR entitlement.",
       "scan_id": scan["scan_id"], "mapping_version": scan["mapping_version"],
       "assignment_ids": []}

r = client.post("/revocations", json=req, headers={**AUTH, "Idempotency-Key": "req-0001"})
check("revocation returns 200", r.status_code == 200, r.text[:200])
resp = r.json()
check("response has exactly the contract keys",
      set(resp) == {"request_id", "status", "message"}, str(resp))
check("status is succeeded", resp["status"] == "succeeded", str(resp))
check("message does not claim verification",
      "verification scan is required" in resp["message"], resp.get("message", ""))

r2 = client.post("/revocations", json=req, headers={**AUTH, "Idempotency-Key": "req-0001"})
check("replaying the same request returns the same response", r2.json() == resp)

conflict = dict(req, entitlement="ent:finance:invoices-read")
check("reusing the ID with different content is a conflict",
      client.post("/revocations", json=conflict, headers=AUTH).status_code == 409)

bad_map = dict(req, request_id="req-0002", mapping_version="9.9.9")
check("stale mapping version is refused",
      client.post("/revocations", json=bad_map, headers=AUTH).json()["status"] == "failed")

bad_src = dict(req, request_id="req-0003", source="somewhere-else")
check("wrong source is refused",
      client.post("/revocations", json=bad_src, headers=AUTH).json()["status"] == "failed")

print("\n--- verification: a second scan must show it gone ---")
r = client.post("/scans", json={"source": "linux-lab", "request_id": "req-0001"},
                headers=AUTH)
scan2 = r.json()
check("verification scan has a different scan_id", scan2["scan_id"] != scan["scan_id"])
check("verification scan echoes the request_id", scan2["request_id"] == "req-0001")
check("verification scan is not older than the request",
      scan2["scanned_at"] >= scan["scanned_at"])
gone = {(a["identity"], a["entitlement"]) for a in scan2["assignments"]}
check("the revoked assignment is absent from the fresh scan",
      (by_user[alex], target_ent) not in gone)
check("nothing else was removed", len(gone) == len(found) - 1,
      f"before {len(found)} after {len(gone)}")

print(f"\n{'=' * 58}\n  {ok} passed, {fail} failed\n{'=' * 58}")
sys.exit(1 if fail else 0)
