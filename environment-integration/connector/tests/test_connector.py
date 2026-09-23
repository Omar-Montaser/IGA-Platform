"""End-to-end tests against the real seeded Linux lab.

The scan document is checked twice: once against hand-written assertions that
say what we believe the contract means, and once against Module 4's actual
pydantic model imported from the sibling package. The second check is the one
that cannot drift - when their contract moves, this suite fails here rather
than during a live campaign.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime

# This file is an explicit live-lab acceptance script, not a unit test module.
# Discovery must never silently execute target changes or erase shared state.
if __name__ != '__main__':
    import unittest
    raise unittest.SkipTest('Live lab acceptance requires explicit execution and target configuration.')
if os.environ.get('IGA_TRANSPORT', 'local') != 'fixture' and os.environ.get('IGA_ALLOW_LIVE_MUTATIONS') != '1':
    sys.exit('Live revocation tests require IGA_ALLOW_LIVE_MUTATIONS=1 on a disposable lab.')

HERE = os.path.dirname(os.path.abspath(__file__))


def moment(value):
    """Parse a contract timestamp. Timestamps must never be compared as text:
    '...45Z' sorts after '...45.1Z' while being the earlier instant."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


sys.path.insert(0, os.path.join(HERE, "..", "src"))
# Module 4 lives beside us in the same repository.
sys.path.insert(0, os.path.join(HERE, "..", "..", "..",
                                "governance-platform", "access-review", "src"))

TOKEN = "test-service-token-0123456789"
os.environ["IGA_TOKEN_SHA256"] = hashlib.sha256(TOKEN.encode()).hexdigest()
# The connector runs wherever Module 4 runs, which is Windows in the current
# deployment - so the scratch state lives in the platform temp directory and is
# cleared with shutil, not `rm -rf`.
_scratch = tempfile.TemporaryDirectory(prefix='iga-connector-test-')
STATE_DIR = _scratch.name
os.environ["IGA_STATE"] = os.path.join(STATE_DIR, "state.db")

from fastapi.testclient import TestClient          # noqa: E402
from iga_connector.api import app                  # noqa: E402

try:
    from iga_review.domain import Scan             # noqa: E402
except Exception as exc:                           # pragma: no cover
    Scan = None
    IMPORT_ERROR = exc

client = TestClient(app)
AUTH = {"Authorization": f"Bearer {TOKEN}"}

# The answer key lives on the target at /opt/iga-lab/, but the connector runs
# wherever Module 4 runs - on Windows in the current deployment. Copy it across
# and point IGA_GROUND_TRUTH at it:
#   scp -P 2222 iga_svc@127.0.0.1:/opt/iga-lab/ground_truth.json .
GT_PATH = os.environ.get("IGA_GROUND_TRUTH", "/opt/iga-lab/ground_truth.json")
if not os.path.isfile(GT_PATH):
    sys.exit(f"ground truth not found at {GT_PATH}\n"
             f"set IGA_GROUND_TRUTH to its location, or copy it off the target:\n"
             f"  scp -P 2222 iga_svc@127.0.0.1:/opt/iga-lab/ground_truth.json .")
GT = json.load(open(GT_PATH))

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
            "applications", "identities", "roles", "groups", "entitlements",
            "grant_paths", "assignments", "exceptions", "history"}
check("exactly the contract keys, no extras", set(scan) == required,
      f"got {sorted(set(scan) ^ required)}")
check("schema_version is 2.0.0", scan["schema_version"] == "2.0.0")
check("scanned_at ends with Z", scan["scanned_at"].endswith("Z"))
check("scanned_at carries sub-second precision",
      "." in scan["scanned_at"],
      "Module 4 rejects a verification scan <= the approval it verifies; "
      "whole-second timestamps fail intermittently")
check("wrong source is rejected",
      client.post("/scans", json={"source": "other"}, headers=AUTH).status_code == 400)

print("\n--- Module 4's own validator ---")
if Scan is None:
    print(f"  SKIP  could not import iga_review.domain ({IMPORT_ERROR})")
    print("        run from a full checkout with pydantic installed")
else:
    try:
        Scan.model_validate(scan)
        check("the scan validates against Module 4's Scan model", True)
    except Exception as exc:
        check("the scan validates against Module 4's Scan model", False,
              f"\n{str(exc)[:1500]}")

print("\n--- object shapes ---")
app_keys = {"id", "name", "criticality", "source"}
check("application objects match the contract",
      all(set(a) == app_keys for a in scan["applications"]))
acc_keys = {"id", "username", "enabled", "source", "application_id", "account_type"}
check("account objects match the contract",
      all(set(a) == acc_keys for a in scan["identities"]))
grp_keys = {"id", "name", "application_id", "privileged", "source"}
check("group objects match the contract",
      all(set(g) == grp_keys for g in scan["groups"]))
ent_keys = {"id", "name", "type", "sensitivity", "privileged", "source",
            "application_id"}
check("entitlement objects match the contract",
      all(set(e) == ent_keys for e in scan["entitlements"]))
path_keys = {"id", "account_id", "entitlement_id", "source", "grant_type", "path"}
check("grant path objects match the contract",
      all(set(p) == path_keys for p in scan["grant_paths"]))
asg_keys = {"id", "identity", "entitlement", "source", "timestamp",
            "grant_path_ids", "business_justification", "exception_id"}
check("assignment objects match the contract",
      all(set(a) == asg_keys for a in scan["assignments"]))
check("nullable fields are present as null, not omitted",
      all(a["business_justification"] is None and a["exception_id"] is None
          for a in scan["assignments"]))
check("enabled is a real boolean, not a string",
      all(isinstance(a["enabled"], bool) for a in scan["identities"]))

print("\n--- referential integrity (Module 4 rejects any of these) ---")
ids = {a["id"] for a in scan["identities"]}
ents = {e["id"] for e in scan["entitlements"]}
paths = {p["id"]: p for p in scan["grant_paths"]}
apps = {a["id"] for a in scan["applications"]}
check("account IDs unique", len(ids) == len(scan["identities"]))
check("assignment IDs unique",
      len({a["id"] for a in scan["assignments"]}) == len(scan["assignments"]))
check("grant path IDs unique", len(paths) == len(scan["grant_paths"]))
check("every assignment resolves to an account",
      all(a["identity"] in ids for a in scan["assignments"]))
check("every assignment resolves to an entitlement",
      all(a["entitlement"] in ents for a in scan["assignments"]))
check("every account belongs to a declared application",
      all(a["application_id"] in apps for a in scan["identities"]))
check("scope matches the entitlement catalog exactly",
      set(scan["scope_entitlements"]) == ents
      and len(scan["scope_entitlements"]) == len(ents))
check("source is consistent everywhere",
      all(o["source"] == scan["source"]
          for group in ("applications", "identities", "roles", "groups",
                        "entitlements", "grant_paths", "assignments",
                        "exceptions", "history")
          for o in scan[group]))
check("no assignment is stamped after the scan",
      # Parsed, not string-compared: "…45Z" sorts AFTER "…45.1Z" as text while
      # being the earlier instant, which is exactly the trap this guards.
      all(a["timestamp"] is None or moment(a["timestamp"]) <= moment(scan["scanned_at"])
          for a in scan["assignments"]))
check("no Linux vocabulary leaks into entitlement IDs",
      all(e.startswith("ent:") for e in ents))

print("\n--- grant paths: how access was reached, not only that it is held ---")
check("every assignment cites at least one grant path",
      all(a["grant_path_ids"] for a in scan["assignments"]))
check("every cited grant path exists",
      all(pid in paths for a in scan["assignments"] for pid in a["grant_path_ids"]))
check("every cited path matches its assignment's account and entitlement",
      all((paths[pid]["account_id"], paths[pid]["entitlement_id"])
          == (a["identity"], a["entitlement"])
          for a in scan["assignments"] for pid in a["grant_path_ids"]))
check("every path starts at its account",
      all(p["path"][0] == {"kind": "account", "ref": p["account_id"]}
          for p in scan["grant_paths"]))
check("every path ends at its entitlement",
      all(p["path"][-1] == {"kind": "entitlement", "ref": p["entitlement_id"]}
          for p in scan["grant_paths"]))
check("direct means exactly two hops, inherited means more",
      all((p["grant_type"] == "direct") == (len(p["path"]) == 2)
          for p in scan["grant_paths"]))

sudo_ent = "ent:it:infrastructure-admin"
sudo_paths = [p for p in scan["grant_paths"] if p["entitlement_id"] == sudo_ent]
group_paths = [p for p in scan["grant_paths"] if p["entitlement_id"] != sudo_ent]
check("the sudo-mapped entitlement is reached by a DIRECT path",
      sudo_paths and all(p["grant_type"] == "direct" for p in sudo_paths),
      f"{len(sudo_paths)} sudo paths")
check("group-mapped entitlements are reached by INHERITED paths through a group",
      group_paths and all(p["grant_type"] == "inherited"
                          and p["path"][1]["kind"] == "group"
                          for p in group_paths))

print("\n--- does the scan match the seeded truth? ---")
found = {(a["identity"], a["entitlement"]) for a in scan["assignments"]}
by_user = {a["username"]: a["id"] for a in scan["identities"]}
expected = {(by_user[t["username"]], t["entitlement"])
            for t in GT["assignments"] if t["username"] in by_user}
check(f"all {len(expected)} seeded assignments discovered",
      expected <= found, f"missing {len(expected - found)}")
check("no assignments invented", len(found - expected) == 0,
      f"extra {sorted(found - expected)[:3]}")

disabled = [a["username"] for a in scan["identities"] if not a["enabled"]]
check("deprovisioned accounts report enabled=false",
      "jules.malik.0047" in disabled, f"disabled={sorted(disabled)}")
check("active accounts report enabled=true",
      next(a for a in scan["identities"]
           if a["username"] == "ada.bennett.0001")["enabled"])
check("the service account is typed as a service, not a person",
      all(a["account_type"] == "service"
          for a in scan["identities"] if a["username"] == "iga_svc"))

print("\n--- revocation ---")
target_ent = "ent:hr:employee-records-read"
alex = "alex.morgan.0002"
target = next(a for a in scan["assignments"]
              if a["identity"] == by_user[alex] and a["entitlement"] == target_ent)

req = {"request_id": "req-0001", "source": "linux-lab",
       "identity": by_user[alex], "entitlement": target_ent,
       "approved_by": "user:admin", "approved_at": scan["scanned_at"],
       "reason": "Engineering user holding a restricted HR entitlement.",
       "scan_id": scan["scan_id"], "mapping_version": scan["mapping_version"],
       "assignment_ids": [target["id"]],
       "grant_path_ids": list(target["grant_path_ids"])}

stale = dict(req, request_id="req-0004",
             assignment_ids=[target["id"], "linux-lab:grant:9999:ent:nope"])
check("an approved assignment set that no longer matches is refused",
      client.post("/revocations", json=stale, headers=AUTH).json()["status"] == "failed")

stale_paths = dict(req, request_id="req-0005", grant_path_ids=["linux-lab:path:9999:sudo"])
check("an approved grant-path set that no longer matches is refused",
      client.post("/revocations", json=stale_paths, headers=AUTH).json()["status"] == "failed")

bad_map = dict(req, request_id="req-0002", mapping_version="9.9.9")
check("stale mapping version is refused",
      client.post("/revocations", json=bad_map, headers=AUTH).json()["status"] == "failed")

bad_src = dict(req, request_id="req-0003", source="somewhere-else")
check("wrong source is refused",
      client.post("/revocations", json=bad_src, headers=AUTH).json()["status"] == "failed")

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
check("the grant path that carried it is gone too",
      not any(p["id"] in target["grant_path_ids"] for p in scan2["grant_paths"]))
if Scan is not None:
    try:
        Scan.model_validate(scan2)
        check("the verification scan also validates", True)
    except Exception as exc:
        check("the verification scan also validates", False, str(exc)[:500])

print(f"\n{'=' * 58}\n  {ok} passed, {fail} failed\n{'=' * 58}")
sys.exit(1 if fail else 0)
