#!/usr/bin/env python3
"""
Module 2 - Linux IAM Environment
IGA Access Review Prototype (ASU x RSA)

Builds the Linux target system from the Module 1 HR bundle, so the accounts on
the box correspond to real HR identities and the deliberate access problems are
defined against Module 1's own policy - not against a second, invented dataset.

    sudo python3 lab.py seed --bundle <dir>     # <dir> holds identities.json + policies.json
    sudo python3 lab.py status
    sudo python3 lab.py capture <outdir>
    sudo python3 lab.py destroy
    sudo python3 lab.py reset --bundle <dir>

Design rules
  * Generic entitlement IDs (ent:...) never appear on the box. The box has POSIX
    groups and sudoers drop-ins. entitlement_map.json is the native-to-generic
    mapping Module 3 owns and uses to normalize.
  * One entitlement is deliberately mapped to sudo rather than a group, so the
    prototype demonstrates that the same generic entitlement can have completely
    different native representations.
  * Every account's primary group is its own user-private group, so every
    entitlement membership is secondary and always safe to remove.
  * Ground truth is DERIVED from Module 1 policy (status rule first, then
    restricted, then expected/privileged, else unlisted) - never hand-written.
"""

import argparse
import json
import os
import pwd
import grp
import shutil
import signal
import subprocess
import sys
from datetime import datetime, timezone

signal.signal(signal.SIGPIPE, signal.SIG_DFL)

LAB_DIR = "/opt/iga-lab"
SUDOERS_D = "/etc/sudoers.d"
SUDO_PREFIX = "90-iga-"
SERVICE_ACCOUNT = "iga_svc"
SOURCE = "linux-lab"
MAPPING_VERSION = "1.0.0"

# The single entitlement represented as sudo rather than a POSIX group.
SUDO_ENTITLEMENT = "ent:it:infrastructure-admin"

# --------------------------------------------------------------------------
# Deliberate access problems, expressed as (username, entitlement_id).
# The issue type is not recorded here - it is derived from Module 1 policy.
# --------------------------------------------------------------------------
EXTRA_GRANTS = [
    # cross-department and restricted access held by active staff
    ("alex.morgan.0002",   "ent:hr:employee-records-read"),
    ("zoe.bennett.0003",   "ent:engineering:production-deploy"),
    ("casey.diaz.0004",    "ent:it:infrastructure-admin"),
    ("dara.farah.0006",    "ent:finance:invoices-read"),
    ("sam.reed.0016",      "ent:finance:payments-approve"),
    ("taylor.santos.0017", "ent:hr:employee-records-read"),
    ("harper.jordan.0027", "ent:finance:invoices-manage"),
    ("ira.kim.0028",       "ent:hr:payroll-admin"),
    ("amir.diaz.0038",     "ent:marketing:audience-export"),
    ("ana.evans.0039",     "ent:sales:pricing-approve"),
    ("noor.reed.0050",     "ent:engineering:source-read"),
    ("remy.santos.0051",   "ent:marketing:audience-export"),
    ("finley.kim.0062",    "ent:it:infrastructure-admin"),
    ("lena.reed.0067",     "ent:security:audit-read"),
]

# Non-active people whose access was never cleaned up. They keep the full
# expected set for their role, which the status rule makes a violation.
LIFECYCLE_LEFTOVERS = {
    "jules.kim.0011",     # terminated, engineering
    "chen.farah.0023",    # terminated, finance
    "taylor.carter.0071", # terminated, it
    "ira.jordan.0010",    # on_leave, engineering
    "casey.gray.0058",    # on_leave, marketing
}

# Pre-hire accounts provisioned before the start date, with partial access.
EARLY_PROVISIONED = {
    "kai.lane.0012":  ["ent:collaboration:workspace-read",
                       "ent:collaboration:workspace-write",
                       "ent:engineering:source-read"],
    "dara.gray.0024": ["ent:collaboration:workspace-read",
                       "ent:finance:invoices-read"],
}

# Non-active people whose access WAS cleaned up correctly: account retained but
# locked, no entitlements. These are the negative controls.
PROPERLY_DEPROVISIONED = {
    "taylor.bennett.0035", "jules.malik.0047", "chen.hayes.0059",
    "sam.santos.0034", "ira.lane.0046", "sam.brooks.0070",
}


# ==========================================================================
# shell helpers
# ==========================================================================

def run(cmd, check=True, quiet=False):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0 and not quiet:
        print(f"  ! {' '.join(cmd)}\n    {r.stderr.strip()}", file=sys.stderr)
    return r


def need_root():
    if os.geteuid() != 0:
        sys.exit("Run with sudo:  sudo python3 lab.py <command>")


def user_exists(n):
    try:
        pwd.getpwnam(n); return True
    except KeyError:
        return False


def group_exists(n):
    try:
        grp.getgrnam(n); return True
    except KeyError:
        return False


def add_user(username, gecos):
    """useradd, retrying with --badname for dotted usernames on strict systems."""
    base = ["useradd", "-m", "-U", "-s", "/bin/bash", "-c", gecos]
    r = run(base + [username], check=False, quiet=True)
    if r.returncode != 0:
        r = run(["useradd", "--badname", "-m", "-U", "-s", "/bin/bash",
                 "-c", gecos, username], check=False, quiet=True)
    if r.returncode != 0 and not user_exists(username):
        print(f"  ! could not create {username}: {r.stderr.strip()}", file=sys.stderr)
        return False
    return True


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ==========================================================================
# native <-> generic mapping  (owned by Module 3)
# ==========================================================================

def native_group_name(entitlement_id):
    """ent:engineering:source-read -> engineering_source_read"""
    return entitlement_id.split("ent:", 1)[-1].replace(":", "_").replace("-", "_")


def build_mapping(entitlements):
    mapping = {}
    for ent in entitlements:
        eid = ent["id"]
        if eid == SUDO_ENTITLEMENT:
            mapping[eid] = {"native_type": "sudo",
                            "native_id": SUDO_PREFIX + "<username>",
                            "note": "granted as a sudoers drop-in file, not a group"}
        else:
            name = native_group_name(eid)
            if len(name) > 32:
                sys.exit(f"native group name too long for {eid}: {name}")
            mapping[eid] = {"native_type": "posix_group", "native_id": name}
    natives = [m["native_id"] for m in mapping.values() if m["native_type"] == "posix_group"]
    if len(natives) != len(set(natives)):
        sys.exit("native group name collision - mapping is not reversible")
    return mapping


# ==========================================================================
# planning: decide the intended state before touching the system
# ==========================================================================

def load_bundle(bundle_dir):
    ip = os.path.join(bundle_dir, "identities.json")
    pp = os.path.join(bundle_dir, "policies.json")
    for p in (ip, pp):
        if not os.path.isfile(p):
            sys.exit(f"Not found: {p}\nPoint --bundle at the folder holding "
                     "identities.json and policies.json")
    with open(ip) as fh:
        identities = json.load(fh)
    with open(pp) as fh:
        policies = json.load(fh)
    return identities, policies


def plan(identities_doc, policies_doc):
    """Return (accounts, mapping, catalog, policy_index, status_index)."""
    catalog = {e["id"]: e for e in policies_doc["entitlements"]}
    mapping = build_mapping(policies_doc["entitlements"])
    policy_index = {(p["department"], p["role"]): p
                    for p in policies_doc["role_policies"]}
    status_index = {s["status"]: s["access"] for s in policies_doc["status_rules"]}

    accounts = []
    for ident in identities_doc["identities"]:
        username, status = ident["username"], ident["status"]
        pol = policy_index.get((ident["department"], ident["role"]))
        expected = list(pol["expected"]) if pol else []

        if status == "active":
            ents, enabled, create = list(expected), True, True
        elif username in LIFECYCLE_LEFTOVERS:
            ents, enabled, create = list(expected), True, True
        elif username in EARLY_PROVISIONED:
            ents, enabled, create = list(EARLY_PROVISIONED[username]), True, True
        elif username in PROPERLY_DEPROVISIONED:
            ents, enabled, create = [], False, True
        else:
            ents, enabled, create = [], False, False   # pre-hire, never provisioned

        if not create:
            continue
        accounts.append({
            "identity_id": ident["id"],
            "username": username,
            "name": ident["name"],
            "department": ident["department"],
            "role": ident["role"],
            "status": status,
            "enabled": enabled,
            "entitlements": ents,
        })

    by_user = {a["username"]: a for a in accounts}
    for username, eid in EXTRA_GRANTS:
        if username not in by_user:
            sys.exit(f"EXTRA_GRANTS references unknown username: {username}")
        if eid not in catalog:
            sys.exit(f"EXTRA_GRANTS references unknown entitlement: {eid}")
        if eid not in by_user[username]["entitlements"]:
            by_user[username]["entitlements"].append(eid)

    return accounts, mapping, catalog, policy_index, status_index


def classify(account, eid, policy_index, status_index, catalog):
    """Derive the expected policy verdict, using Module 1 rules only.

    Status rule first, then restricted, then expected/privileged, else unlisted.
    """
    if status_index.get(account["status"], "role_policy") == "none":
        return "lifecycle_restricted", False
    pol = policy_index.get((account["department"], account["role"]))
    if pol is None:
        return "unknown_entitlement", False
    if eid in pol["restricted"]:
        privileged = bool(catalog.get(eid, {}).get("privileged"))
        return ("unauthorized_privilege" if privileged else "restricted"), False
    if eid in pol["expected"]:
        return "expected", True
    if eid in pol["privileged"]:
        return "permitted_privileged", True
    return "unlisted", False


# ==========================================================================
# embedded privileged helpers installed on the box
# ==========================================================================

IGA_INSPECT = r'''#!/usr/bin/env python3
"""Read-only privileged inspection for the Module 3 discovery path.

    sudo -n /usr/local/sbin/iga-inspect sudo

Prints {"<username>": ["<sudoers line>", ...]} for lab-managed drop-in files.
"""
import json, os, sys
D, P = "/etc/sudoers.d", "90-iga-"
if len(sys.argv) != 2 or sys.argv[1] != "sudo":
    print(json.dumps({"error": "usage: iga-inspect sudo"})); sys.exit(2)
out = {}
for fn in sorted(os.listdir(D)):
    if not fn.startswith(P):
        continue
    try:
        with open(os.path.join(D, fn)) as fh:
            out[fn[len(P):]] = [l.strip() for l in fh
                                if l.strip() and not l.startswith("#")]
    except OSError as e:
        out[fn[len(P):]] = ["<unreadable: %s>" % e]
print(json.dumps(out, indent=2))
'''

IGA_REMEDIATE = r'''#!/usr/bin/env python3
"""Guarded native removal for the Module 3 remediation path.

    sudo -n /usr/local/sbin/iga-remediate remove-group <user> <group> [--dry-run]
    sudo -n /usr/local/sbin/iga-remediate remove-sudo  <user>         [--dry-run]

Prints one JSON object. Exit 0 on success, 1 on refusal or failure.
Refuses system accounts, the service account itself, primary-group removal,
groups outside the managed mapping, and any change that breaks sudoers.
"""
import json, grp, os, pwd, subprocess, sys

MANAGED = "/opt/iga-lab/managed_groups.txt"
D, P, SVC = "/etc/sudoers.d", "90-iga-", "iga_svc"


def out(ok, action, **kw):
    print(json.dumps({"ok": ok, "action": action, **kw}, indent=2))
    sys.exit(0 if ok else 1)


def managed():
    try:
        with open(MANAGED) as fh:
            return {l.strip() for l in fh if l.strip()}
    except OSError:
        return set()


def check_user(u, action):
    try:
        e = pwd.getpwnam(u)
    except KeyError:
        out(False, action, error="no_such_user", user=u)
    if e.pw_uid < 1000:
        out(False, action, error="system_account_refused", user=u, uid=e.pw_uid)
    if u == SVC:
        out(False, action, error="service_account_refused", user=u)
    return e


def remove_group(u, g, dry):
    e = check_user(u, "remove-group")
    try:
        gr = grp.getgrnam(g)
    except KeyError:
        out(False, "remove-group", error="no_such_group", user=u, group=g)
    if gr.gr_gid == e.pw_gid:
        out(False, "remove-group", error="primary_group_refused", user=u, group=g,
            note="removing a primary group would orphan the account")
    if g not in managed():
        out(False, "remove-group", error="group_not_managed", user=u, group=g)
    if u not in gr.gr_mem:
        out(True, "remove-group", user=u, group=g, changed=False,
            note="not_a_member_already")
    if dry:
        out(True, "remove-group", user=u, group=g, changed=False, dry_run=True)
    r = subprocess.run(["/usr/bin/gpasswd", "-d", u, g], capture_output=True, text=True)
    if r.returncode != 0:
        out(False, "remove-group", error="gpasswd_failed", user=u, group=g,
            detail=r.stderr.strip())
    out(True, "remove-group", user=u, group=g, changed=True)


def remove_sudo(u, dry):
    check_user(u, "remove-sudo")
    path = os.path.join(D, P + u)
    if not os.path.isfile(path):
        out(True, "remove-sudo", user=u, changed=False, note="no_sudo_grant_present")
    if dry:
        out(True, "remove-sudo", user=u, changed=False, dry_run=True, file=path)
    backup = path + ".removed"
    os.rename(path, backup)
    v = subprocess.run(["/usr/sbin/visudo", "-c"], capture_output=True, text=True)
    if v.returncode != 0:
        os.rename(backup, path)
        out(False, "remove-sudo", error="sudoers_validation_failed", user=u,
            detail=v.stderr.strip(), note="change_rolled_back")
    os.remove(backup)
    out(True, "remove-sudo", user=u, changed=True, file=path)


args = [a for a in sys.argv[1:] if a != "--dry-run"]
dry = "--dry-run" in sys.argv[1:]
if len(args) == 3 and args[0] == "remove-group":
    remove_group(args[1], args[2], dry)
elif len(args) == 2 and args[0] == "remove-sudo":
    remove_sudo(args[1], dry)
else:
    out(False, args[0] if args else "none", error="bad_arguments")
'''


# ==========================================================================
# seed
# ==========================================================================

def seed(bundle_dir):
    need_root()
    identities_doc, policies_doc = load_bundle(bundle_dir)
    accounts, mapping, catalog, policy_index, status_index = plan(identities_doc, policies_doc)

    print(f"Module 1 bundle : {identities_doc['dataset_id']}")
    print(f"  identities    : {len(identities_doc['identities'])}")
    print(f"  entitlements  : {len(catalog)}")
    print(f"  role policies : {len(policy_index)}\n")

    os.makedirs(LAB_DIR, exist_ok=True)

    groups = sorted(m["native_id"] for m in mapping.values()
                    if m["native_type"] == "posix_group")
    print(f"Creating {len(groups)} POSIX groups")
    for g in groups:
        if not group_exists(g):
            run(["groupadd", g], check=False, quiet=True)
    with open(os.path.join(LAB_DIR, "managed_groups.txt"), "w") as fh:
        fh.write("\n".join(groups) + "\n")

    print(f"Creating {len(accounts)} accounts")
    made = 0
    for a in accounts:
        if not user_exists(a["username"]):
            if not add_user(a["username"], a["name"]):
                continue
            made += 1
        if not a["enabled"]:
            run(["usermod", "-L", a["username"]], check=False, quiet=True)
            run(["usermod", "-s", "/usr/sbin/nologin", a["username"]],
                check=False, quiet=True)
    print(f"  {made} created, {len(accounts) - made} already present")

    print("Granting entitlements")
    sudo_users = []
    for a in accounts:
        for eid in a["entitlements"]:
            m = mapping[eid]
            if m["native_type"] == "sudo":
                sudo_users.append(a["username"])
            else:
                run(["gpasswd", "-a", a["username"], m["native_id"]],
                    check=False, quiet=True)

    print(f"Writing {len(sudo_users)} sudoers drop-ins")
    for u in sudo_users:
        path = os.path.join(SUDOERS_D, SUDO_PREFIX + u)
        with open(path, "w") as fh:
            fh.write(f"# {SUDO_ENTITLEMENT} granted to {u}\n")
            fh.write(f"{u} ALL=(ALL) NOPASSWD:ALL\n")
        os.chmod(path, 0o440); os.chown(path, 0, 0)

    print("Creating connector service account")
    if not user_exists(SERVICE_ACCOUNT):
        add_user(SERVICE_ACCOUNT, "Module 3 connector service account")
    for path, body in (("/usr/local/sbin/iga-inspect", IGA_INSPECT),
                       ("/usr/local/sbin/iga-remediate", IGA_REMEDIATE)):
        with open(path, "w") as fh:
            fh.write(body)
        os.chmod(path, 0o755); os.chown(path, 0, 0)
    svc = os.path.join(SUDOERS_D, "10-iga-service")
    with open(svc, "w") as fh:
        fh.write("# Least-privilege access for the Module 3 connector\n")
        fh.write(f"{SERVICE_ACCOUNT} ALL=(root) NOPASSWD: "
                 "/usr/local/sbin/iga-inspect, /usr/local/sbin/iga-remediate\n")
    os.chmod(svc, 0o440); os.chown(svc, 0, 0)

    if run(["visudo", "-c"], check=False).returncode != 0:
        sys.exit("sudoers validation FAILED - fix before continuing")
    print("  sudoers validated")

    write_artifacts(accounts, mapping, catalog, policy_index, status_index,
                    identities_doc, policies_doc)
    summary()


# ==========================================================================
# artifacts
# ==========================================================================

def write_artifacts(accounts, mapping, catalog, policy_index, status_index,
                    identities_doc, policies_doc):
    print("\nWriting hand-off artifacts")

    truth, counts = [], {}
    for a in accounts:
        for eid in a["entitlements"]:
            verdict, legit = classify(a, eid, policy_index, status_index, catalog)
            truth.append({
                "username": a["username"],
                "identity_id": a["identity_id"],
                "entitlement": eid,
                "native_type": mapping[eid]["native_type"],
                "expected_policy_result": verdict,
                "legitimate": legit,
                "department": a["department"],
                "role": a["role"],
                "employment_status": a["status"],
            })
            if not legit:
                counts[verdict] = counts.get(verdict, 0) + 1

    correlations = []
    for a in accounts:
        try:
            uid = pwd.getpwnam(a["username"]).pw_uid
        except KeyError:
            continue
        correlations.append({
            "account_id": f"{SOURCE}:uid:{uid}",
            "username": a["username"],
            "identity_id": a["identity_id"],
            "evidence": "account provisioned from this HR identity by the lab seeder",
        })

    docs = {
        "entitlement_map.json": {
            "schema_version": "1.0.0",
            "mapping_version": MAPPING_VERSION,
            "source": SOURCE,
            "generated_at": now_iso(),
            "note": "Native-to-generic mapping owned by Module 3. "
                    "Generic entitlement IDs never appear on the target system.",
            "entitlements": mapping,
        },
        "correlations.json": {
            "schema_version": "1.0.0",
            "source": SOURCE,
            "generated_at": now_iso(),
            "note": "Explicit account-to-HR bindings. Module 4 must not infer "
                    "these from usernames; two identities share the name "
                    "'Alex Morgan' in this dataset.",
            "correlations": correlations,
        },
        "ground_truth.json": {
            "schema_version": "1.0.0",
            "generated_at": now_iso(),
            "derived_from": policies_doc["dataset_id"],
            "note": "Derived from Module 1 policy, not hand-written. "
                    "Withhold from the review engine team until measurement.",
            "total_assignments": len(truth),
            "violations": sum(counts.values()),
            "by_expected_policy_result": counts,
            "assignments": truth,
        },
        "seed_manifest.json": {
            "generated_at": now_iso(),
            "source": SOURCE,
            "mapping_version": MAPPING_VERSION,
            "users": [a["username"] for a in accounts] + [SERVICE_ACCOUNT],
            "groups": sorted(m["native_id"] for m in mapping.values()
                             if m["native_type"] == "posix_group"),
        },
    }
    for name, payload in docs.items():
        p = os.path.join(LAB_DIR, name)
        with open(p, "w") as fh:
            json.dump(payload, fh, indent=2)
        os.chmod(p, 0o644)
        print(f"  + {p}")


def summary():
    gt = json.load(open(os.path.join(LAB_DIR, "ground_truth.json")))
    total, bad = gt["total_assignments"], gt["violations"]
    print("\n" + "=" * 66)
    print(f"  {total} access assignments, {bad} violating Module 1 policy "
          f"({bad * 100 // total}%)")
    print("=" * 66)
    for k, v in sorted(gt["by_expected_policy_result"].items(), key=lambda x: -x[1]):
        print(f"  {v:3d}  {k}")
    print("=" * 66)
    print(f"\n  {LAB_DIR}/entitlement_map.json  -> Module 3 normalization")
    print(f"  {LAB_DIR}/correlations.json     -> Module 4 import payload")
    print(f"  {LAB_DIR}/ground_truth.json     -> keep private until measurement")
    print("\nTake a VirtualBox snapshot now, named 'lab-seeded'.")


# ==========================================================================
# status / capture / destroy
# ==========================================================================

def status():
    mf = os.path.join(LAB_DIR, "seed_manifest.json")
    if not os.path.isfile(mf):
        sys.exit("No lab found. Run seed first.")
    manifest = json.load(open(mf))
    print(f"{'account':24s} {'on?':5s} groups")
    print("-" * 100)
    for u in manifest["users"]:
        if not user_exists(u):
            print(f"{u:24s} <missing>"); continue
        sec = sorted(g.gr_name for g in grp.getgrall() if u in g.gr_mem)
        shell = pwd.getpwnam(u).pw_shell
        locked = "off" if shell.endswith(("nologin", "false")) else "on"
        sudo = "  [sudo]" if os.path.isfile(os.path.join(SUDOERS_D, SUDO_PREFIX + u)) else ""
        print(f"{u:24s} {locked:5s} {', '.join(sec)}{sudo}")


def capture(dest):
    need_root()
    os.makedirs(dest, exist_ok=True)
    for src in ("/etc/passwd", "/etc/group"):
        shutil.copy(src, os.path.join(dest, os.path.basename(src)))
    r = run(["/usr/local/sbin/iga-inspect", "sudo"], check=False)
    with open(os.path.join(dest, "sudoers_dropins.json"), "w") as fh:
        fh.write(r.stdout or "{}")
    for n in ("entitlement_map.json", "correlations.json"):
        s = os.path.join(LAB_DIR, n)
        if os.path.isfile(s):
            shutil.copy(s, os.path.join(dest, n))
    print(f"Captured raw system state to {dest}/")
    print("Commit this to the repo: the Module 3 parser can be built and")
    print("unit-tested against it with no VM and no SSH.")


def destroy():
    need_root()
    mf = os.path.join(LAB_DIR, "seed_manifest.json")
    if not os.path.isfile(mf):
        sys.exit("Nothing to remove (no seed manifest).")
    manifest = json.load(open(mf))
    print(f"Removing {len(manifest['users'])} accounts")
    for u in manifest["users"]:
        if user_exists(u) and pwd.getpwnam(u).pw_uid >= 1000:
            run(["userdel", "-r", u], check=False, quiet=True)
    print(f"Removing {len(manifest['groups'])} groups")
    for g in manifest["groups"]:
        if group_exists(g):
            run(["groupdel", g], check=False, quiet=True)
    for fn in sorted(os.listdir(SUDOERS_D)):
        if fn.startswith(SUDO_PREFIX) or fn == "10-iga-service":
            os.remove(os.path.join(SUDOERS_D, fn))
    for p in ("/usr/local/sbin/iga-inspect", "/usr/local/sbin/iga-remediate"):
        if os.path.exists(p):
            os.remove(p)
    shutil.rmtree(LAB_DIR, ignore_errors=True)
    ok = run(["visudo", "-c"], check=False).returncode == 0
    print("sudoers " + ("validated" if ok else "BROKEN - check it"))
    print("Lab removed.")


def main():
    ap = argparse.ArgumentParser(description="Module 2 - Linux IAM environment")
    ap.add_argument("command", choices=["seed", "reset", "status", "capture", "destroy"])
    ap.add_argument("target", nargs="?", default="./samples")
    ap.add_argument("--bundle", default=".",
                    help="folder containing identities.json and policies.json")
    a = ap.parse_args()
    if a.command == "seed":
        seed(a.bundle)
    elif a.command == "reset":
        destroy(); print("-" * 66); seed(a.bundle)
    elif a.command == "status":
        status()
    elif a.command == "capture":
        capture(a.target)
    elif a.command == "destroy":
        destroy()


main()
