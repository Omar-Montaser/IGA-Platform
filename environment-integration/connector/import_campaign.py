#!/usr/bin/env python3
"""Import one live access-review campaign into Module 4 from the Module 3 connector.

Module 4's CLI can only build a campaign from its own synthetic fixture (the
`demo` command). This is the live equivalent: it takes a real scan from the
Module 3 connector and posts it, with the Module 1 documents and the explicit
account-to-HR correlations, to POST /api/campaigns.

Nothing here interprets the data. It moves four documents into one payload of
the shape Module 4's CampaignInput declares, and reports what came back.

    python import_campaign.py

Environment (all have working defaults for the current laptop deployment):

    IGA_CONNECTOR_URL   http://127.0.0.1:8000      Module 3
    IGA_CONNECTOR_TOKEN                            required, plaintext
    IGA_REVIEW_URL      http://127.0.0.1:8040      Module 4
    IGA_REVIEW_STATE    .live-review               reads reviewer-token.txt
    IGA_SOURCE          linux-lab
    IGA_BUNDLE          ../../governance-platform/hr-policy/data
    IGA_CORRELATIONS    ../samples/correlations.json
"""
import json
import os
import re
import sys
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
CONNECTOR = os.environ.get("IGA_CONNECTOR_URL", "http://127.0.0.1:8000").rstrip("/")
REVIEW = os.environ.get("IGA_REVIEW_URL", "http://127.0.0.1:8040").rstrip("/")
SOURCE = os.environ.get("IGA_SOURCE", "linux-lab")
STATE = Path(os.environ.get("IGA_REVIEW_STATE", ".live-review"))
BUNDLE = Path(os.environ.get(
    "IGA_BUNDLE", HERE / ".." / ".." / "governance-platform" / "hr-policy" / "data"))
CORRELATIONS = Path(os.environ.get("IGA_CORRELATIONS", HERE / ".." / "samples"
                                   / "correlations.json"))


def fail(message):
    sys.exit(f"import failed: {message}")


def load(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"could not read the {label} ({path}): {exc}")
    except ValueError as exc:
        fail(f"the {label} is not valid JSON ({path}): {exc}")


def main():
    token = os.environ.get("IGA_CONNECTOR_TOKEN", "")
    if not token:
        fail("set IGA_CONNECTOR_TOKEN to the connector's plaintext service token "
             "(the same value whose SHA-256 the connector holds)")

    reviewer_path = STATE / "reviewer-token.txt"
    try:
        reviewer = reviewer_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        fail(f"could not read the reviewer credential ({reviewer_path}): {exc}. "
             f"Run `iga-review init --state-dir {STATE}` first.")

    identities = load(BUNDLE / "identities.json", "Module 1 identities")
    policies = load(BUNDLE / "policies.json", "Module 1 policies")
    correlations = load(CORRELATIONS, "account correlations")
    # The seeder writes a wrapper document; Module 4 wants the bare list.
    if isinstance(correlations, dict):
        correlations = correlations.get("correlations", correlations)

    print(f"Requesting a scan from the connector at {CONNECTOR} ...")
    try:
        response = httpx.post(
            f"{CONNECTOR}/scans", json={"source": SOURCE, "request_id": None},
            headers={"Authorization": f"Bearer {token}"},
            timeout=120, follow_redirects=False)
    except httpx.HTTPError as exc:
        fail(f"could not reach the connector at {CONNECTOR}: {exc}. Is it running?")
    if response.status_code != 200:
        fail(f"the connector refused the scan ({response.status_code}): "
             f"{response.text[:400]}")
    scan = response.json()

    print(f"  {len(scan['identities'])} accounts, {len(scan['assignments'])} assignments, "
          f"{len(scan['grant_paths'])} grant paths, scan {scan['scan_id']}")

    # Correlations bind accounts to HR identities explicitly. If they do not line
    # up with the scan's account IDs, every case comes back as unresolved
    # ownership - which looks like a broken connector rather than a broken join,
    # so it is worth failing loudly here instead.
    scanned = {account["id"] for account in scan["identities"]}
    correlated = {row["account_id"] for row in correlations}
    matched = scanned & correlated
    print(f"  {len(matched)} of {len(correlated)} correlations match a scanned account")
    if not matched:
        fail(f"no correlation matches any account in the scan. The scan uses IDs "
             f"like {sorted(scanned)[0]!r} and the correlations use "
             f"{sorted(correlated)[0]!r}. Re-run `lab.py reset` and re-capture.")

    # A correlation that points at the WRONG person is far more dangerous than
    # one that is missing: the account IDs still resolve, so every downstream
    # check passes and Module 4 reviews real access against someone else's HR
    # record. Nothing below this point can detect it. Re-seeding the lab with a
    # different set of accounts shifts every UID, so a correlations file left
    # over from an earlier scenario looks valid and is completely wrong.
    #
    # The seeder writes the username into each correlation's evidence string,
    # which gives us an independent way to check the binding.
    username_of = {a["id"]: a["username"] for a in scan["identities"]}
    stated = re.compile(r"POSIX account (\S+) \(uid (\d+)\)")
    checked = mismatched = 0
    examples = []
    for row in correlations:
        found = stated.search(row.get("evidence", ""))
        if not found or row["account_id"] not in username_of:
            continue
        checked += 1
        claimed, actual = found.group(1), username_of[row["account_id"]]
        if claimed != actual:
            mismatched += 1
            if len(examples) < 5:
                examples.append(f"    {row['account_id']}: correlation says "
                                f"{claimed}, the target says {actual}")
    if checked and mismatched:
        fail(f"{mismatched} of {checked} correlations name a different account "
             f"than the target does. This file was generated for a different "
             f"lab, and importing it would review real access against the wrong "
             f"people.\n" + "\n".join(examples) +
             f"\n\n  Re-capture it from the target:\n"
             f"    VM:  sudo python3 ~/lab.py capture ~/samples\n"
             f"    then copy ~/samples/correlations.json to {CORRELATIONS}")
    if checked:
        print(f"  {checked} correlations cross-checked against the target's own "
              f"usernames, no mismatches")
    else:
        print("  WARNING: correlations carry no username evidence, so the "
              "account-to-person binding could not be verified")

    uncorrelated = sorted(username_of[a] for a in scanned - correlated)
    if uncorrelated:
        print(f"  {len(uncorrelated)} accounts with no HR identity: "
              f"{', '.join(uncorrelated[:6])}"
              f"{' ...' if len(uncorrelated) > 6 else ''}")

    payload = {
        "name": f"Linux access review · {scan['scanned_at']}",
        "identities": identities,
        "policies": policies,
        "scan": scan,
        "correlations": correlations,
    }

    print(f"Posting the campaign to {REVIEW} ...")
    try:
        created = httpx.post(
            f"{REVIEW}/api/campaigns", json=payload,
            headers={"Authorization": f"Bearer {reviewer}"},
            timeout=300, follow_redirects=False)
    except httpx.HTTPError as exc:
        fail(f"could not reach Module 4 at {REVIEW}: {exc}. Is `iga-review serve` running?")
    if created.status_code != 201:
        fail(f"Module 4 rejected the campaign ({created.status_code}):\n"
             f"{created.text[:2000]}")

    body = created.json()
    print("\nCampaign created.")
    print(json.dumps(body, indent=2)[:2000])
    campaign_id = body.get("id") or body.get("campaign_id")
    if campaign_id:
        print(f"\nOpen {REVIEW} and sign in with the token in {reviewer_path}")
        print(f"Campaign: {campaign_id}")


if __name__ == "__main__":
    main()
