#!/usr/bin/env python3
"""Measure Module 4's findings against the Module 2 answer key.

The answer key (`ground_truth.json`) is DERIVED by the seeder from Module 1's
own policy, not hand-written, and the Module 4 team has never seen it. That is
what makes the number mean anything: the engine was not tuned against it.

The join is direct. Ground truth records, per (username, entitlement), an
`expected_policy_result` taken from Module 4's own vocabulary; findings carry a
`policy_result`. No translation happens here, so a disagreement is a real
disagreement rather than a mapping artefact.

    python measure_accuracy.py [--campaign review:...] [--json report.json]

Environment:
    IGA_REVIEW_URL      http://127.0.0.1:8040
    IGA_REVIEW_STATE    .live-review          (reads reviewer-token.txt)
    IGA_GROUND_TRUTH    ground_truth.json
"""
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

import httpx

REVIEW = os.environ.get("IGA_REVIEW_URL", "http://127.0.0.1:8040").rstrip("/")
STATE = Path(os.environ.get("IGA_REVIEW_STATE", ".live-review"))
GT_PATH = Path(os.environ.get("IGA_GROUND_TRUTH", "ground_truth.json"))

# Findings that are not claims about one account's hold on one entitlement, so
# there is nothing in the answer key to compare them against. They are counted
# and shown, never silently dropped.
NON_ASSIGNMENT = {"unmatched", "ambiguous", "coverage_gap", "missing_expected",
                  "unknown_entitlement"}


def fail(message):
    sys.exit(f"measurement failed: {message}")


def ai_report(findings, truth, legit):
    """Score the AI reviewer against the same answer key, on its own terms.

    The reviewer returns an ACTION (retain / remove / investigate / escalate),
    not a policy label, so it is judged on what it would do rather than on what
    it would call things. The number that matters is not overall agreement: it
    is how often the reviewer said `retain` about access the policy forbids,
    because that is the only error in this direction that loses access control.
    """
    scored, fallback = [], []
    for finding in findings:
        if finding.get("policy_result") in NON_ASSIGNMENT or not finding.get("entitlement_id"):
            continue
        key = (finding["username"], finding["entitlement_id"])
        if key not in truth:
            continue
        case = finding.get("case_assessment") or {}
        assessment = finding.get("item_assessment") or {}
        action = assessment.get("action") or finding.get("recommended_action")
        row = {"key": key, "action": action,
               "engine": finding["policy_result"],
               "expected_legitimate": truth[key] in legit,
               "confidence": case.get("confidence"),
               "mandatory_human_review": finding.get("mandatory_human_review"),
               "reasons": finding.get("human_review_reasons") or []}
        (fallback if case.get("fallback_reason") else scored).append(row)

    total = len(scored) + len(fallback)
    if not total:
        return {"status": "no_assessments_present"}

    print(f"\n{'=' * 58}\n  AI reviewer\n{'=' * 58}")
    if not scored:
        reasons = Counter(f.get("reasons") and f["reasons"][0] or "fallback" for f in fallback)
        print(f"  no AI assessments: all {len(fallback)} items were rules fallback")
        print("  (run with IGA_AI_PROVIDER=gemini and GEMINI_API_KEY to measure the AI)")
        return {"status": "all_fallback", "items": total,
                "fallback": len(fallback), "reasons": dict(reasons)}

    print(f"  items assessed by the model      {len(scored)}")
    print(f"  items that fell back to rules    {len(fallback)}"
          f"   ({len(fallback) * 100 / total:.1f}%)")

    violations = [r for r in scored if not r["expected_legitimate"]]
    legitimate = [r for r in scored if r["expected_legitimate"]]

    removed = [r for r in violations if r["action"] == "remove"]
    deferred = [r for r in violations if r["action"] in ("investigate", "escalate")]
    retained = [r for r in violations if r["action"] == "retain"]

    kept = [r for r in legitimate if r["action"] == "retain"]
    over = [r for r in legitimate if r["action"] != "retain"]

    if violations:
        print(f"\n  access the policy forbids        {len(violations)}")
        print(f"    model said remove              {len(removed)}")
        print(f"    model said investigate/escalate{len(deferred):>4d}   (flagged, not resolved)")
        print(f"    model said RETAIN              {len(retained)}   <- the errors that matter")
        print(f"    flagged in some form           "
              f"{len(removed) + len(deferred)}/{len(violations)} = "
              f"{(len(removed) + len(deferred)) * 100 / len(violations):.1f}%")
    if legitimate:
        print(f"\n  access the policy allows         {len(legitimate)}")
        print(f"    model said retain              {len(kept)}")
        print(f"    model wanted to act on it      {len(over)}   (over-flagging)")

    # Disagreement with the engine is not an error - their design keeps it
    # visible and routes it to a human rather than resolving it silently.
    engine_says_remove = {"restricted", "lifecycle_restricted", "unauthorized_privilege"}
    disagree = [r for r in scored
                if (r["engine"] in engine_says_remove) != (r["action"] != "retain")]
    print(f"\n  disagreements with the engine    {len(disagree)}")
    flagged_for_human = [r for r in scored if r["mandatory_human_review"]]
    print(f"  routed to mandatory human review {len(flagged_for_human)}")
    if flagged_for_human:
        for reason, count in sorted(Counter(
                reason for r in flagged_for_human for reason in r["reasons"]).items(),
                key=lambda x: -x[1]):
            print(f"    {reason:30s} {count}")

    confidences = [r["confidence"] for r in scored if isinstance(r["confidence"], (int, float))]
    if confidences:
        print(f"\n  mean self-reported confidence    {sum(confidences) / len(confidences):.2f}")
        print("  (the model's own estimate, not a calibrated probability)")

    if retained:
        print(f"\n  RETAINED despite a policy violation ({len(retained)}):")
        for row in retained[:15]:
            print(f"    {row['key'][0]:22s} {row['key'][1]:34s} engine={row['engine']}")

    return {
        "status": "measured",
        "items": total, "assessed": len(scored), "fallback": len(fallback),
        "violations": {"total": len(violations), "remove": len(removed),
                       "investigate_or_escalate": len(deferred), "retained": len(retained)},
        "legitimate": {"total": len(legitimate), "retained": len(kept), "acted_on": len(over)},
        "engine_disagreements": len(disagree),
        "mandatory_human_review": len(flagged_for_human),
        "retained_violations": [{"username": r["key"][0], "entitlement": r["key"][1],
                                 "engine": r["engine"]} for r in retained],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", help="campaign id (default: the newest)")
    parser.add_argument("--json", type=Path, help="also write the full report here")
    args = parser.parse_args()

    try:
        token = (STATE / "reviewer-token.txt").read_text(encoding="utf-8").strip()
    except OSError as exc:
        fail(f"could not read the reviewer credential: {exc}")
    auth = {"Authorization": f"Bearer {token}"}

    try:
        truth_doc = json.loads(GT_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"could not read the answer key ({GT_PATH}): {exc}. Copy it off the "
             f"target and set IGA_GROUND_TRUTH.")

    campaign_id = args.campaign
    if not campaign_id:
        listing = httpx.get(f"{REVIEW}/api/campaigns", headers=auth, timeout=60)
        if listing.status_code != 200:
            fail(f"could not list campaigns ({listing.status_code}): {listing.text[:300]}")
        campaigns = listing.json()["campaigns"]
        if not campaigns:
            fail("no campaigns exist yet - run import_campaign.py first")
        campaign_id = campaigns[0]["id"]

    detail = httpx.get(f"{REVIEW}/api/campaigns/{campaign_id}", headers=auth, timeout=120)
    if detail.status_code != 200:
        fail(f"could not read the campaign ({detail.status_code}): {detail.text[:300]}")
    campaign = detail.json()
    findings = campaign["findings"]

    truth = {(row["username"], row["entitlement"]): row["expected_policy_result"]
             for row in truth_doc["assignments"]}
    found = {}
    other = []
    for finding in findings:
        if finding["policy_result"] in NON_ASSIGNMENT or not finding.get("entitlement_id"):
            other.append(finding)
            continue
        found[(finding["username"], finding["entitlement_id"])] = finding["policy_result"]

    agreed = [k for k in truth if k in found and found[k] == truth[k]]
    disagreed = [k for k in truth if k in found and found[k] != truth[k]]
    missed = [k for k in truth if k not in found]
    extra = [k for k in found if k not in truth]

    print(f"campaign        {campaign['id']}")
    print(f"                {campaign['name']}")
    print(f"answer key      {GT_PATH}  ({truth_doc['derived_from']})")
    print(f"warnings        {campaign['warnings'] or 'none'}")
    print()
    print(f"assignments in the answer key   {len(truth)}")
    print(f"assignment findings returned    {len(found)}")
    print(f"  agreed                        {len(agreed)}")
    print(f"  disagreed                     {len(disagreed)}")
    print(f"  in the key, no finding        {len(missed)}")
    print(f"  finding, not in the key       {len(extra)}")

    comparable = len(agreed) + len(disagreed)
    if comparable:
        print(f"\nagreement on comparable assignments: "
              f"{len(agreed)}/{comparable} = {len(agreed) * 100 / comparable:.1f}%")

    # Violations are what a review exists to catch, so they get their own
    # numbers. Everything the key marks as anything other than `expected` or
    # `permitted_privileged` is a violation.
    legit = {"expected", "permitted_privileged"}
    key_violations = {k for k, v in truth.items() if v not in legit}
    flagged = {k for k, v in found.items() if v not in legit}
    caught = key_violations & flagged
    if key_violations:
        missed_v = key_violations - flagged
        false_alarm = flagged - key_violations
        recall = len(caught) * 100 / len(key_violations)
        precision = len(caught) * 100 / len(flagged) if flagged else 0.0
        print(f"\nviolations in the answer key    {len(key_violations)}")
        print(f"  caught                        {len(caught)}   (recall {recall:.1f}%)")
        print(f"  missed                        {len(missed_v)}")
        print(f"  flagged but legitimate        {len(false_alarm)}   (precision {precision:.1f}%)")

    print("\nby expected policy result:")
    for label, count in sorted(Counter(truth.values()).items(), key=lambda x: -x[1]):
        keys = [k for k in truth if truth[k] == label]
        hit = sum(1 for k in keys if found.get(k) == label)
        print(f"  {label:24s} {hit:4d} / {len(keys):<4d} agreed")

    if disagreed:
        print(f"\ndisagreements ({len(disagreed)}):")
        for key in sorted(disagreed)[:25]:
            print(f"  {key[0]:22s} {key[1]:34s} key={truth[key]:22s} module4={found[key]}")
        if len(disagreed) > 25:
            print(f"  ... and {len(disagreed) - 25} more")

    if other:
        print(f"\nfindings with no counterpart in the key ({len(other)}):")
        for label, count in sorted(Counter(f["policy_result"] for f in other).items()):
            print(f"  {label:24s} {count}")
        print("  (account-level and evidence-quality findings - expected, not errors)")

    # ---------------------------------------------------------------- AI layer
    # The deterministic engine and the AI reviewer are scored separately and
    # never averaged. They answer different questions: the engine says what the
    # policy states, the reviewer says what it would do about it. Mixing them
    # would hide which one made an error.
    ai = ai_report(findings, truth, legit)

    if args.json:
        args.json.write_text(json.dumps({
            "campaign_id": campaign["id"],
            "answer_key": truth_doc.get("derived_from"),
            "deterministic_engine": {
                "totals": {"key": len(truth), "found": len(found), "agreed": len(agreed),
                           "disagreed": len(disagreed), "missed": len(missed),
                           "extra": len(extra)},
                "violations": {"in_key": len(key_violations), "caught": len(caught),
                               "flagged": len(flagged)},
                "disagreements": [{"username": k[0], "entitlement": k[1],
                                   "expected": truth[k], "module4": found[k]}
                                  for k in sorted(disagreed)],
            },
            "ai_reviewer": ai,
        }, indent=2) + "\n", encoding="utf-8")
        print(f"\nfull report written to {args.json}")


if __name__ == "__main__":
    main()
