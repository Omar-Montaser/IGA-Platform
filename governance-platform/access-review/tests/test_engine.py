"""Independent acceptance cases for generic input and review evaluation."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import unittest

from pydantic import ValidationError

from iga_hr import validate_documents
from iga_review.domain import Correlation, EngineConfig, InputError, Scan, strict_json
from iga_review.engine import evaluate


NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
BASELINE = "ent:work:read"
OPTIONAL = "ent:work:admin"
FORBIDDEN = "ent:payments:admin"
UNLISTED = "ent:audit:read"
UNKNOWN = "capability:unmapped"


def fixtures():
    envelope = {"schema_version": "1.0.0", "dataset_id": "engine-acceptance",
                "snapshot_at": "2026-09-21T00:00:00Z", "synthetic": True}
    people = []

    def person(name, **changes):
        row = {"id": f"id:{name}", "username": name, "name": f"Person {name}",
               "department": "engineering", "role": "analyst", "status": "active",
               "employment_type": "employee", "manager_id": "id:manager",
               "start_date": "2026-01-01", "end_date": None}
        row.update(changes)
        people.append(row)

    person("manager", role="manager", manager_id=None)
    person("subject")
    for number in range(1, 6):
        person(f"peer-{number}")
    person("contractor", employment_type="contractor", end_date="2027-01-01")
    person("leave", status="on_leave")
    person("unobserved")
    person("other-role", role="auditor")
    person("other-department", department="finance")
    catalog = [
        {"id": identifier, "name": name, "description": f"Business capability: {name}.",
         "type": "permission", "sensitivity": sensitivity, "privileged": privileged}
        for identifier, name, sensitivity, privileged in (
            (BASELINE, "Read shared work", "low", False),
            (OPTIONAL, "Administer shared work", "high", True),
            (FORBIDDEN, "Administer payments", "critical", True),
            (UNLISTED, "Read audit evidence", "high", False),
        )
    ]
    profiles = [
        {"id": f"pol:{department}-{role}", "department": department, "role": role,
         "expected": [BASELINE], "restricted": [FORBIDDEN], "privileged": [OPTIONAL]}
        for department, role in sorted({(row["department"], row["role"]) for row in people})
    ]
    identities = {**envelope, "identities": people}
    policies = {**envelope, "effective_from": "2026-09-01", "unlisted_access": "review",
                "entitlements": catalog, "role_policies": profiles,
                "status_rules": [{"status": status, "access": "role_policy" if status == "active" else "none"}
                                 for status in ("active", "on_leave", "pre_hire", "terminated")]}
    source = "example-directory"
    accounts = [{"id": f"account:{row['username']}", "username": row["username"],
                 "enabled": True, "source": source}
                for row in people if row["username"] != "unobserved"]
    scan_entitlements = [{key: value for key, value in row.items() if key != "description"}
                        | {"source": source} for row in catalog]
    scan_entitlements.append({"id": UNKNOWN, "name": "Unmapped source capability",
                              "type": "permission", "sensitivity": "unknown",
                              "privileged": None, "source": source})
    scan = {"schema_version": "1.0.0", "scan_id": "scan:initial", "source": source,
            "scanned_at": "2026-09-21T12:00:00Z", "complete": True,
            "mapping_version": "mapping-v1", "scope_entitlements": [row["id"] for row in scan_entitlements],
            "request_id": None, "identities": accounts, "entitlements": scan_entitlements,
            "assignments": [{"id": f"assignment:{account['username']}:baseline",
                             "identity": account["id"], "entitlement": BASELINE, "source": source,
                             "timestamp": "2026-09-21T11:00:00Z"} for account in accounts]}
    bindings = [{"account_id": account["id"], "identity_id": f"id:{account['username']}",
                 "evidence": "Independently verified immutable source account reference."}
                for account in accounts]
    return identities, policies, scan, bindings


class EngineAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.identities, self.policies, self.scan, self.bindings = fixtures()

    def run_engine(self, *, now=NOW, config=None):
        return evaluate(validate_documents(self.identities, self.policies), Scan.model_validate(self.scan),
                        [Correlation.model_validate(row) for row in self.bindings], now=now,
                        **({"config": config} if config is not None else {}))

    def grant(self, account="account:subject", entitlement=OPTIONAL, suffix="extra"):
        self.scan["assignments"].append({"id": f"assignment:{suffix}", "identity": account,
                                         "entitlement": entitlement, "source": self.scan["source"],
                                         "timestamp": "2026-09-21T11:00:00Z"})

    def assignment(self, result, account="account:subject", entitlement=BASELINE):
        return next(row for row in result["findings"] if row["kind"] == "assignment"
                    and row["account_id"] == account and row["entitlement_id"] == entitlement)

    def missing(self, result, identity="id:subject"):
        return [row for row in result["findings"] if row["kind"] == "missing_access"
                and row["identity_id"] == identity]

    def remove_grants(self, account, entitlement=None):
        self.scan["assignments"] = [row for row in self.scan["assignments"]
                                    if not (row["identity"] == account
                                            and (entitlement is None or row["entitlement"] == entitlement))]

    def profile(self):
        return next(row for row in self.policies["role_policies"]
                    if (row["department"], row["role"]) == ("engineering", "analyst"))

    def test_expected_assignment_remains_individually_reviewable(self):
        result = self.run_engine()
        finding = self.assignment(result)
        self.assertTrue(result["actionable"])
        self.assertEqual(result["warnings"], [])
        self.assertEqual(finding["policy_result"], "expected")
        self.assertEqual(finding["recommendation"], "certify")
        self.assertEqual(finding["assignment_ids"], ["assignment:subject:baseline"])
        self.assertEqual(finding["evidence"]["scan_id"], self.scan["scan_id"])

    def test_lifecycle_precedes_expected_restricted_and_unknown(self):
        subject = next(row for row in self.identities["identities"] if row["id"] == "id:subject")
        for status in ("on_leave", "terminated", "pre_hire"):
            with self.subTest(status=status):
                subject.update(status=status, start_date="2026-01-01", end_date=None)
                if status == "terminated":
                    subject["end_date"] = "2026-09-21"
                if status == "pre_hire":
                    subject["start_date"] = "2026-09-22"
                self.remove_grants("account:subject")
                for number, entitlement in enumerate((BASELINE, FORBIDDEN, UNKNOWN)):
                    self.grant(entitlement=entitlement, suffix=f"lifecycle-{number}")
                result = self.run_engine()
                for entitlement in (BASELINE, FORBIDDEN, UNKNOWN):
                    finding = self.assignment(result, entitlement=entitlement)
                    self.assertEqual(finding["policy_result"], "lifecycle_restricted")
                    self.assertEqual(finding["recommendation"], "revoke")
                self.assertEqual(self.missing(result), [])

    def test_policy_categories_are_distinct(self):
        for number, entitlement in enumerate((OPTIONAL, FORBIDDEN, UNLISTED, UNKNOWN)):
            self.grant(entitlement=entitlement, suffix=f"category-{number}")
        result = self.run_engine()
        for entitlement, expected in ((OPTIONAL, "permitted_privileged"), (FORBIDDEN, "restricted"),
                                      (UNLISTED, "unlisted"), (UNKNOWN, "unknown_entitlement")):
            self.assertEqual(self.assignment(result, entitlement=entitlement)["policy_result"], expected)

    def test_unlisted_catalog_privilege_is_unauthorized(self):
        self.profile()["privileged"] = []
        self.grant()
        finding = self.assignment(self.run_engine(), entitlement=OPTIONAL)
        self.assertEqual(finding["policy_result"], "unauthorized_privilege")
        self.assertTrue(finding["privileged"])
        self.assertEqual(finding["recommendation"], "revoke")

    def test_source_only_privilege_is_retained_for_unlisted_access(self):
        next(row for row in self.scan["entitlements"] if row["id"] == UNLISTED)["privileged"] = True
        self.grant(entitlement=UNLISTED)
        finding = self.assignment(self.run_engine(), entitlement=UNLISTED)
        self.assertEqual(finding["policy_result"], "unauthorized_privilege")
        self.assertTrue(finding["privileged"])
        self.assertIn("catalog_mismatch", {row["code"] for row in finding["signals"]})

    def test_lower_source_classification_cannot_reduce_authoritative_classification(self):
        source = next(row for row in self.scan["entitlements"] if row["id"] == FORBIDDEN)
        source.update(sensitivity="low", privileged=False)
        self.grant(entitlement=FORBIDDEN)
        finding = self.assignment(self.run_engine(), entitlement=FORBIDDEN)
        self.assertEqual(finding["sensitivity"], "critical")
        self.assertTrue(finding["privileged"])
        self.assertIn("catalog_mismatch", {row["code"] for row in finding["signals"]})

    def test_higher_source_classification_requires_review(self):
        source = next(row for row in self.scan["entitlements"] if row["id"] == BASELINE)
        source.update(sensitivity="critical", privileged=True)
        finding = self.assignment(self.run_engine())
        self.assertEqual(finding["sensitivity"], "critical")
        self.assertTrue(finding["privileged"])
        self.assertEqual(finding["recommendation"], "review")

    def test_unknown_source_privilege_remains_unknown(self):
        self.grant(entitlement=UNKNOWN)
        finding = self.assignment(self.run_engine(), entitlement=UNKNOWN)
        self.assertEqual(finding["policy_result"], "unknown_entitlement")
        self.assertEqual(finding["sensitivity"], "unknown")
        self.assertIsNone(finding["privileged"])

    def test_optional_privilege_absence_is_not_missing_baseline(self):
        self.assertEqual(self.missing(self.run_engine()), [])

    def test_required_privilege_absence_and_presence(self):
        self.profile()["expected"].append(OPTIONAL)
        missing = self.missing(self.run_engine())
        self.assertEqual([row["entitlement_id"] for row in missing], [OPTIONAL])
        self.assertTrue(missing[0]["privileged"])
        self.grant()
        result = self.run_engine()
        self.assertEqual(self.missing(result), [])
        self.assertEqual(self.assignment(result, entitlement=OPTIONAL)["policy_result"], "expected")

    def test_multiple_grants_preserve_all_assignment_evidence(self):
        self.grant(entitlement=BASELINE, suffix="second-grant")
        finding = self.assignment(self.run_engine())
        self.assertEqual(set(finding["assignment_ids"]), {"assignment:subject:baseline", "assignment:second-grant"})

    def test_disabled_account_retains_access_finding(self):
        next(row for row in self.scan["identities"] if row["id"] == "account:subject")["enabled"] = False
        finding = self.assignment(self.run_engine())
        self.assertIn("disabled_account_grants", {row["code"] for row in finding["signals"]})
        self.assertEqual(finding["recommendation"], "review")

    def test_matching_or_reused_username_never_creates_binding(self):
        self.bindings = [row for row in self.bindings if row["account_id"] != "account:subject"]
        finding = self.assignment(self.run_engine())
        self.assertEqual(finding["policy_result"], "unmatched")
        self.assertIsNone(finding["identity_id"])
        self.assertEqual(finding["evidence"]["correlations"], [])

    def test_identical_display_names_keep_explicit_id_bindings_distinct(self):
        for person in self.identities["identities"]:
            person["name"] = "Alex Morgan"
        result = self.run_engine()
        self.assertEqual(self.assignment(result)["identity_id"], "id:subject")
        self.assertEqual(self.assignment(result, account="account:peer-1")["identity_id"], "id:peer-1")

    def test_ambiguous_binding_preserves_candidates_without_selecting_one(self):
        self.bindings.append({"account_id": "account:subject", "identity_id": "id:peer-1",
                              "evidence": "Conflicting independently supplied reference."})
        finding = self.assignment(self.run_engine())
        self.assertEqual(finding["policy_result"], "ambiguous")
        self.assertIsNone(finding["identity_id"])
        self.assertEqual(len(finding["evidence"]["correlations"]), 2)

    def test_unmatched_and_ambiguous_accounts_remain_visible_without_grants(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous):
                self.setUp()
                self.remove_grants("account:subject")
                if ambiguous:
                    self.bindings.append({"account_id": "account:subject", "identity_id": "id:peer-1",
                                          "evidence": "Conflicting reference."})
                else:
                    self.bindings = [row for row in self.bindings if row["account_id"] != "account:subject"]
                finding = next(row for row in self.run_engine()["findings"] if row["account_id"] == "account:subject")
                self.assertEqual(finding["kind"], "account")
                self.assertEqual(finding["policy_result"], "ambiguous" if ambiguous else "unmatched")

    def test_duplicate_and_unresolvable_bindings_are_input_errors(self):
        for binding in (copy.deepcopy(self.bindings[0]),
                        {"account_id": "account:missing", "identity_id": "id:subject", "evidence": "Reference."},
                        {"account_id": "account:subject", "identity_id": "id:missing", "evidence": "Reference."}):
            with self.subTest(binding=binding):
                self.bindings.append(binding)
                with self.assertRaises(InputError):
                    self.run_engine()
                self.bindings.pop()

    def test_multiple_accounts_use_union_for_missing_baseline(self):
        self.remove_grants("account:subject")
        self.scan["identities"].append({"id": "account:secondary", "username": "alternate-login",
                                       "enabled": True, "source": self.scan["source"]})
        self.bindings.append({"account_id": "account:secondary", "identity_id": "id:subject",
                              "evidence": "Separate immutable account reference for the same person."})
        self.grant(account="account:secondary", entitlement=BASELINE)
        result = self.run_engine()
        self.assertEqual(self.missing(result), [])
        finding = self.assignment(result, account="account:secondary")
        self.assertEqual(set(finding["evidence"]["linked_accounts"]), {"account:subject", "account:secondary"})

    def test_missing_baseline_needs_observed_person_and_scope(self):
        self.remove_grants("account:subject")
        result = self.run_engine()
        self.assertEqual([row["entitlement_id"] for row in self.missing(result)], [BASELINE])
        self.assertEqual(self.missing(result, "id:unobserved"), [])
        self.scan["entitlements"] = [row for row in self.scan["entitlements"] if row["id"] != BASELINE]
        self.scan["scope_entitlements"].remove(BASELINE)
        self.scan["assignments"] = [row for row in self.scan["assignments"] if row["entitlement"] != BASELINE]
        self.assertEqual(self.missing(self.run_engine()), [])

    def test_peers_count_other_comparable_observed_people(self):
        finding = self.assignment(self.run_engine())
        self.assertTrue(finding["peer"]["available"])
        self.assertEqual(finding["peer"]["count"], 5)
        self.assertEqual(finding["peer"]["holders"], 5)
        self.assertEqual(finding["peer"]["ratio"], 1.0)

    def test_peer_denominator_deduplicates_multiple_accounts_and_uses_union(self):
        self.grant()
        self.scan["identities"].append({"id": "account:peer-secondary", "username": "peer-alternate",
                                       "enabled": True, "source": self.scan["source"]})
        self.bindings.append({"account_id": "account:peer-secondary", "identity_id": "id:peer-1",
                              "evidence": "Verified secondary account."})
        self.grant(account="account:peer-secondary", suffix="peer-secondary")
        finding = self.assignment(self.run_engine(), entitlement=OPTIONAL)
        self.assertEqual(finding["peer"]["count"], 5)
        self.assertEqual(finding["peer"]["holders"], 1)
        self.assertEqual(finding["peer"]["ratio"], 0.2)

    def test_sparse_and_unmatched_peers_suppress_inference(self):
        self.bindings = [row for row in self.bindings if row["account_id"] != "account:peer-1"]
        finding = self.assignment(self.run_engine())
        self.assertEqual(finding["peer"]["count"], 4)
        self.assertFalse(finding["peer"]["available"])
        self.assertIsNone(finding["peer"]["ratio"])

    def test_rarity_is_visible_without_becoming_policy_violation(self):
        self.grant()
        finding = self.assignment(self.run_engine(), entitlement=OPTIONAL)
        self.assertEqual(finding["policy_result"], "permitted_privileged")
        self.assertEqual(finding["peer"]["holders"], 0)
        self.assertIn("peer_rare", {row["code"] for row in finding["signals"]})
        self.assertEqual(finding["recommendation"], "review")

    def test_peer_agreement_never_overrides_restriction(self):
        for number, account in enumerate(["account:subject"] + [f"account:peer-{i}" for i in range(1, 6)]):
            self.grant(account=account, entitlement=FORBIDDEN, suffix=f"shared-{number}")
        finding = self.assignment(self.run_engine(), entitlement=FORBIDDEN)
        self.assertEqual(finding["peer"]["ratio"], 1.0)
        self.assertEqual(finding["policy_result"], "restricted")
        self.assertEqual(finding["recommendation"], "revoke")

    def test_ambiguous_secondary_account_suppresses_false_absence(self):
        self.remove_grants("account:subject")
        self.scan["identities"].append({"id": "account:disputed", "username": "disputed",
                                       "enabled": True, "source": self.scan["source"]})
        for identity in ("id:subject", "id:peer-1"):
            self.bindings.append({"account_id": "account:disputed", "identity_id": identity,
                                  "evidence": "Conflicting immutable reference."})
        self.grant(account="account:disputed", entitlement=BASELINE)
        self.assertEqual(self.missing(self.run_engine()), [])

    def test_subject_involved_in_secondary_ambiguity_has_no_peer_inference(self):
        self.scan["identities"].append({"id": "account:disputed", "username": "disputed",
                                       "enabled": True, "source": self.scan["source"]})
        for identity in ("id:subject", "id:contractor"):
            self.bindings.append({"account_id": "account:disputed", "identity_id": identity,
                                  "evidence": "Conflicting immutable reference."})
        self.grant()
        finding = self.assignment(self.run_engine(), entitlement=OPTIONAL)
        self.assertFalse(finding["peer"]["available"])
        self.assertIsNone(finding["peer"]["ratio"])
        self.assertNotIn("peer_rare", {row["code"] for row in finding["signals"]})

    def test_ambiguous_secondary_account_excludes_candidate_from_peer_denominator(self):
        self.scan["identities"].append({"id": "account:disputed", "username": "disputed",
                                       "enabled": True, "source": self.scan["source"]})
        for identity in ("id:peer-1", "id:contractor"):
            self.bindings.append({"account_id": "account:disputed", "identity_id": identity,
                                  "evidence": "Conflicting immutable reference."})
        self.grant()
        finding = self.assignment(self.run_engine(), entitlement=OPTIONAL)
        self.assertEqual(finding["peer"]["count"], 4)
        self.assertFalse(finding["peer"]["available"])

    def test_partial_and_stale_evidence_blocks_decisions_and_absence_inference(self):
        for case in ("partial", "stale-scan", "stale-hr", "future", "before-hr"):
            with self.subTest(case=case):
                self.setUp()
                self.remove_grants("account:subject")
                self.grant()
                now = NOW
                if case == "partial":
                    self.scan["complete"] = False
                elif case == "stale-scan":
                    now += timedelta(days=2)
                elif case == "stale-hr":
                    now += timedelta(days=31)
                    self.scan["scanned_at"] = now.isoformat().replace("+00:00", "Z")
                elif case == "future":
                    self.scan["scanned_at"] = "2026-09-21T12:06:00Z"
                else:
                    self.scan["scanned_at"] = "2026-09-20T23:00:00Z"
                    for row in self.scan["assignments"]:
                        row["timestamp"] = "2026-09-20T22:00:00Z"
                result = self.run_engine(now=now)
                self.assertFalse(result["actionable"])
                self.assertTrue(result["warnings"])
                self.assertEqual(self.missing(result), [])
                self.assertTrue(any(row["kind"] == "coverage" for row in result["findings"]))
                for row in result["findings"]:
                    self.assertFalse(row["actionable"])
                    self.assertFalse(row["peer"]["available"])

    def test_explicit_timezone_is_required_for_evaluation(self):
        with self.assertRaises(InputError):
            self.run_engine(now=NOW.replace(tzinfo=None))

    def test_risk_is_repeatable_explained_and_capped(self):
        subject = next(row for row in self.identities["identities"] if row["id"] == "id:subject")
        subject.update(status="terminated", end_date="2026-09-21")
        self.grant(entitlement=FORBIDDEN)
        first = self.run_engine()
        self.assertEqual(first, self.run_engine())
        for finding in first["findings"]:
            self.assertEqual(finding["risk_score"], min(100, sum(row["points"] for row in finding["signals"])))
            self.assertGreaterEqual(finding["risk_score"], 0)
            self.assertLessEqual(finding["risk_score"], 100)
        self.assertEqual(self.assignment(first, entitlement=FORBIDDEN)["risk_score"], 100)

    def test_evaluation_does_not_change_inputs(self):
        before = copy.deepcopy((self.identities, self.policies, self.scan, self.bindings))
        self.run_engine()
        self.assertEqual((self.identities, self.policies, self.scan, self.bindings), before)


class DomainAcceptanceTests(unittest.TestCase):
    def setUp(self):
        _, _, self.scan, self.bindings = fixtures()

    def test_empty_complete_scan_is_valid(self):
        self.scan.update(identities=[], entitlements=[], assignments=[], scope_entitlements=[])
        Scan.model_validate(self.scan)

    def test_scan_rejects_unknown_fields_and_type_coercion(self):
        for change in ({"extra": True}, {"complete": "true"}, {"schema_version": "2.0.0"},
                       {"scope_entitlements": "not-an-array"}, {"request_id": 1}):
            with self.subTest(change=change):
                with self.assertRaises(ValidationError):
                    Scan.model_validate(self.scan | change)

    def test_nested_unknown_fields_and_non_boolean_account_status_are_rejected(self):
        for field, value in (("enabled", 1), ("native_group", "staff")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.scan)
                changed["identities"][0][field] = value
                with self.assertRaises(ValidationError):
                    Scan.model_validate(changed)

    def test_duplicate_object_ids_are_rejected(self):
        for collection in ("identities", "entitlements", "assignments"):
            with self.subTest(collection=collection):
                changed = copy.deepcopy(self.scan)
                changed[collection].append(copy.deepcopy(changed[collection][0]))
                with self.assertRaises(ValidationError):
                    Scan.model_validate(changed)

    def test_source_and_assignment_references_must_resolve(self):
        for collection, field, value in (("identities", "source", "other-source"),
                                         ("entitlements", "source", "other-source"),
                                         ("assignments", "source", "other-source"),
                                         ("assignments", "identity", "account:missing"),
                                         ("assignments", "entitlement", "ent:missing:read")):
            with self.subTest(collection=collection, field=field):
                changed = copy.deepcopy(self.scan)
                changed[collection][0][field] = value
                with self.assertRaises(ValidationError):
                    Scan.model_validate(changed)

    def test_scope_requires_complete_unique_catalog_references(self):
        for scope in (self.scan["scope_entitlements"][:-1], self.scan["scope_entitlements"] + [BASELINE],
                      self.scan["scope_entitlements"] + ["ent:missing:read"]):
            with self.subTest(scope=scope):
                with self.assertRaises(ValidationError):
                    Scan.model_validate(self.scan | {"scope_entitlements": scope})

    def test_calendar_utc_and_assignment_timestamp_rules(self):
        for stamp in ("2026-09-21T12:00:00+00:00", "2026-02-30T12:00:00Z", "2026-09-21", "2026-09-21T25:00:00Z"):
            with self.subTest(stamp=stamp):
                with self.assertRaises(ValidationError):
                    Scan.model_validate(self.scan | {"scanned_at": stamp})
        self.scan["assignments"][0]["timestamp"] = "2026-09-21T12:00:01Z"
        with self.assertRaises(ValidationError):
            Scan.model_validate(self.scan)

    def test_fractional_utc_timestamp_is_valid(self):
        self.scan["scanned_at"] = "2026-09-21T12:00:00.123456Z"
        Scan.model_validate(self.scan)

    def test_control_surrogate_untrimmed_and_oversized_strings_are_rejected(self):
        for value in ("", " leading", "trailing ", "bad\x00value", "bad\x7fvalue", "bad\ud800value", "a" * 2001):
            with self.subTest(value=ascii(value[:30])):
                with self.assertRaises(ValidationError):
                    Scan.model_validate(self.scan | {"source": value})
                with self.assertRaises(ValidationError):
                    Correlation.model_validate(self.bindings[0] | {"evidence": value})

    def test_strict_json_rejects_duplicate_nonfinite_invalid_utf8_and_deep_inputs(self):
        for raw in (b'{"a": 1, "a": 1}', b'{"nested":{"a":1,"a":2}}', b'{"a":NaN}',
                    b'{"a":Infinity}', b'{"a":-Infinity}', b'{"a":"\xff"}', b'{',
                    b'[' * 2000 + b'0' + b']' * 2000):
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(InputError):
                    strict_json(raw)


if __name__ == "__main__":
    unittest.main()
