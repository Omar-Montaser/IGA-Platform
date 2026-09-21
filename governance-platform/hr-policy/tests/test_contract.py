"""Acceptance tests use independently authored records, not runtime internals."""

from __future__ import annotations

import copy
import dataclasses
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from iga_hr import BundleValidationError, load_bundle, validate_documents


PROJECT = Path(__file__).resolve().parents[1]


def documents():
    """Small independent bundle covering every supported employment state."""
    envelope = {
        "schema_version": "1.0.0",
        "dataset_id": "acceptance-fixture",
        "snapshot_at": "2026-09-21T00:00:00Z",
        "synthetic": True,
    }

    def person(identifier, status="active", **overrides):
        record = {
            "id": f"id:{identifier}",
            "username": identifier,
            "name": f"Person {identifier}",
            "department": "engineering",
            "role": "analyst",
            "status": status,
            "employment_type": "employee",
            "manager_id": "id:manager",
            "start_date": "2026-01-01",
            "end_date": None,
        }
        record.update(overrides)
        return record

    identities = {
        **envelope,
        "identities": [
            person("manager", role="manager", manager_id=None),
            person("analyst"),
            person("contractor", employment_type="contractor", end_date="2026-10-01"),
            person("leave", status="on_leave"),
            person("future", status="pre_hire", start_date="2026-09-22"),
            person("former", status="terminated", end_date="2026-09-21"),
        ],
    }
    policies = {
        **envelope,
        "effective_from": "2026-01-01",
        "unlisted_access": "review",
        "entitlements": [
            {
                "id": "ent:workspace:read",
                "name": "Workspace read",
                "description": "Read the shared workspace.",
                "type": "permission",
                "sensitivity": "low",
                "privileged": False,
            },
            {
                "id": "ent:records:read",
                "name": "Confidential records read",
                "description": "Read sensitive business records.",
                "type": "permission",
                "sensitivity": "high",
                "privileged": False,
            },
            {
                "id": "ent:workspace:admin",
                "name": "Workspace administration",
                "description": "Administer workspace access.",
                "type": "permission",
                "sensitivity": "critical",
                "privileged": True,
            },
            {
                "id": "ent:payroll:write",
                "name": "Payroll write",
                "description": "Change payroll business records.",
                "type": "permission",
                "sensitivity": "medium",
                "privileged": False,
            },
        ],
        "role_policies": [
            {
                "id": "pol:engineering-manager",
                "department": "engineering",
                "role": "manager",
                "expected": ["ent:workspace:read", "ent:workspace:admin"],
                "restricted": ["ent:payroll:write"],
                "privileged": ["ent:workspace:admin"],
            },
            {
                "id": "pol:engineering-analyst",
                "department": "engineering",
                "role": "analyst",
                "expected": ["ent:workspace:read", "ent:records:read"],
                "restricted": ["ent:payroll:write"],
                "privileged": [],
            },
        ],
        "status_rules": [
            {"status": "active", "access": "role_policy"},
            {"status": "on_leave", "access": "none"},
            {"status": "pre_hire", "access": "none"},
            {"status": "terminated", "access": "none"},
        ],
    }
    return identities, policies


class ValidationContractTests(unittest.TestCase):
    def setUp(self):
        self.identities, self.policies = documents()

    def assert_invalid(self, identities=None, policies=None):
        with self.assertRaises(BundleValidationError) as caught:
            validate_documents(
                self.identities if identities is None else identities,
                self.policies if policies is None else policies,
            )
        issues = caught.exception.issues
        self.assertIsInstance(issues, tuple)
        self.assertTrue(issues)
        for issue in issues:
            self.assertIsInstance(issue.code, str)
            self.assertTrue(issue.code)
            self.assertIsInstance(issue.path, str)
            self.assertTrue(issue.path)
            self.assertIsInstance(issue.message, str)
            self.assertTrue(issue.message)
        return issues

    def test_independent_valid_bundle(self):
        bundle = validate_documents(self.identities, self.policies)
        self.assertEqual(len(bundle.identities), 6)
        self.assertEqual(bundle.dataset_id, "acceptance-fixture")
        self.assertEqual(bundle.schema_version, "1.0.0")

    def test_required_fields_are_enforced_at_each_level(self):
        for document, path, field in [
            ("identities", (), "schema_version"),
            ("identities", ("identities", 0), "username"),
            ("identities", ("identities", 0), "manager_id"),
            ("identities", ("identities", 0), "end_date"),
            ("policies", (), "unlisted_access"),
            ("policies", ("entitlements", 0), "privileged"),
            ("policies", ("role_policies", 0), "restricted"),
            ("policies", ("status_rules", 0), "access"),
        ]:
            with self.subTest(document=document, path=path, field=field):
                identities, policies = documents()
                target = identities if document == "identities" else policies
                for component in path:
                    target = target[component]
                del target[field]
                self.assert_invalid(identities, policies)

    def test_unknown_fields_are_rejected_at_each_level(self):
        for document, path in [
            ("identities", ()),
            ("identities", ("identities", 0)),
            ("policies", ()),
            ("policies", ("entitlements", 0)),
            ("policies", ("role_policies", 0)),
            ("policies", ("status_rules", 0)),
        ]:
            with self.subTest(document=document, path=path):
                identities, policies = documents()
                target = identities if document == "identities" else policies
                for component in path:
                    target = target[component]
                target["unexpected"] = "not part of the contract"
                self.assert_invalid(identities, policies)

    def test_operational_accounts_and_scores_are_not_hr_fields(self):
        for field in ("accounts", "password", "risk_score", "scenario"):
            with self.subTest(field=field):
                identities, policies = documents()
                identities["identities"][1][field] = "forbidden"
                self.assert_invalid(identities, policies)

    def test_invalid_identity_fields(self):
        cases = [
            ("id", "user:analyst"), ("id", "id:Upper"),
            ("username", "Analyst"), ("username", "1analyst"),
            ("username", "analyst@example.test"), ("username", "a" * 65),
            ("name", ""), ("name", " Analyst"), ("name", "Analyst "),
            ("department", "Engineering"), ("role", "business analyst"),
            ("status", "disabled"), ("employment_type", "vendor"),
            ("start_date", "2026-02-30"), ("start_date", "2026-1-01"),
            ("end_date", "2027-02-29"), ("manager_id", 123),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                identities, policies = documents()
                identities["identities"][1][field] = value
                self.assert_invalid(identities, policies)

    def test_arrays_must_be_nonempty(self):
        self.identities["identities"] = []
        self.assert_invalid()
        for field in ("entitlements", "role_policies", "status_rules"):
            with self.subTest(field=field):
                identities, policies = documents()
                policies[field] = []
                self.assert_invalid(identities, policies)

    def test_duplicate_identity_ids_and_usernames_fail(self):
        for field in ("id", "username"):
            with self.subTest(field=field):
                identities, policies = documents()
                identities["identities"][2][field] = identities["identities"][1][field]
                self.assert_invalid(identities, policies)

    def test_unicode_and_duplicate_display_names_are_allowed(self):
        for person in self.identities["identities"]:
            person["name"] = "مريم García"
        bundle = validate_documents(self.identities, self.policies)
        self.assertEqual(len(bundle.identities), 6)
        self.assertEqual(bundle.identities[1].name, "مريم García")

    def test_ascii_controls_and_unpaired_surrogates_are_rejected(self):
        for character in ("\x00", "\x09", "\x0a", "\x1b", "\x1f", "\x7f", "\ud800", "\udfff"):
            for document in ("identities", "policies"):
                with self.subTest(character=ascii(character), document=document):
                    identities, policies = documents()
                    if document == "identities":
                        identities["identities"][1]["name"] = f"Before{character}After"
                    else:
                        policies["entitlements"][0]["description"] = f"Before{character}After"
                    self.assert_invalid(identities, policies)

    def test_active_start_date_is_inclusive(self):
        self.identities["identities"][1]["start_date"] = "2026-09-21"
        validate_documents(self.identities, self.policies)

    def test_active_and_leave_end_dates_are_exclusive(self):
        for status in ("active", "on_leave"):
            for end_date in ("2026-09-20", "2026-09-21"):
                with self.subTest(status=status, end_date=end_date):
                    identities, policies = documents()
                    identities["identities"][1].update(status=status, end_date=end_date)
                    self.assert_invalid(identities, policies)
            identities, policies = documents()
            identities["identities"][1].update(status=status, end_date="2026-09-22")
            validate_documents(identities, policies)

    def test_active_and_leave_must_have_started(self):
        for status in ("active", "on_leave"):
            with self.subTest(status=status):
                identities, policies = documents()
                identities["identities"][1].update(status=status, start_date="2026-09-22")
                self.assert_invalid(identities, policies)

    def test_pre_hire_start_must_be_strictly_after_snapshot(self):
        for start_date in ("2026-09-20", "2026-09-21"):
            with self.subTest(start_date=start_date):
                identities, policies = documents()
                identities["identities"][4]["start_date"] = start_date
                self.assert_invalid(identities, policies)

    def test_terminated_requires_completed_employment_window(self):
        for changes in (
            {"end_date": None}, {"end_date": "2026-09-22"},
            {"start_date": "2026-09-22", "end_date": "2026-09-23"},
        ):
            with self.subTest(changes=changes):
                identities, policies = documents()
                identities["identities"][5].update(changes)
                self.assert_invalid(identities, policies)

    def test_every_end_date_must_be_after_start_date(self):
        for end_date in ("2025-12-31", "2026-01-01"):
            with self.subTest(end_date=end_date):
                identities, policies = documents()
                identities["identities"][5]["end_date"] = end_date
                self.assert_invalid(identities, policies)

    def test_contractors_require_end_dates(self):
        self.identities["identities"][2]["end_date"] = None
        self.assert_invalid()

    def test_null_manager_is_valid(self):
        self.identities["identities"][1]["manager_id"] = None
        validate_documents(self.identities, self.policies)

    def test_missing_manager_and_self_management_fail(self):
        for manager_id in ("id:missing", "id:analyst"):
            with self.subTest(manager_id=manager_id):
                identities, policies = documents()
                identities["identities"][1]["manager_id"] = manager_id
                self.assert_invalid(identities, policies)

    def test_live_identity_requires_active_manager(self):
        for status, changes in (
            ("active", {}), ("on_leave", {}),
            ("pre_hire", {"start_date": "2026-09-22"}),
        ):
            for manager in ("id:leave", "id:former", "id:future"):
                with self.subTest(status=status, manager=manager):
                    identities, policies = documents()
                    identities["identities"][1].update(status=status, manager_id=manager, **changes)
                    self.assert_invalid(identities, policies)

    def test_terminated_identity_can_retain_inactive_manager(self):
        self.identities["identities"][5]["manager_id"] = "id:leave"
        validate_documents(self.identities, self.policies)

    def test_manager_cycle_fails(self):
        self.identities["identities"][0]["manager_id"] = "id:analyst"
        self.assert_invalid()

    def test_deep_manager_chain_does_not_depend_on_recursion_limit(self):
        template = self.identities["identities"][1]
        self.identities["identities"] = [
            {
                **template,
                "id": f"id:chain-{index}",
                "username": f"chain-{index}",
                "manager_id": f"id:chain-{index + 1}" if index < 1499 else None,
            }
            for index in range(1500)
        ]
        bundle = validate_documents(self.identities, self.policies)
        self.assertEqual(len(bundle.identities), 1500)
        self.identities["identities"][-1]["manager_id"] = "id:chain-0"
        self.assert_invalid()

    def test_all_envelope_fields_must_agree(self):
        for field, replacement in (
            ("dataset_id", "another-fixture"),
            ("snapshot_at", "2026-09-21T12:00:00Z"),
            ("synthetic", False),
        ):
            with self.subTest(field=field):
                identities, policies = documents()
                policies[field] = replacement
                self.assert_invalid(identities, policies)

    def test_unsupported_schema_version_always_fails(self):
        for which in ("identities", "policies", "both"):
            with self.subTest(which=which):
                identities, policies = documents()
                if which != "policies":
                    identities["schema_version"] = "2.0.0"
                if which != "identities":
                    policies["schema_version"] = "2.0.0"
                self.assert_invalid(identities, policies)

    def test_snapshot_requires_valid_canonical_utc_timestamp(self):
        for value in (
            "2026-09-21", "2026-09-21T00:00:00+00:00", "2026-09-21T00:00:00.000Z",
            "2026-02-30T00:00:00Z", "2026-09-21T24:00:00Z", "not-a-date",
        ):
            with self.subTest(value=value):
                identities, policies = documents()
                identities["snapshot_at"] = policies["snapshot_at"] = value
                self.assert_invalid(identities, policies)

    def test_effective_date_not_after_snapshot(self):
        self.policies["effective_from"] = "2026-09-22"
        self.assert_invalid()
        self.policies["effective_from"] = "2026-09-21"
        validate_documents(self.identities, self.policies)

    def test_invalid_policy_catalog_values(self):
        for field, value in (
            ("id", "ent:missing-namespace"), ("type", "group"),
            ("sensitivity", "extreme"), ("privileged", "false"),
            ("name", " Workspace read"), ("description", "Read workspace. "),
        ):
            with self.subTest(field=field, value=value):
                identities, policies = documents()
                policies["entitlements"][0][field] = value
                self.assert_invalid(identities, policies)

    def test_duplicate_entitlement_ids_and_names_fail(self):
        for field in ("id", "name"):
            with self.subTest(field=field):
                identities, policies = documents()
                policies["entitlements"][1][field] = policies["entitlements"][0][field]
                self.assert_invalid(identities, policies)

    def test_entitlement_names_are_unique_ignoring_case(self):
        self.policies["entitlements"][1]["name"] = self.policies["entitlements"][0]["name"].upper()
        self.assert_invalid()

    def test_profile_id_and_department_role_are_unique(self):
        duplicate_id = copy.deepcopy(self.policies)
        duplicate_id["role_policies"][1]["id"] = duplicate_id["role_policies"][0]["id"]
        self.assert_invalid(policies=duplicate_id)
        duplicate_pair = copy.deepcopy(self.policies)
        new_profile = copy.deepcopy(duplicate_pair["role_policies"][0])
        new_profile["id"] = "pol:duplicate-pair"
        duplicate_pair["role_policies"].append(new_profile)
        self.assert_invalid(policies=duplicate_pair)

    def test_every_identity_needs_matching_profile(self):
        self.identities["identities"][5]["role"] = "unknown-role"
        self.assert_invalid()

    def test_referenced_entitlements_must_exist(self):
        for field in ("expected", "restricted", "privileged"):
            with self.subTest(field=field):
                identities, policies = documents()
                policies["role_policies"][1][field].append("ent:unknown:read")
                self.assert_invalid(identities, policies)

    def test_duplicate_references_in_each_list_fail(self):
        for field in ("expected", "restricted", "privileged"):
            with self.subTest(field=field):
                identities, policies = documents()
                entries = policies["role_policies"][0][field]
                entries.append(entries[0])
                self.assert_invalid(identities, policies)

    def test_restricted_cannot_overlap_expected_or_privileged(self):
        for field in ("expected", "privileged"):
            with self.subTest(field=field):
                identities, policies = documents()
                profile = policies["role_policies"][0]
                profile["restricted"].append(profile[field][0])
                self.assert_invalid(identities, policies)

    def test_expected_privileged_access_must_also_be_explicitly_permitted(self):
        self.policies["role_policies"][0]["privileged"] = []
        self.assert_invalid()

    def test_privileged_profile_references_require_catalog_privilege(self):
        self.policies["role_policies"][1]["privileged"].append("ent:records:read")
        self.assert_invalid()

    def test_sensitivity_and_privilege_are_independent(self):
        self.policies["entitlements"][2]["sensitivity"] = "low"
        bundle = validate_documents(self.identities, self.policies)
        by_id = {item.id: item for item in bundle.entitlements}
        self.assertFalse(by_id["ent:records:read"].privileged)
        self.assertTrue(by_id["ent:workspace:admin"].privileged)

    def test_optional_privilege_does_not_need_to_be_expected(self):
        self.policies["role_policies"][0]["expected"].remove("ent:workspace:admin")
        validate_documents(self.identities, self.policies)

    def test_known_unlisted_access_is_allowed_in_catalog(self):
        for profile in self.policies["role_policies"]:
            profile["restricted"] = []
        validate_documents(self.identities, self.policies)

    def test_status_rules_must_be_complete_unique_and_conservative(self):
        missing = copy.deepcopy(self.policies)
        missing["status_rules"].pop()
        self.assert_invalid(policies=missing)
        duplicate = copy.deepcopy(self.policies)
        duplicate["status_rules"].append(copy.deepcopy(duplicate["status_rules"][0]))
        self.assert_invalid(policies=duplicate)
        for index in range(4):
            with self.subTest(index=index):
                policies = copy.deepcopy(self.policies)
                policies["status_rules"][index]["access"] = "none" if index == 0 else "role_policy"
                self.assert_invalid(policies=policies)

    def test_unlisted_access_must_remain_reviewable(self):
        for value in ("allow", "deny", "ignore"):
            with self.subTest(value=value):
                policies = copy.deepcopy(self.policies)
                policies["unlisted_access"] = value
                self.assert_invalid(policies=policies)


class ConsumerApiTests(unittest.TestCase):
    def setUp(self):
        self.identities, self.policies = documents()
        self.bundle = validate_documents(self.identities, self.policies)

    def test_id_and_username_lookup(self):
        identity = self.bundle.identity_by_id("id:analyst")
        self.assertEqual(identity.username, "analyst")
        self.assertEqual(self.bundle.identity_by_username("analyst"), identity)
        self.assertIsNone(self.bundle.identity_by_id("id:missing"))
        self.assertIsNone(self.bundle.identity_by_username("missing"))
        self.assertIsNone(self.bundle.identity_by_username("Analyst"))

    def test_policy_lookup_and_unknown_identity(self):
        profile = self.bundle.policy_for("id:analyst")
        self.assertEqual((profile.department, profile.role), ("engineering", "analyst"))
        with self.assertRaises(KeyError):
            self.bundle.policy_for("id:missing")
        with self.assertRaises(KeyError):
            self.bundle.context_for("id:missing")

    def test_all_records_and_collections_are_immutable(self):
        for field in ("identities", "entitlements", "role_policies", "status_rules"):
            records = getattr(self.bundle, field)
            self.assertIsInstance(records, tuple)
            for record in records:
                self.assertTrue(dataclasses.is_dataclass(record))
                first_field = dataclasses.fields(record)[0].name
                with self.assertRaises((AttributeError, TypeError)):
                    setattr(record, first_field, "changed")
        for profile in self.bundle.role_policies:
            for field in ("expected", "restricted", "privileged"):
                self.assertIsInstance(getattr(profile, field), tuple)
        with self.assertRaises((AttributeError, TypeError)):
            self.bundle.dataset_id = "changed"

    def test_bundle_is_detached_from_caller_documents(self):
        original_name = self.bundle.identity_by_id("id:analyst").name
        self.identities["identities"][1]["name"] = "Changed name"
        self.policies["role_policies"][1]["expected"].clear()
        self.assertEqual(self.bundle.identity_by_id("id:analyst").name, original_name)
        self.assertTrue(self.bundle.policy_for("id:analyst").expected)

    def test_context_is_fresh_and_json_ready(self):
        original = self.bundle.context_for("id:analyst")
        self.assertEqual(set(original), {"identity", "role_policy", "status_rule"})
        self.assertEqual(original["identity"]["id"], "id:analyst")
        json.dumps(original, allow_nan=False)
        changed = self.bundle.context_for("id:analyst")
        changed["identity"]["name"] = "Changed name"
        changed["role_policy"]["expected"].clear()
        changed["status_rule"]["access"] = "none"
        self.assertEqual(self.bundle.context_for("id:analyst"), original)

    def test_context_preserves_lifecycle_without_judging_assignments(self):
        for status in ("active", "on_leave", "pre_hire", "terminated"):
            person = next(item for item in self.bundle.identities if item.status == status)
            context = self.bundle.context_for(person.id)
            self.assertEqual(context["status_rule"]["status"], status)
            self.assertEqual(context["status_rule"]["access"], "role_policy" if status == "active" else "none")
            self.assertNotIn("decision", context)
            self.assertNotIn("assignments", context)

    def test_summary_is_json_ready(self):
        summary = self.bundle.summary()
        self.assertIsInstance(summary, dict)
        json.dumps(summary, allow_nan=False)
        self.assertEqual(summary["dataset_id"], self.bundle.dataset_id)


class FilesystemAndCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.identities_path = self.root / "identities.json"
        self.policies_path = self.root / "policies.json"
        self.identities, self.policies = documents()
        self.write_documents()

    def write_documents(self):
        self.identities_path.write_text(json.dumps(self.identities, ensure_ascii=False), encoding="utf-8")
        self.policies_path.write_text(json.dumps(self.policies, ensure_ascii=False), encoding="utf-8")

    def run_cli(self, *arguments):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(PROJECT / "src") + os.pathsep + environment.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, "-m", "iga_hr", *map(str, arguments)],
            cwd=PROJECT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )

    def assert_load_invalid(self):
        with self.assertRaises(BundleValidationError) as caught:
            load_bundle(self.identities_path, self.policies_path)
        self.assertTrue(caught.exception.issues)
        for issue in caught.exception.issues:
            self.assertTrue(issue.code)
            self.assertTrue(issue.path)

    def test_load_bundle_round_trip(self):
        loaded = load_bundle(self.identities_path, self.policies_path)
        expected = validate_documents(self.identities, self.policies)
        self.assertEqual(loaded.context_for("id:analyst"), expected.context_for("id:analyst"))

    def test_malformed_json_and_invalid_utf8_are_structured_errors(self):
        for payload in (b"{", b"[]", b"null", b"{\"invalid\":\xff}", b"{} trailing"):
            with self.subTest(payload=payload):
                self.identities_path.write_bytes(payload)
                self.assert_load_invalid()

    def test_deeply_nested_json_raises_structured_validation_error(self):
        payload = b"[" * 2000 + b"0" + b"]" * 2000
        self.identities_path.write_bytes(payload)
        self.assert_load_invalid()

    def test_duplicate_json_keys_are_rejected_even_when_values_match(self):
        valid = json.dumps(self.identities)
        payloads = [
            valid.replace('"dataset_id": "acceptance-fixture"', '"dataset_id": "acceptance-fixture", "dataset_id": "acceptance-fixture"'),
            valid.replace('"username": "analyst"', '"username": "analyst", "username": "analyst"'),
        ]
        for payload in payloads:
            with self.subTest(payload=payload[:80]):
                self.identities_path.write_text(payload, encoding="utf-8")
                self.assert_load_invalid()

    def test_nonfinite_json_numbers_are_rejected(self):
        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(literal=literal):
                payload = json.dumps(self.identities).replace('"synthetic": true', f'"synthetic": {literal}')
                self.identities_path.write_text(payload, encoding="utf-8")
                self.assert_load_invalid()

    def test_files_larger_than_ten_mib_are_rejected(self):
        # Valid JSON plus insignificant whitespace isolates the size boundary.
        valid_json = self.identities_path.read_bytes()
        self.identities_path.write_bytes(valid_json + b" " * (10 * 1024 * 1024 + 1))
        self.assert_load_invalid()

    def test_policy_json_uses_the_same_strict_parser(self):
        payload = json.dumps(self.policies).replace('"unlisted_access": "review"', '"unlisted_access": "review", "unlisted_access": "review"')
        self.policies_path.write_text(payload, encoding="utf-8")
        self.assert_load_invalid()

    def test_missing_files_and_directory_inputs_are_validation_errors(self):
        self.identities_path.unlink()
        self.assert_load_invalid()
        self.identities_path.mkdir()
        self.assert_load_invalid()

    def test_semantic_errors_are_rejected_by_file_loader(self):
        self.identities["identities"][1]["manager_id"] = "id:missing"
        self.write_documents()
        self.assert_load_invalid()

    def test_cli_validate_success_json_and_text(self):
        for options in ([], ["--json"]):
            with self.subTest(options=options):
                result = self.run_cli("validate", self.identities_path, self.policies_path, *options)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.strip())
                self.assertNotIn("Traceback", result.stderr)
                if options:
                    self.assertIsInstance(json.loads(result.stdout), dict)

    def test_cli_validation_failure_exit_code(self):
        self.identities["identities"][1]["username"] = "INVALID"
        self.write_documents()
        result = self.run_cli("validate", self.identities_path, self.policies_path, "--json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertTrue(result.stdout.strip() or result.stderr.strip())

    def test_cli_context_matches_consumer_api(self):
        result = self.run_cli("context", self.identities_path, self.policies_path, "id:analyst")
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = validate_documents(self.identities, self.policies).context_for("id:analyst")
        self.assertEqual(json.loads(result.stdout), expected)

    def test_cli_unknown_identity_is_a_clean_input_error(self):
        result = self.run_cli("context", self.identities_path, self.policies_path, "id:missing")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_cli_malformed_file_is_a_clean_input_error(self):
        self.identities_path.write_bytes(b"{not json}")
        result = self.run_cli("validate", self.identities_path, self.policies_path)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_cli_usage_error_exit_code(self):
        for arguments in ([], ["invalid-command"], ["validate"]):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 2)


class ShippedDemoTests(unittest.TestCase):
    def run_generator(self, *arguments):
        return subprocess.run(
            [sys.executable, str(PROJECT / "scripts" / "generate_demo.py"), *map(str, arguments)],
            cwd=PROJECT,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )

    def test_shipped_demo_is_valid_and_covers_project_scenarios(self):
        bundle = load_bundle(PROJECT / "data" / "identities.json", PROJECT / "data" / "policies.json")
        self.assertTrue(bundle.synthetic)
        self.assertEqual(len(bundle.identities), 72)
        self.assertEqual(len({person.department for person in bundle.identities}), 6)
        self.assertEqual(len(bundle.role_policies), 12)
        self.assertEqual({person.status for person in bundle.identities}, {"active", "on_leave", "pre_hire", "terminated"})
        self.assertEqual({person.employment_type for person in bundle.identities}, {"employee", "contractor"})
        for person in bundle.identities:
            self.assertEqual(bundle.context_for(person.id)["identity"]["id"], person.id)

    def test_shipped_demo_matches_generator_without_modification(self):
        paths = [PROJECT / "data" / name for name in ("identities.json", "policies.json")]
        before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
        result = self.run_generator("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([(path.read_bytes(), path.stat().st_mtime_ns) for path in paths], before)

    def test_generation_is_reproducible_and_check_detects_drift_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            result = self.run_generator("--output-dir", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("identities.json", "policies.json"):
                self.assertEqual((output / name).read_bytes(), (PROJECT / "data" / name).read_bytes())
            result = self.run_generator("--output-dir", output, "--check")
            self.assertEqual(result.returncode, 0, result.stderr)
            changed = output / "identities.json"
            changed.write_bytes(changed.read_bytes() + b"\n")
            before = changed.read_bytes()
            result = self.run_generator("--output-dir", output, "--check")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(changed.read_bytes(), before)

    def test_check_missing_directory_does_not_create_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "missing"
            result = self.run_generator("--output-dir", output, "--check")
            self.assertEqual(result.returncode, 1)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
