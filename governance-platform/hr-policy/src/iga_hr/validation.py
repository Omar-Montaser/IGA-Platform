"""Strict structural and relational validation of Module 1's two-file contract."""

from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from importlib.resources import files
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator, FormatChecker

from .models import Bundle, Entitlement, Identity, RolePolicy, StatusRule

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_REPORTED_ISSUES = 100
STATUSES = frozenset({"active", "on_leave", "pre_hire", "terminated"})


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    path: str
    message: str


class BundleValidationError(ValueError):
    """No usable bundle exists when any of these issues is present."""

    def __init__(self, issues: list[ValidationIssue] | tuple[ValidationIssue, ...]):
        self.issues = tuple(issues)
        super().__init__("; ".join(f"{item.path}: {item.message}" for item in self.issues))


_formats = FormatChecker()


@_formats.checks("date")
def _calendar_date(value: object) -> bool:
    if not isinstance(value, str):
        return True  # JSON Schema's type keyword handles non-strings.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value, flags=re.ASCII):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


@_formats.checks("date-time")
def _utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return True
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value, flags=re.ASCII):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


@lru_cache(maxsize=2)
def _validator(kind: str) -> Draft202012Validator:
    schema_path = files("iga_hr").joinpath("schemas", f"{kind}.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=_formats)


def _strict_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key is not allowed")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite JSON number is not allowed")


def _read_document(path: str | Path, kind: str) -> dict:
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError(f"Input exceeds {MAX_FILE_BYTES} byte limit")
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (OSError, ValueError, RecursionError) as exc:
        # UnicodeDecodeError and JSONDecodeError are ValueErrors.
        message = str(exc) if not isinstance(exc, RecursionError) else "JSON nesting is too deep"
        raise BundleValidationError([ValidationIssue("input", kind, message)]) from exc


def load_bundle(identities_path: str | Path, policies_path: str | Path) -> Bundle:
    """Read and validate the complete pair before exposing any consumer data."""
    identities = _read_document(identities_path, "identities.json")
    policies = _read_document(policies_path, "policies.json")
    return validate_documents(identities, policies)


def _path(root: str, parts) -> str:
    # JSON Pointer escaping keeps malformed property names unambiguous.
    return root + "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def validate_documents(identities: dict, policies: dict) -> Bundle:
    """Validate structure, lifecycle, references, and policy consistency.

    Copies all accepted data into frozen models. This does not judge access,
    prove snapshot authenticity, or enforce historical ID immutability.
    """
    issues: list[ValidationIssue] = []

    def report(code: str, path: str, message: str) -> None:
        if len(issues) < MAX_REPORTED_ISSUES:
            issues.append(ValidationIssue(code, path, message))

    for kind, document in (("identities", identities), ("policies", policies)):
        try:
            for error in _validator(kind).iter_errors(document):
                report("schema", _path(f"{kind}.json", error.absolute_path), error.message)
                if len(issues) >= MAX_REPORTED_ISSUES:
                    break
        except RecursionError as exc:
            raise BundleValidationError([
                ValidationIssue("schema", f"{kind}.json", "Document nesting is too deep")
            ]) from exc
    if issues:
        raise BundleValidationError(issues)

    # Check trimmed human-readable values too, without silently rewriting input.
    for kind, document in (("identities", identities), ("policies", policies)):
        pending = [(f"{kind}.json", document)]
        while pending:
            path, value = pending.pop()
            if isinstance(value, dict):
                pending.extend((_path(path, [key]), item) for key, item in value.items())
            elif isinstance(value, list):
                pending.extend((_path(path, [index]), item) for index, item in enumerate(value))
            elif isinstance(value, str):
                if not value.strip() or value != value.strip():
                    report("canonical", path, "String must be nonempty and have no surrounding whitespace")
                if any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value):
                    report("canonical", path, "Control characters and unpaired Unicode surrogates are not allowed")

    for field in ("schema_version", "dataset_id", "snapshot_at", "synthetic"):
        if identities[field] != policies[field]:
            report("bundle_mismatch", f"policies.json/{field}", "Value must match identities.json")

    snapshot = datetime.fromisoformat(identities["snapshot_at"]).date()
    if date.fromisoformat(policies["effective_from"]) > snapshot:
        report("effective_date", "policies.json/effective_from", "Policy is not effective at the snapshot date")

    people = identities["identities"]
    catalog = policies["entitlements"]
    profiles = policies["role_policies"]
    status_rules = policies["status_rules"]

    def unique_index(records: list[dict], field: str, path: str, *, folded: bool = False) -> dict:
        index = {}
        for i, record in enumerate(records):
            key = record[field].casefold() if folded else record[field]
            if key in index:
                report("duplicate", f"{path}/{i}/{field}", f"Duplicate {field}")
            else:
                index[key] = record
        return index

    people_by_id = unique_index(people, "id", "identities.json/identities")
    unique_index(people, "username", "identities.json/identities", folded=True)
    catalog_by_id = unique_index(catalog, "id", "policies.json/entitlements")
    unique_index(catalog, "name", "policies.json/entitlements", folded=True)
    unique_index(profiles, "id", "policies.json/role_policies")
    rules_by_status = unique_index(status_rules, "status", "policies.json/status_rules")
    if set(rules_by_status) != STATUSES:
        report("status_coverage", "policies.json/status_rules", "Exactly one rule is required for every supported status")
    for i, rule in enumerate(status_rules):
        required = "role_policy" if rule["status"] == "active" else "none"
        if rule["access"] != required:
            report("status_access", f"policies.json/status_rules/{i}/access", f"This status requires access={required}")

    profiles_by_key = {}
    for i, profile in enumerate(profiles):
        path = f"policies.json/role_policies/{i}"
        key = (profile["department"], profile["role"])
        if key in profiles_by_key:
            report("duplicate_profile", path, "Department and role must identify exactly one policy")
        else:
            profiles_by_key[key] = profile
        expected, restricted, privileged = (set(profile[field]) for field in ("expected", "restricted", "privileged"))
        if restricted & (expected | privileged):
            report("policy_conflict", path, "Restricted access overlaps expected or permitted privileged access")
        for field in ("expected", "restricted", "privileged"):
            for j, entitlement_id in enumerate(profile[field]):
                if entitlement_id not in catalog_by_id:
                    report("unknown_entitlement", f"{path}/{field}/{j}", "Entitlement ID is absent from the catalog")
        for entitlement_id in privileged:
            entitlement = catalog_by_id.get(entitlement_id)
            if entitlement and not entitlement["privileged"]:
                report("privilege_classification", f"{path}/privileged", "Permitted privileged access must be marked privileged in the catalog")
        for entitlement_id in expected:
            entitlement = catalog_by_id.get(entitlement_id)
            if entitlement and entitlement["privileged"] and entitlement_id not in privileged:
                report("privilege_classification", f"{path}/expected", "Expected privileged access must also be in the profile's privileged list")

    for i, person in enumerate(people):
        path = f"identities.json/identities/{i}"
        if (person["department"], person["role"]) not in profiles_by_key:
            report("policy_coverage", path, "No policy exists for this department and role")
        start = date.fromisoformat(person["start_date"])
        end = date.fromisoformat(person["end_date"]) if person["end_date"] is not None else None
        if end is not None and end <= start:
            report("employment_dates", f"{path}/end_date", "End date must be strictly after start date")
        if person["employment_type"] == "contractor" and end is None:
            report("contract_end", f"{path}/end_date", "Contractors require an end date")
        status = person["status"]
        if status == "pre_hire":
            if start <= snapshot:
                report("lifecycle", f"{path}/start_date", "Pre-hire must start after the snapshot date")
        elif start > snapshot:
            report("lifecycle", f"{path}/start_date", "This employment status requires a start on or before the snapshot date")
        if status == "terminated":
            if end is None or end > snapshot:
                report("lifecycle", f"{path}/end_date", "Terminated identities require an end date on or before the snapshot")
        elif status in {"active", "on_leave"} and end is not None and end <= snapshot:
            report("lifecycle", f"{path}/end_date", "Active and on-leave identities cannot have reached their end date")
        manager_id = person["manager_id"]
        if manager_id is not None:
            manager = people_by_id.get(manager_id)
            if manager is None:
                report("unknown_manager", f"{path}/manager_id", "Manager ID is absent from the identity document")
            elif manager_id == person["id"]:
                report("manager_cycle", f"{path}/manager_id", "An identity cannot manage itself")
            elif status != "terminated" and manager["status"] != "active":
                report("inactive_manager", f"{path}/manager_id", "A current or future employee's manager must be active")

    # Linear graph walk, deliberately iterative so long valid manager chains
    # and cycles do not exhaust Python's call stack.
    complete: set[str] = set()
    for identity_id in people_by_id:
        chain: set[str] = set()
        current = identity_id
        while current in people_by_id and current not in complete:
            if current in chain:
                report("manager_cycle", "identities.json/identities", "Management graph contains a cycle")
                break
            chain.add(current)
            current = people_by_id[current]["manager_id"]
        complete.update(chain)

    if issues:
        raise BundleValidationError(issues)
    return Bundle(
        schema_version=identities["schema_version"],
        dataset_id=identities["dataset_id"],
        snapshot_at=identities["snapshot_at"],
        synthetic=identities["synthetic"],
        effective_from=policies["effective_from"],
        unlisted_access=policies["unlisted_access"],
        identities=tuple(Identity(**item) for item in people),
        entitlements=tuple(Entitlement(**item) for item in catalog),
        role_policies=tuple(RolePolicy(
            id=item["id"], department=item["department"], role=item["role"],
            expected=tuple(item["expected"]), restricted=tuple(item["restricted"]),
            privileged=tuple(item["privileged"]),
        ) for item in profiles),
        status_rules=tuple(StatusRule(**item) for item in status_rules),
    )
