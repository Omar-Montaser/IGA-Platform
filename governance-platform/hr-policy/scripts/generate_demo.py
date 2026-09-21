#!/usr/bin/env python3
"""Reproduce the frozen, wholly synthetic Module 1 demo without dependencies."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unicodedata


SNAPSHOT_AT = "2026-09-21T00:00:00Z"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "data"
DEPARTMENTS = (
    ("engineering", "software-engineer"),
    ("finance", "financial-analyst"),
    ("hr", "people-operations-specialist"),
    ("sales", "account-executive"),
    ("marketing", "marketing-specialist"),
    ("it", "service-desk-analyst"),
)
FIRST_NAMES = (
    "Ada", "Amir", "Ana", "Casey", "Chen", "Dara", "Emi", "Finley", "Harper",
    "Ira", "Jules", "Kai", "Lena", "Noor", "Remy", "Sam", "Taylor", "Zuri",
)
LAST_NAMES = (
    "Bennett", "Brooks", "Carter", "Diaz", "Evans", "Farah", "Gray", "Hayes",
    "Ibrahim", "Jordan", "Kim", "Lane", "Malik", "Nguyen", "Patel", "Reed",
    "Santos",
)


def envelope() -> dict:
    return {
        "schema_version": "1.0.0",
        "dataset_id": "access-review-demo-2026-09-21",
        "snapshot_at": SNAPSHOT_AT,
        "synthetic": True,
    }


def build_identities() -> dict:
    identities = []
    for department_index, (department, specialist_role) in enumerate(DEPARTMENTS):
        first_number = department_index * 12 + 1
        manager_id = f"id:person-{first_number:04d}"
        for position in range(12):
            number = first_number + position
            name = (
                "Alex Morgan" if number in (2, 14)
                else f"{FIRST_NAMES[(number - 1) % len(FIRST_NAMES)]} "
                f"{LAST_NAMES[(number - 1) % len(LAST_NAMES)]}"
            )
            name = {3: "Zoë Bennett", 15: "Renée Nguyen"}.get(number, name)
            # This only constructs known demo logins. Real correlation belongs
            # to the consumer and must not derive identity from a display name.
            login_stem = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
            status = {9: "on_leave", 10: "terminated", 11: "pre_hire"}.get(
                position, "active"
            )
            # Two active contractors per department; no personal data is used.
            is_contractor = position in (7, 8)
            start_date = (
                "2026-10-05" if status == "pre_hire"
                else "2026-09-20" if position == 8
                else "2026-06-01" if is_contractor
                else "2023-01-16" if position == 0
                else f"2024-{position:02d}-15"
            )
            end_date = (
                "2026-09-21" if status == "terminated"
                else "2027-03-31" if is_contractor
                else None
            )
            identities.append({
                "id": f"id:person-{number:04d}",
                "username": f"{login_stem.lower().replace(' ', '.')}.{number:04d}",
                "name": name,
                "department": department,
                "role": f"{department}-manager" if position == 0 else specialist_role,
                "status": status,
                "employment_type": "contractor" if is_contractor else "employee",
                "manager_id": None if position == 0 else manager_id,
                "start_date": start_date,
                "end_date": end_date,
            })
    return {**envelope(), "identities": identities}


def entitlement(
    identifier: str, name: str, description: str, sensitivity: str,
    privileged: bool = False,
) -> dict:
    return {
        "id": identifier,
        "name": name,
        "description": description,
        "type": "permission",
        "sensitivity": sensitivity,
        "privileged": privileged,
    }


def build_policies() -> dict:
    entitlements = [
        entitlement("ent:collaboration:workspace-read", "Read shared workspaces",
                    "Read ordinary internal collaboration content.", "low"),
        entitlement("ent:collaboration:workspace-write", "Contribute to shared workspaces",
                    "Create and edit ordinary internal collaboration content.", "medium"),
        entitlement("ent:knowledge:articles-read", "Read internal knowledge articles",
                    "Read general internal operating guidance.", "low"),
        entitlement("ent:hr:directory-read", "Read employee directory",
                    "View basic work directory information.", "medium"),
        entitlement("ent:hr:employee-records-read", "Read confidential employee records",
                    "Read restricted human resources employment records.", "high"),
        entitlement("ent:hr:employee-records-write", "Maintain confidential employee records",
                    "Create and update restricted human resources employment records.", "high"),
        entitlement("ent:hr:payroll-admin", "Administer payroll configuration",
                    "Change payroll processing configuration and administrative settings.", "critical", True),
        entitlement("ent:finance:invoices-read", "Read invoices",
                    "Read business invoices and their processing status.", "medium"),
        entitlement("ent:finance:invoices-manage", "Process invoices",
                    "Create and update invoices without approving payments.", "high"),
        entitlement("ent:finance:payments-approve", "Approve payments",
                    "Authorize outgoing business payments as a designated approver.", "critical", True),
        entitlement("ent:finance:ledger-admin", "Administer financial ledger",
                    "Change ledger configuration and privileged accounting settings.", "critical", True),
        entitlement("ent:sales:customer-records-read", "Read customer records",
                    "Read customer and prospect business records.", "high"),
        entitlement("ent:sales:customer-records-write", "Maintain customer records",
                    "Create and update customer and prospect business records.", "high"),
        entitlement("ent:sales:pricing-approve", "Approve sales pricing",
                    "Approve pricing exceptions within the sales process.", "high"),
        entitlement("ent:marketing:campaigns-read", "Read marketing campaigns",
                    "View campaign plans and aggregate performance.", "medium"),
        entitlement("ent:marketing:campaigns-manage", "Manage marketing campaigns",
                    "Create and update marketing campaigns.", "medium"),
        entitlement("ent:marketing:audience-export", "Export marketing audiences",
                    "Export approved audience records for campaign operations.", "high"),
        entitlement("ent:engineering:source-read", "Read source code",
                    "Read internal application source code.", "high"),
        entitlement("ent:engineering:source-write", "Contribute source code",
                    "Submit and maintain changes to internal application source code.", "high"),
        entitlement("ent:engineering:production-deploy", "Deploy to production",
                    "Release approved application versions into production.", "critical", True),
        entitlement("ent:it:tickets-manage", "Manage service desk tickets",
                    "Triage and resolve internal support tickets.", "medium"),
        entitlement("ent:it:infrastructure-admin", "Administer infrastructure",
                    "Change production infrastructure and administrative settings.", "critical", True),
        entitlement("ent:security:audit-read", "Read security audit records",
                    "Read restricted security audit evidence.", "high"),
    ]
    baseline = [
        "ent:collaboration:workspace-read", "ent:collaboration:workspace-write",
        "ent:knowledge:articles-read", "ent:hr:directory-read",
    ]
    job_access = {
        "engineering": ["ent:engineering:source-read", "ent:engineering:source-write"],
        "finance": ["ent:finance:invoices-read", "ent:finance:invoices-manage"],
        "hr": ["ent:hr:employee-records-read", "ent:hr:employee-records-write"],
        "sales": ["ent:sales:customer-records-read", "ent:sales:customer-records-write"],
        "marketing": ["ent:marketing:campaigns-read", "ent:marketing:campaigns-manage"],
        "it": ["ent:it:tickets-manage"],
    }
    manager_access = {
        "engineering": [],
        "finance": ["ent:finance:payments-approve"],
        "hr": [],
        "sales": ["ent:sales:pricing-approve"],
        "marketing": ["ent:marketing:audience-export"],
        "it": ["ent:it:infrastructure-admin"],
    }
    manager_privilege = {
        "engineering": ["ent:engineering:production-deploy"],
        "finance": ["ent:finance:payments-approve", "ent:finance:ledger-admin"],
        "hr": ["ent:hr:payroll-admin"],
        "sales": [],
        "marketing": [],
        "it": ["ent:it:infrastructure-admin"],
    }
    # Explicit forbidden capabilities are a curated subset. Remaining known
    # capabilities stay reviewable under unlisted_access; absence is not approval.
    restricted_shared = [
        item["id"] for item in entitlements if item["privileged"]
    ]
    role_policies = []
    for department, specialist_role in DEPARTMENTS:
        for is_manager in (False, True):
            role = f"{department}-manager" if is_manager else specialist_role
            expected = baseline + job_access[department]
            privileged = manager_privilege[department] if is_manager else []
            if is_manager:
                expected = expected + manager_access[department]
            restricted = [item for item in restricted_shared if item not in privileged]
            if department != "hr":
                restricted += ["ent:hr:employee-records-read", "ent:hr:employee-records-write"]
            if department != "engineering":
                restricted.append("ent:engineering:source-write")
            if not is_manager and department in ("sales", "marketing"):
                restricted += manager_access[department]
            role_policies.append({
                "id": f"pol:{department}-{'manager' if is_manager else 'specialist'}",
                "department": department,
                "role": role,
                "expected": sorted(expected),
                "restricted": sorted(restricted),
                "privileged": sorted(privileged),
            })
    return {
        **envelope(),
        "effective_from": "2026-09-01",
        "unlisted_access": "review",
        "entitlements": entitlements,
        "role_policies": role_policies,
        "status_rules": [
            {"status": status, "access": "role_policy" if status == "active" else "none"}
            for status in ("active", "on_leave", "pre_hire", "terminated")
        ],
    }


def generated_files() -> dict[str, bytes]:
    return {
        name: (json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        for name, document in (
            ("identities.json", build_identities()), ("policies.json", build_policies())
        )
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help="destination directory (default: this project's data directory)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
                      help="compare exact bytes to generated data, without writing anything")
    mode.add_argument("--force", action="store_true",
                      help="replace differing regular output files after checking both paths")
    args = parser.parse_args(argv)
    files = generated_files()
    pending = []
    try:
        # Check both paths before mutating either. Never follow an output-file
        # symlink, even with --force; identical files need no rewrite.
        problems = []
        for name, content in files.items():
            destination = args.output_dir / name
            if destination.is_symlink():
                problems.append(f"Refusing symbolic-link output: {destination}")
                continue
            if destination.exists() and not destination.is_file():
                problems.append(f"Output is not a regular file: {destination}")
                continue
            exists = destination.exists()
            if exists and destination.read_bytes() == content:
                continue
            if args.check:
                problems.append(f"{'Different' if exists else 'Missing'}: {destination}")
            elif exists and not args.force:
                problems.append(f"Refusing to overwrite differing file: {destination} (use --force)")
            else:
                pending.append((destination, content))
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 1
        if args.check:
            print("Demo dataset matches generated bytes.")
            return 0
        if pending:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            staged = []
            try:
                for destination, content in pending:
                    with tempfile.NamedTemporaryFile(
                        mode="wb", dir=args.output_dir, prefix=f".{destination.name}.",
                        suffix=".tmp", delete=False,
                    ) as temporary:
                        staged.append((Path(temporary.name), destination))
                        temporary.write(content)
                        temporary.flush()
                        os.fsync(temporary.fileno())
                    Path(temporary.name).chmod(0o644)
                for temporary, destination in staged:
                    os.replace(temporary, destination)
            finally:
                for temporary, _ in staged:
                    temporary.unlink(missing_ok=True)
        print(f"Demo dataset ready: {args.output_dir}")
        return 0
    except OSError as error:
        print(f"Unable to generate or check demo dataset: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
