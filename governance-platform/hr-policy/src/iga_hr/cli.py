"""Read-only command line interface for validating and inspecting a bundle."""

import argparse
import json
import sys

from .validation import BundleValidationError, load_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate both files together")
    validate.add_argument("identities", help="Path to identities.json")
    validate.add_argument("policies", help="Path to policies.json")
    validate.add_argument("--json", action="store_true", help="Print machine-readable summary")
    context = commands.add_parser("context", help="Print identity and policy context for Module 4")
    context.add_argument("identities", help="Path to identities.json")
    context.add_argument("policies", help="Path to policies.json")
    context.add_argument("identity_id", help="Stable HR identity ID")
    args = parser.parse_args(argv)
    try:
        bundle = load_bundle(args.identities, args.policies)
    except BundleValidationError as exc:
        for issue in exc.issues:
            print(f"{issue.path}: [{issue.code}] {issue.message}", file=sys.stderr)
        return 1
    if args.command == "context":
        try:
            result = bundle.context_for(args.identity_id)
        except KeyError:
            print("Unknown identity ID in this bundle.", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    elif args.json:
        print(json.dumps(bundle.summary(), indent=2, ensure_ascii=False, allow_nan=False))
    else:
        summary = bundle.summary()
        print(f"Valid bundle {bundle.dataset_id} (schema {bundle.schema_version}, snapshot {bundle.snapshot_at})")
        print(f"{summary['identities']} identities; {summary['departments']} departments; "
              f"{summary['role_policies']} role policies; {summary['entitlements']} entitlements.")
    return 0
