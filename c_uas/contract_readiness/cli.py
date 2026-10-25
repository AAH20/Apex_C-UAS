"""
CLI for the Contract Readiness Engine:

    c-uas contract --verify --spec openapi.yaml
    c-uas contract --breaking --spec openapi.yaml --old-spec openapi.prev.yaml
    c-uas contract --gate --spec openapi.yaml --old-spec openapi.prev.yaml

--verify compares spec routes against the FastAPI app route table and
reports missing / extra / mismatched routes.
--breaking compares two OpenAPI specs for breaking changes.
--gate runs the CI gate: non-zero exit on missing routes or breaking changes;
last-run state persists under ~/.c-uas-platform/contract_readiness/.

All output is deterministic: identical inputs produce identical output.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, List, Optional, Sequence

from .breaking import BreakingReport, detect_breaking_changes_from_files
from .ci_gate import run_gate
from .contract import ContractReport, load_app_routes, verify_contract


def _add_contract_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify spec routes against the FastAPI app route table",
    )
    parser.add_argument(
        "--breaking",
        action="store_true",
        help="Compare --spec against --old-spec for breaking changes",
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        help="CI gate: verify plus breaking changes, non-zero exit on violations",
    )
    parser.add_argument(
        "--spec",
        type=str,
        default=None,
        help="OpenAPI spec path (YAML or JSON)",
    )
    parser.add_argument(
        "--old-spec",
        type=str,
        default=None,
        dest="old_spec",
        help="Previous OpenAPI spec path for breaking-change comparison",
    )


def build_subparser(subparsers: Any) -> Any:
    """Register the ``contract`` subcommand on a parent parser (e.g. c_uas.cli)."""
    parser = subparsers.add_parser(
        "contract",
        help=(
            "Contract readiness: verify OpenAPI contracts against the app "
            "route table, detect breaking changes, CI gate"
        ),
    )
    _add_contract_arguments(parser)
    return parser


def _format_contract_report(report: ContractReport) -> str:
    """Deterministic text rendering of a ContractReport."""
    lines: List[str] = []
    lines.append("[C-UAS] Contract verification")
    lines.append("  Spec        : " + report.spec_path)
    lines.append("  Spec routes : " + str(len(report.spec_routes)))
    lines.append("  App routes  : " + str(len(report.app_routes)))
    lines.append("  Missing     : " + str(len(report.missing)))
    lines.append("  Extra       : " + str(len(report.extra)))
    lines.append("  Mismatched  : " + str(len(report.mismatched)))
    for route in report.missing:
        lines.append("  missing     : " + route.method + " " + route.path)
    for route in report.extra:
        lines.append("  extra       : " + route.method + " " + route.path)
    for path, spec_methods, app_methods in report.mismatched:
        lines.append(
            "  mismatched  : "
            + path
            + " spec="
            + ",".join(spec_methods)
            + " app="
            + ",".join(app_methods)
        )
    lines.append("  Status      : " + ("OK" if report.ok else "VIOLATION"))
    return "\n".join(lines)


def _format_breaking_report(report: BreakingReport) -> str:
    """Deterministic text rendering of a BreakingReport."""
    lines: List[str] = []
    lines.append("[C-UAS] Breaking change detection")
    lines.append("  Old spec : " + report.old_spec_path)
    lines.append("  New spec : " + report.new_spec_path)
    lines.append("  Changes  : " + str(len(report.changes)))
    for change in report.changes:
        lines.append(
            "  - ["
            + change.kind
            + "] "
            + change.location
            + ": "
            + change.detail
            + " (old="
            + str(change.old_value)
            + ", new="
            + str(change.new_value)
            + ")"
        )
    lines.append("  Status      : " + ("CLEAN" if not report.breaking else "BREAKING"))
    return "\n".join(lines)


def contract_main(args: argparse.Namespace) -> int:
    """Dispatch the contract subcommand from a parsed namespace."""
    if args.gate:
        result = run_gate(spec_path=args.spec, old_spec_path=args.old_spec)
        print("[C-UAS] Contract gate")
        print("  Spec        : " + str(args.spec))
        print("  Old spec    : " + str(args.old_spec))
        print("  Exit code   : " + str(result.exit_code))
        print("  Reason      : " + result.reason)
        print("  State       : " + result.state_path)
        return result.exit_code

    if args.verify:
        if not args.spec:
            print("[C-UAS] contract --verify requires --spec PATH")
            return 1
        contract_report = verify_contract(args.spec, load_app_routes())
        print(_format_contract_report(contract_report))
        return 0 if contract_report.ok else 1

    if args.breaking:
        if not args.spec or not args.old_spec:
            print("[C-UAS] contract --breaking requires --spec PATH and --old-spec PATH")
            return 1
        breaking_report = detect_breaking_changes_from_files(args.old_spec, args.spec)
        print(_format_breaking_report(breaking_report))
        return 0 if not breaking_report.breaking else 1

    print("[C-UAS] contract: specify --verify, --breaking, or --gate")
    print("  c-uas contract --verify --spec openapi.yaml")
    print("  c-uas contract --breaking --spec openapi.yaml --old-spec openapi.prev.yaml")
    print("  c-uas contract --gate --spec openapi.yaml")
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Standalone entry point: parses argv and dispatches to contract_main(args)."""
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="c-uas contract",
        description="C-UAS contract readiness: verify, breaking-change detection, CI gate",
    )
    _add_contract_arguments(parser)
    args = parser.parse_args(argv)
    return contract_main(args)


if __name__ == "__main__":
    sys.exit(main())
