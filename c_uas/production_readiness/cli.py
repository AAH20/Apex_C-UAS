"""``c-uas readiness`` CLI: production readiness review go/no-go.

Usage:
    c-uas readiness --check
    c-uas readiness --report

``--check`` runs all domain checks, aggregates the weighted readiness score,
decides go/no-go, prints the report, and always persists state under
~/.c-uas-platform/production_readiness/ (outside the repo). Exits 0 on GO,
1 on NO-GO so it can double as a CI release gate.

Output is deterministic: identical inputs produce identical output.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional

from .aggregator import GO, ReadinessReport, run_readiness_check
from .report import DEFAULT_STATE_DIR, load_latest_report, render_text, save_report


def build_subparser(subparsers: Any) -> Any:
    """Register the ``readiness`` subcommand on a parent parser."""
    parser = subparsers.add_parser(
        "readiness",
        help="Production readiness review: aggregate all domain checks into "
        "a release go/no-go decision",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run all readiness checks and publish a go/no-go report (exits 0 on GO, 1 on NO-GO)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Show the latest persisted readiness report",
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default=DEFAULT_STATE_DIR,
        help=(
            "State directory for persisted reports "
            "(default: ~/.c-uas-platform/production_readiness/)"
        ),
    )
    return parser


def readiness_main(args: argparse.Namespace) -> int:
    if not any([getattr(args, "check", False), getattr(args, "report", False)]):
        print("[C-UAS] readiness: specify --check or --report")
        print("  c-uas readiness --check")
        print("  c-uas readiness --report")
        return 1

    state_dir = getattr(args, "state_dir", DEFAULT_STATE_DIR)

    if getattr(args, "check", False):
        check_report = run_readiness_check()
        save_report(check_report, state_dir=state_dir)
        print(render_text(check_report))
        return 0 if check_report.go_no_go == GO else 1

    report: Optional[ReadinessReport] = load_latest_report(state_dir=state_dir)
    if report is None:
        print("[C-UAS] readiness: no persisted report found; run `c-uas readiness --check` first")
        return 1
    print(render_text(report))
    return 0


def main(argv: Optional[list] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="c-uas readiness",
        description="Production readiness review go/no-go decision",
    )
    build_subparser(parser.add_subparsers(dest="command"))
    args = parser.parse_args(argv)
    return readiness_main(args)


if __name__ == "__main__":
    sys.exit(main())
