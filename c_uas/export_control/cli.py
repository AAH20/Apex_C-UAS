"""``c-uas export-control`` subcommand: Export Control Compliance Scanner.

Usage:
    c-uas export-control --scan PATH
    c-uas export-control --audit
    c-uas export-control --gate PATH

Scans a directory tree for weapons-employment framing that may trigger
ITAR §120.41 'specially designed' exposure via repository description.
All output is deterministic. State persists under
~/.c-uas-platform/export_control/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional

from .audit import diff_audits, load_prior, save_audit
from .ci_gate import run_gate
from .scanner import save_scan, scan_directory


def build_subparser(subparsers: Any) -> Any:
    """Register the ``export-control`` subcommand on a parent parser."""
    parser = subparsers.add_parser(
        "export-control",
        help="Export control compliance scanner (§120.41 'specially designed' exposure)",
    )
    parser.add_argument(
        "--scan",
        type=str,
        default=None,
        help="Scan a directory tree for weapons-employment framing",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Diff the latest scan against the prior audit",
    )
    parser.add_argument(
        "--gate",
        type=str,
        default=None,
        help="Run the CI gate on a directory (non-zero exit on HIGH/CRITICAL)",
    )
    return parser


def handle_scan(path: str) -> str:
    report = scan_directory(path)
    save_scan(report)
    lines = [
        "[C-UAS] export-control scan",
        f"  root            : {report.root}",
        f"  files scanned   : {report.files_scanned}",
        f"  critical        : {report.critical_count}",
        f"  high            : {report.high_count}",
        f"  medium          : {report.medium_count}",
        f"  low             : {report.low_count}",
        f"  info            : {report.info_count}",
    ]
    if report.findings:
        lines.append("  findings:")
        for f in report.findings[:20]:
            lines.append(f"    {f.file}:{f.line} [{f.severity}] {f.term} — {f.context[:80]}")
        if len(report.findings) > 20:
            lines.append(f"    ... ({len(report.findings) - 20} more)")
    return "\n".join(lines)


def handle_audit() -> str:
    from .scanner import load_latest_scan

    current = load_latest_scan()
    if current is None:
        return "[C-UAS] export-control audit: no prior scan found; run --scan first"
    prior = load_prior()
    trail = diff_audits(prior, current)
    save_audit(trail)
    lines = [
        "[C-UAS] export-control audit",
        f"  generated at    : {trail.generated_at}",
        f"  new findings    : {trail.new_count}",
        f"  removed findings: {trail.removed_count}",
        f"  current critical: {trail.current_critical}",
        f"  current high    : {trail.current_high}",
    ]
    if trail.new_findings:
        lines.append("  new:")
        for f in trail.new_findings:
            lines.append(f"    {f.file}:{f.line} [{f.severity}] {f.term}")
    if trail.removed_findings:
        lines.append("  removed:")
        for f in trail.removed_findings:
            lines.append(f"    {f.file}:{f.line} [{f.severity}] {f.term}")
    return "\n".join(lines)


def handle_gate(path: str) -> int:
    return run_gate(path)


def export_control_main(args: argparse.Namespace) -> int:
    if args.scan:
        print(handle_scan(args.scan))
        return 0
    if args.audit:
        print(handle_audit())
        return 0
    if args.gate:
        return handle_gate(args.gate)
    print("[C-UAS] export-control: specify --scan, --audit, or --gate")
    print("  c-uas export-control --scan .")
    print("  c-uas export-control --audit")
    print("  c-uas export-control --gate .")
    return 1


def main(argv: Optional[list] = None) -> int:
    if argv is None:
        import sys

        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="c-uas export-control",
        description="Export control compliance scanner for the C-UAS platform",
    )
    build_subparser(parser.add_subparsers(dest="command"))
    args = parser.parse_args(argv)
    return export_control_main(args)


if __name__ == "__main__":
    sys.exit(main())
