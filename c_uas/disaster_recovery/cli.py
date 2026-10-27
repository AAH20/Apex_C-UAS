"""``c-uas dr`` subcommand: Disaster Recovery / Backup.

    c-uas dr --backup
    c-uas dr --restore --backup-id <id> [--target <dir>]
    c-uas dr --rpo-rto [--rpo-threshold-s <s>] [--rto-threshold-s <s>]

Snapshots all module state dirs under ``~/.c-uas-platform/*/`` into a
deterministic archive, restores from a backup archive with checksum
verification, and tracks RPO/RTO per module with threshold flags.
State persists under ``~/.c-uas-platform/disaster_recovery/`` (outside the
repo). All output is deterministic: identical inputs produce identical
output (the only wall-clock value is the backup timestamp itself).
"""

from __future__ import annotations

import argparse
import os
from typing import Any, Optional, Sequence

from .backup import (
    DEFAULT_STATE_DIR,
    BackupResult,
    create_backup,
    list_backups,
)
from .restore import restore_backup
from .rpo_rto import (
    DEFAULT_RPO_THRESHOLD_S,
    DEFAULT_RTO_THRESHOLD_S,
    compute_rpo_rto,
    format_rpo_rto,
)


def build_subparser(subparsers: Any) -> Any:
    """Register the ``dr`` subcommand on a parent parser (e.g. c_uas.cli)."""
    parser = subparsers.add_parser(
        "dr",
        help=(
            "Disaster Recovery / Backup: snapshot all module state dirs, "
            "restore from a backup archive, and track RPO/RTO per module"
        ),
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Snapshot all module state dirs into a deterministic archive",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Restore from a backup archive (requires --backup-id)",
    )
    parser.add_argument(
        "--rpo-rto",
        action="store_true",
        help="Show RPO/RTO status per module with threshold violation flags",
    )
    parser.add_argument(
        "--backup-id",
        type=str,
        default=None,
        help="Backup id to restore (default: latest backup)",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=None,
        help="Restore target directory (default: platform state root, "
        "i.e. the parent of the disaster recovery state dir)",
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default=None,
        help="Disaster recovery state dir (default: ~/.c-uas-platform/disaster_recovery/)",
    )
    parser.add_argument(
        "--rpo-threshold-s",
        type=float,
        default=DEFAULT_RPO_THRESHOLD_S,
        help="RPO violation threshold in seconds (default: %.0f = 24h)" % DEFAULT_RPO_THRESHOLD_S,
    )
    parser.add_argument(
        "--rto-threshold-s",
        type=float,
        default=DEFAULT_RTO_THRESHOLD_S,
        help="RTO violation threshold in seconds (default: %.0f = 1h)" % DEFAULT_RTO_THRESHOLD_S,
    )
    return parser


def _render_backup(result: BackupResult) -> str:
    lines: list[str] = [
        "[C-UAS] Disaster Recovery Backup",
        f"  backup_id   : {result.backup_id}",
        f"  timestamp   : {result.timestamp}",
        f"  archive     : {result.archive_path}",
        f"  archive_sha256: {result.archive_sha256}",
        f"  modules     : {len(result.modules)}"
        + (f" ({', '.join(result.modules)})" if result.modules else " (none)"),
        f"  files       : {result.total_files}",
        f"  total_size  : {result.total_size} bytes",
        "  files:",
    ]
    if not result.files:
        lines.append("    (no files)")
    for entry in result.files:
        lines.append(f"    {entry.module}/{entry.path}  {entry.size} B  {entry.sha256}")
    return "\n".join(lines)


def _latest_backup_id(state_dir: str) -> Optional[str]:
    backups = list_backups(state_dir)
    return backups[0].backup_id if backups else None


def handle_backup(state_dir: str) -> str:
    result = create_backup(state_dir=state_dir)
    return _render_backup(result)


def _render_restore(report) -> str:
    lines: list[str] = [
        "[C-UAS] Disaster Recovery Restore",
        f"  backup_id   : {report.backup_id}",
        f"  archive     : {report.archive_path}",
        f"  target_dir  : {report.target_dir}",
        f"  restored    : {len(report.restored)}",
        f"  missing     : {len(report.missing)}",
        f"  failed      : {len(report.failed)}",
    ]
    for item in report.restored:
        lines.append(f"    [restored]  {item.module}/{item.path} ({item.expected_sha256[:12]}...)")
    for item in report.missing:
        lines.append(f"    [missing]   {item.module}/{item.path} -- {item.reason}")
    for item in report.failed:
        lines.append(f"    [failed]    {item.module}/{item.path} -- {item.reason}")
    if not report.restored and not report.missing and not report.failed:
        lines.append("    (no files in backup)")
    return "\n".join(lines)


def handle_restore(args: argparse.Namespace, state_dir: str) -> int:
    backup_id = args.backup_id or _latest_backup_id(state_dir)
    if backup_id is None:
        print("[C-UAS] dr --restore: no backup found; run --backup first")
        print("  c-uas dr --backup")
        return 1
    target = args.target or os.path.dirname(state_dir)  # platform state root
    report = restore_backup(backup_id, target, state_dir)
    print(_render_restore(report))
    if report.failed or report.missing:
        return 1
    return 0


def handle_rpo_rto(args: argparse.Namespace, state_dir: str) -> str:
    report = compute_rpo_rto(
        state_dir,
        rpo_threshold_s=args.rpo_threshold_s,
        rto_threshold_s=args.rto_threshold_s,
    )
    return format_rpo_rto(report)


def dr_main(args: argparse.Namespace) -> int:
    state_dir = args.state_dir or DEFAULT_STATE_DIR
    if args.backup:
        print(handle_backup(state_dir))
        return 0
    if args.restore:
        return handle_restore(args, state_dir)
    if args.rpo_rto:
        print(handle_rpo_rto(args, state_dir))
        return 0
    print("[C-UAS] dr: specify --backup, --restore, or --rpo-rto")
    print("  c-uas dr --backup")
    print("  c-uas dr --restore --backup-id <id>")
    print("  c-uas dr --rpo-rto")
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Standalone entry point: ``python -m c_uas.disaster_recovery.cli``."""
    parser = argparse.ArgumentParser(
        prog="c-uas dr",
        description="Disaster Recovery / Backup for the C-UAS platform",
    )
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 1
    return dr_main(args)


if __name__ == "__main__":
    import sys

    sys.exit(main())
