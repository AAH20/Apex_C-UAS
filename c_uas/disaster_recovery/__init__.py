"""Disaster Recovery / Backup module for the C-UAS platform.

Deterministic backup, restore, and recovery-point-objective (RPO) /
recovery-time-objective (RTO) tracking for all platform state directories
under ``~/.c-uas-platform/*/``. State persists under
``~/.c-uas-platform/disaster_recovery/`` (outside the repo).

Nothing here mutates the scanned state trees -- backups are read-only
snapshots, and restores write only to the caller-chosen target directory.
"""

from __future__ import annotations

from .backup import (
    DEFAULT_STATE_DIR,
    BackupMetadata,
    BackupResult,
    FileEntry,
    create_backup,
    list_backups,
    load_metadata,
    snapshot_files,
)
from .cli import build_subparser, dr_main
from .restore import RestoreFileReport, RestoreReport, restore_backup
from .rpo_rto import (
    DEFAULT_RESTORE_THROUGHPUT_BPS,
    DEFAULT_RPO_THRESHOLD_S,
    DEFAULT_RTO_THRESHOLD_S,
    RPORTORepport,
    RPOStatus,
    RTOStatus,
    compute_rpo,
    compute_rpo_rto,
    compute_rto,
    format_rpo_rto,
)

__all__ = [
    "DEFAULT_STATE_DIR",
    "DEFAULT_RPO_THRESHOLD_S",
    "DEFAULT_RTO_THRESHOLD_S",
    "DEFAULT_RESTORE_THROUGHPUT_BPS",
    "BackupMetadata",
    "BackupResult",
    "FileEntry",
    "RestoreFileReport",
    "RestoreReport",
    "RPOStatus",
    "RTOStatus",
    "RPORTORepport",
    "build_subparser",
    "compute_rpo",
    "compute_rpo_rto",
    "compute_rto",
    "create_backup",
    "dr_main",
    "format_rpo_rto",
    "list_backups",
    "load_metadata",
    "restore_backup",
    "snapshot_files",
]
