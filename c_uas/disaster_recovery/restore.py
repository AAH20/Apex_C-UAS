"""Disaster recovery restore manager.

Restores a backup archive into a target directory, verifies every file's
SHA-256 checksum against the backup metadata, and reports restored / missing
/ failed files. All values are computed from real execution -- no mocks.
"""

from __future__ import annotations

import json
import os
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from .backup import (
    BACKUP_SUBDIR,
    FileEntry,
    _archive_name,
    _sha256_file,
    load_metadata,
)


@dataclass(frozen=True)
class RestoreFileReport:
    """Per-file restore result: status is restored | missing | failed."""

    module: str
    path: str
    status: str
    reason: Optional[str]
    expected_sha256: str
    actual_sha256: Optional[str]


@dataclass(frozen=True)
class RestoreReport:
    """Result of ``restore_backup``."""

    backup_id: str
    archive_path: str
    target_dir: str
    restored: Tuple[RestoreFileReport, ...]
    missing: Tuple[RestoreFileReport, ...]
    failed: Tuple[RestoreFileReport, ...]


def _is_safe_member_name(name: str) -> bool:
    """True if ``name`` is a relative, non-escaping archive member path."""
    parts = Path(name).parts
    return not name.startswith("/") and ".." not in parts and not any(part == "" for part in parts)


def _extract_archive(archive_path: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r") as tar:
        members = [member for member in tar.getmembers() if _is_safe_member_name(member.name)]
        tar.extractall(target_dir, members=members)


def _file_report(entry: FileEntry, target_dir: Path, extraction_failed: bool) -> RestoreFileReport:
    dest = target_dir / entry.module / entry.path
    if extraction_failed:
        return RestoreFileReport(
            module=entry.module,
            path=entry.path,
            status="failed",
            reason="archive extraction failed",
            expected_sha256=entry.sha256,
            actual_sha256=None,
        )
    if not dest.exists():
        return RestoreFileReport(
            module=entry.module,
            path=entry.path,
            status="missing",
            reason="not present in target directory after restore",
            expected_sha256=entry.sha256,
            actual_sha256=None,
        )
    actual = _sha256_file(dest)
    if actual != entry.sha256:
        return RestoreFileReport(
            module=entry.module,
            path=entry.path,
            status="failed",
            reason="checksum mismatch",
            expected_sha256=entry.sha256,
            actual_sha256=actual,
        )
    return RestoreFileReport(
        module=entry.module,
        path=entry.path,
        status="restored",
        reason=None,
        expected_sha256=entry.sha256,
        actual_sha256=actual,
    )


def restore_backup(
    backup_id: str,
    target_dir: str | os.PathLike[str],
    state_dir: str | os.PathLike[str] = None,  # type: ignore[assignment]
) -> RestoreReport:
    """Restore ``backup_id`` into ``target_dir`` with checksum verification.

    Returns a ``RestoreReport`` listing restored / missing / failed files.
    Raises ``FileNotFoundError`` when the backup archive is absent.
    """
    if state_dir is None:
        from .backup import DEFAULT_STATE_DIR

        state_dir = DEFAULT_STATE_DIR
    state_dir_path = Path(state_dir)
    backup_dir = state_dir_path / BACKUP_SUBDIR
    archive_path = backup_dir / _archive_name(backup_id)
    if not archive_path.exists():
        raise FileNotFoundError(f"backup archive not found: {archive_path}")
    metadata = load_metadata(backup_id, state_dir)
    if metadata is None:
        raise FileNotFoundError(f"backup metadata not found: {backup_id}")

    target = Path(target_dir)
    extraction_failed = False
    try:
        _extract_archive(archive_path, target)
    except Exception:  # archive corrupt/unreadable -> report every file failed
        extraction_failed = True

    restored: List[RestoreFileReport] = []
    missing: List[RestoreFileReport] = []
    failed: List[RestoreFileReport] = []
    for entry in metadata.files:
        report = _file_report(entry, target, extraction_failed)
        if report.status == "restored":
            restored.append(report)
        elif report.status == "missing":
            missing.append(report)
        else:
            failed.append(report)

    restored.sort(key=lambda item: (item.module, item.path))
    missing.sort(key=lambda item: (item.module, item.path))
    failed.sort(key=lambda item: (item.module, item.path))
    return RestoreReport(
        backup_id=backup_id,
        archive_path=str(archive_path),
        target_dir=str(target),
        restored=tuple(restored),
        missing=tuple(missing),
        failed=tuple(failed),
    )


def save_restore_report(report: RestoreReport, state_dir: str | os.PathLike[str]) -> Path:
    """Persist a restore report as JSON under ``<state_dir>/restores/``."""
    restores_dir = Path(state_dir) / "restores"
    restores_dir.mkdir(parents=True, exist_ok=True)
    payload = asdict(report)
    out_path = restores_dir / f"{report.backup_id}.restore.json"
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return out_path
