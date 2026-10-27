"""Deterministic Disaster Recovery / Backup tests.

Covers backup, restore checksum verification, and RPO/RTO thresholds.
All values are computed from real execution -- no mocks, no fabricated
metrics. Wall-clock time is frozen via pytest monkeypatch where
determinism requires it; state always lives in a tmp_path state dir
(never the real ~/.c-uas-platform).
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

import pytest

from c_uas.disaster_recovery import (
    DEFAULT_RPO_THRESHOLD_S,
    DEFAULT_RTO_THRESHOLD_S,
    compute_rpo,
    compute_rpo_rto,
    compute_rto,
    create_backup,
    format_rpo_rto,
    list_backups,
    load_metadata,
    restore_backup,
)
from c_uas.disaster_recovery import backup as backup_mod
from c_uas.disaster_recovery.backup import _save_metadata
from c_uas.disaster_recovery.cli import dr_main
from c_uas.disaster_recovery.rpo_rto import DEFAULT_RESTORE_THROUGHPUT_BPS

T1 = "2026-10-27T10:00:00Z"
T2 = "2026-10-27T11:00:00Z"
T_PLUS_25H = "2026-10-28T11:00:00Z"


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_state(state_dir: str, module_files: dict) -> None:
    """Write module files under the platform root (parent of state_dir)."""
    root = os.path.dirname(state_dir)
    for module, entries in module_files.items():
        for rel_path, content in entries.items():
            full = os.path.join(root, module, rel_path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            _write(full, content)


def _namespace(**overrides) -> argparse.Namespace:
    defaults = {
        "backup": False,
        "restore": False,
        "rpo_rto": False,
        "backup_id": None,
        "target": None,
        "state_dir": None,
        "rpo_threshold_s": DEFAULT_RPO_THRESHOLD_S,
        "rto_threshold_s": DEFAULT_RTO_THRESHOLD_S,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# backup
# ---------------------------------------------------------------------------


def test_backup_snapshots_all_module_state_dirs(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(
        state_dir,
        {
            "edge": {
                "SITE-01/config.json": '{"site": "SITE-01"}\n',
                "fleet/nodes.json": "{}\n",
            },
            "security": {"audits/latest.json": '{"ok": true}\n'},
        },
    )
    result = create_backup(state_dir=state_dir)
    assert result.total_files == 3
    assert result.modules == ("edge", "security")
    by_path = {(entry.module, entry.path): entry for entry in result.files}
    assert by_path[("edge", "SITE-01/config.json")].sha256 == _sha256_bytes(
        b'{"site": "SITE-01"}\n'
    )
    assert by_path[("edge", "SITE-01/config.json")].size == len(b'{"site": "SITE-01"}\n')
    archive = Path(result.archive_path)
    assert archive.exists()
    assert archive.stat().st_size > 0
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == result.archive_sha256


def test_backup_metadata_contains_timestamp_files_checksums(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    result = create_backup(state_dir=state_dir)
    meta = load_metadata(result.backup_id, state_dir=state_dir)
    assert meta is not None
    assert meta.backup_id == result.backup_id
    assert isinstance(meta.timestamp, str) and len(meta.timestamp) > 0
    assert meta.total_files == 1
    assert meta.total_size == result.total_size
    assert meta.archive_sha256 == result.archive_sha256
    assert len(meta.files) == 1
    assert meta.files[0].sha256 == _sha256_bytes(b"{}\n")


def test_backup_is_byte_deterministic_for_same_inputs(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    first = create_backup(state_dir=state_dir)
    second = create_backup(state_dir=state_dir)
    assert first.backup_id == second.backup_id
    assert first.archive_sha256 == second.archive_sha256
    assert Path(first.archive_path).read_bytes() == Path(second.archive_path).read_bytes()


def test_backup_excludes_disaster_recovery_directory(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    os.makedirs(state_dir, exist_ok=True)
    _write(os.path.join(state_dir, "must-not-be-backed-up.txt"), "secret")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    result = create_backup(state_dir=state_dir)
    assert all(entry.module != "disaster_recovery" for entry in result.files)
    assert not any("must-not-be-backed-up" in entry.path for entry in result.files)


def test_backup_skips_dot_and_noise_files(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(
        state_dir,
        {
            "edge": {
                "SITE-01/config.json": "{}\n",
                ".DS_Store": "junk",
                "__pycache__/module.pyc": "junk",
            }
        },
    )
    result = create_backup(state_dir=state_dir)
    paths = {(entry.module, entry.path) for entry in result.files}
    assert ("edge", "SITE-01/config.json") in paths
    assert not any(path.endswith(".DS_Store") for _, path in paths)
    assert not any("__pycache__" in path for _, path in paths)
    assert result.total_files == 1


def test_backup_empty_state_dir(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    result = create_backup(state_dir=state_dir)
    assert result.total_files == 0
    assert result.modules == ()
    assert result.files == ()
    assert Path(result.archive_path).exists()
    backup_id = result.backup_id
    again = create_backup(state_dir=state_dir)
    assert again.backup_id == backup_id


def test_backup_id_changes_when_content_changes(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    first = create_backup(state_dir=state_dir)
    _make_state(
        state_dir,
        {"edge": {"SITE-01/config.json": "{}\n", "extra.txt": "x"}},
    )
    second = create_backup(state_dir=state_dir)
    assert second.backup_id != first.backup_id
    assert second.total_files == 2


def test_backup_metadata_save_load_roundtrip(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    result = create_backup(state_dir=state_dir)
    meta = load_metadata(result.backup_id, state_dir=state_dir)
    assert meta == backup_mod.BackupMetadata(
        backup_id=meta.backup_id,
        timestamp=meta.timestamp,
        modules=meta.modules,
        files=meta.files,
        total_files=meta.total_files,
        total_size=meta.total_size,
        archive_path=meta.archive_path,
        archive_sha256=meta.archive_sha256,
    )
    assert load_metadata("does-not-exist", state_dir=state_dir) is None


def test_list_backups_newest_first(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"a.txt": "1"}})
    first = create_backup(state_dir=state_dir)
    _make_state(state_dir, {"edge": {"a.txt": "2", "b.txt": "3"}})
    second = create_backup(state_dir=state_dir)
    ordered = list_backups(state_dir=state_dir)
    assert [m.backup_id for m in ordered] == [second.backup_id, first.backup_id]
    assert ordered[0].timestamp >= ordered[1].timestamp


# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------


def test_restore_roundtrip_recovers_files(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": '{"x": 1}\n'}})
    result = create_backup(state_dir=state_dir)
    target = str(tmp_path / "restored")
    report = restore_backup(result.backup_id, target, state_dir=state_dir)
    assert len(report.restored) == 1
    assert report.missing == ()
    assert report.failed == ()
    restored_path = Path(target) / "edge" / "SITE-01/config.json"
    assert restored_path.read_text(encoding="utf-8") == '{"x": 1}\n'


def test_restore_creates_target_directories(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"deep/nested/note.txt": "note"}})
    result = create_backup(state_dir=state_dir)
    target = str(tmp_path / "fresh")
    report = restore_backup(result.backup_id, target, state_dir=state_dir)
    assert len(report.restored) == 1
    assert Path(target, "edge", "deep", "nested", "note.txt").read_text(encoding="utf-8") == "note"


def test_restore_checksum_mismatch_reported_as_failed(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    result = create_backup(state_dir=state_dir)
    meta = load_metadata(result.backup_id, state_dir=state_dir)

    def tampered(entry: backup_mod.FileEntry) -> backup_mod.FileEntry:
        if entry.path != "SITE-01/config.json":
            return entry
        return backup_mod.FileEntry(
            module=entry.module,
            path=entry.path,
            size=entry.size,
            sha256="0" * 64,
        )

    _save_metadata(
        backup_mod.BackupMetadata(
            backup_id=meta.backup_id,
            timestamp=meta.timestamp,
            modules=meta.modules,
            files=tuple(tampered(e) for e in meta.files),
            total_files=meta.total_files,
            total_size=meta.total_size,
            archive_path=meta.archive_path,
            archive_sha256=meta.archive_sha256,
        ),
        Path(state_dir) / "backups",
    )
    report = restore_backup(result.backup_id, str(tmp_path / "restored"), state_dir=state_dir)
    assert len(report.failed) == 1
    assert report.failed[0].status == "failed"
    assert report.failed[0].reason == "checksum mismatch"
    assert report.failed[0].expected_sha256 == "0" * 64
    assert report.failed[0].actual_sha256 == _sha256_bytes(b"{}\n")
    assert report.restored == ()
    assert report.missing == ()


def test_restore_missing_files_reported(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    result = create_backup(state_dir=state_dir)
    meta = load_metadata(result.backup_id, state_dir=state_dir)
    bogus = backup_mod.FileEntry(module="edge", path="does-not-exist.json", size=0, sha256="0" * 64)
    _save_metadata(
        backup_mod.BackupMetadata(
            backup_id=meta.backup_id,
            timestamp=meta.timestamp,
            modules=meta.modules,
            files=meta.files + (bogus,),
            total_files=meta.total_files + 1,
            total_size=meta.total_size,
            archive_path=meta.archive_path,
            archive_sha256=meta.archive_sha256,
        ),
        Path(state_dir) / "backups",
    )
    report = restore_backup(result.backup_id, str(tmp_path / "restored"), state_dir=state_dir)
    assert len(report.missing) == 1
    assert report.missing[0].status == "missing"
    assert report.missing[0].path == "does-not-exist.json"
    assert report.missing[0].actual_sha256 is None
    assert len(report.restored) == 1


def test_restore_unknown_backup_id_raises(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    with pytest.raises(FileNotFoundError):
        restore_backup("unknown-id", str(tmp_path / "restored"), state_dir=state_dir)


def test_restore_truncated_archive_reports_all_failed(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    result = create_backup(state_dir=state_dir)
    archive = Path(result.archive_path)
    archive.write_bytes(b"not a tar archive at all")  # unreadable -> extraction fails
    report = restore_backup(result.backup_id, str(tmp_path / "restored"), state_dir=state_dir)
    assert len(report.failed) == 1
    assert report.failed[0].status == "failed"
    assert report.failed[0].reason == "archive extraction failed"
    assert report.restored == ()
    assert report.missing == ()


# ---------------------------------------------------------------------------
# RPO / RTO
# ---------------------------------------------------------------------------


def test_rpo_computed_from_last_backup(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(backup_mod, "utc_now_iso", lambda: T1)
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    create_backup(state_dir=state_dir)
    statuses = compute_rpo(state_dir, now="2026-10-27T12:00:00Z")
    edge = next(s for s in statuses if s.module == "edge")
    assert edge.last_backup == T1
    assert edge.rpo_seconds == 7200.0
    assert edge.rpo_threshold_s == DEFAULT_RPO_THRESHOLD_S
    assert edge.rpo_violated is False


def test_rpo_violation_when_stale(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(backup_mod, "utc_now_iso", lambda: T1)
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    create_backup(state_dir=state_dir)
    statuses = compute_rpo(state_dir, now=T_PLUS_25H)
    edge = next(s for s in statuses if s.module == "edge")
    assert edge.rpo_seconds == 90000.0
    assert edge.rpo_violated is True


def test_rpo_never_backed_up_module_is_violated(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    statuses = compute_rpo(state_dir, now=T1)
    edge = next(s for s in statuses if s.module == "edge")
    assert edge.last_backup is None
    assert edge.rpo_seconds is None
    assert edge.rpo_violated is True


def test_rto_estimated_from_backup_size(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(backup_mod, "utc_now_iso", lambda: T1)
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    result = create_backup(state_dir=state_dir)
    statuses = compute_rto(state_dir)
    edge = next(s for s in statuses if s.module == "edge")
    assert edge.backup_size_bytes == result.total_size
    assert edge.rto_seconds == result.total_size / DEFAULT_RESTORE_THROUGHPUT_BPS
    assert edge.rto_violated is False  # tiny backup vs 1h threshold


def test_rto_violation_when_threshold_is_zero(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(backup_mod, "utc_now_iso", lambda: T1)
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    create_backup(state_dir=state_dir)
    statuses = compute_rto(state_dir, rto_threshold_s=0.0)
    edge = next(s for s in statuses if s.module == "edge")
    assert edge.rto_seconds > 0.0
    assert edge.rto_violated is True


def test_rpo_rto_report_flags_overall_violated(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(backup_mod, "utc_now_iso", lambda: T1)
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    create_backup(state_dir=state_dir)
    report = compute_rpo_rto(
        state_dir,
        now=T_PLUS_25H,
        rpo_threshold_s=DEFAULT_RPO_THRESHOLD_S,
        rto_threshold_s=DEFAULT_RTO_THRESHOLD_S,
    )
    assert report.rpo_threshold_s == DEFAULT_RPO_THRESHOLD_S
    assert report.rto_threshold_s == DEFAULT_RTO_THRESHOLD_S
    modules = {status.module: status for status in report.modules}
    assert "edge" in modules
    assert modules["edge"].rpo.rpo_violated is True  # 25h > 24h threshold
    assert report.overall_violated is True


def test_rpo_rto_report_no_modules_when_empty(tmp_path) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    report = compute_rpo_rto(state_dir, now=T1)
    assert report.modules == ()
    assert report.overall_violated is False


def test_format_rpo_rto_is_deterministic(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(backup_mod, "utc_now_iso", lambda: T1)
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    create_backup(state_dir=state_dir)
    report = compute_rpo_rto(state_dir, now=T2)
    out1 = format_rpo_rto(report)
    out2 = format_rpo_rto(report)
    assert out1 == out2
    assert "edge" in out1
    assert "rpo_violated    : False" in out1
    assert "rto_seconds     :" in out1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_backup_deterministic_output(tmp_path, capsys) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    args = _namespace(backup=True, state_dir=state_dir)
    dr_main(args)
    out1 = capsys.readouterr().out
    dr_main(args)
    out2 = capsys.readouterr().out
    # Same inputs -> same backup id and archive checksum (the timestamp line
    # may differ if a second boundary is crossed, so compare id/sha256 lines).
    id1 = [line for line in out1.splitlines() if line.startswith("  backup_id   :")][0]
    id2 = [line for line in out2.splitlines() if line.startswith("  backup_id   :")][0]
    sha1 = [line for line in out1.splitlines() if line.startswith("  archive_sha256:")][0]
    sha2 = [line for line in out2.splitlines() if line.startswith("  archive_sha256:")][0]
    assert id1 == id2
    assert sha1 == sha2
    assert "[C-UAS] Disaster Recovery Backup" in out1


def test_cli_restore_reports_restored_count(tmp_path, capsys) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    result = create_backup(state_dir=state_dir)
    target = str(tmp_path / "restored")
    args = _namespace(restore=True, backup_id=result.backup_id, target=target, state_dir=state_dir)
    rc = dr_main(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "restored    : 1" in out
    assert "missing     : 0" in out
    assert "failed      : 0" in out
    assert Path(target, "edge", "SITE-01/config.json").exists()


def test_cli_restore_missing_backup_id_fails(tmp_path, capsys) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    args = _namespace(restore=True, state_dir=state_dir)
    rc = dr_main(args)
    assert rc == 1
    assert "no backup found" in capsys.readouterr().out


def test_cli_no_action_prints_usage(tmp_path, capsys) -> None:
    state_dir = str(tmp_path / "disaster_recovery")
    args = _namespace(state_dir=state_dir)
    rc = dr_main(args)
    assert rc == 1
    assert "specify --backup, --restore, or --rpo-rto" in capsys.readouterr().out


def test_cli_rpo_rto_output(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.setattr(backup_mod, "utc_now_iso", lambda: T1)
    state_dir = str(tmp_path / "disaster_recovery")
    _make_state(state_dir, {"edge": {"SITE-01/config.json": "{}\n"}})
    create_backup(state_dir=state_dir)
    args = _namespace(rpo_rto=True, state_dir=state_dir)
    dr_main(args)
    out = capsys.readouterr().out
    assert "[C-UAS] Disaster Recovery RPO/RTO" in out
    assert "edge" in out
    assert f"RPO threshold          : {int(DEFAULT_RPO_THRESHOLD_S)}s" in out
    assert f"RTO threshold          : {int(DEFAULT_RTO_THRESHOLD_S)}s" in out
