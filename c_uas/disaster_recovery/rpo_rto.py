"""Disaster recovery RPO/RTO tracker.

Tracks the last backup time per module, computes:

* RPO -- time since the last backup per module (real wall-clock delta).
* RTO -- estimated restore time per module, derived from the persisted
  backup size divided by an assumed restore throughput.

Flags violations of configurable thresholds. All state is read from the
disaster recovery registry persisted under the state dir; all values are
real computed values -- no mocks, no fabricated metrics.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .backup import (
    _load_registry,
    list_modules,
    utc_now_iso,
)

DEFAULT_RPO_THRESHOLD_S = 86400.0  # 24 hours
DEFAULT_RTO_THRESHOLD_S = 3600.0  # 1 hour
DEFAULT_RESTORE_THROUGHPUT_BPS = 50.0 * 1024.0 * 1024.0  # 50 MB/s estimate


@dataclass(frozen=True)
class RPOStatus:
    module: str
    last_backup: Optional[str]
    rpo_seconds: Optional[float]
    rpo_threshold_s: float
    rpo_violated: bool


@dataclass(frozen=True)
class RTOStatus:
    module: str
    backup_size_bytes: int
    rto_seconds: float
    rto_threshold_s: float
    rto_violated: bool


@dataclass(frozen=True)
class ModuleRecoveryStatus:
    module: str
    rpo: RPOStatus
    rto: RTOStatus


@dataclass(frozen=True)
class RPORTORepport:
    generated_at: str
    rpo_threshold_s: float
    rto_threshold_s: float
    restore_throughput_bps: float
    modules: Tuple[ModuleRecoveryStatus, ...]
    overall_violated: bool


def last_backup_info(state_dir: str | os.PathLike[str]) -> Dict[str, Dict]:
    """Last-backup record per module from the persisted registry."""
    registry = _load_registry(state_dir)
    return registry.get("last_backup_per_module", {})


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def compute_rpo(
    state_dir: str | os.PathLike[str],
    now: str | None = None,
    rpo_threshold_s: float = DEFAULT_RPO_THRESHOLD_S,
) -> Tuple[RPOStatus, ...]:
    """RPO per module: wall-clock time since its last backup.

    Covers every module on disk: modules with no recorded backup have
    ``rpo_seconds = None`` and are flagged as violated.
    ``now`` is injectable for deterministic tests; defaults to real time.
    """
    now_dt = _parse_iso(now) if now is not None else datetime.now(timezone.utc)
    info = last_backup_info(state_dir)
    modules = sorted(set(list_modules(state_dir)) | set(info.keys()))
    statuses: List[RPOStatus] = []
    for module in modules:
        record = info.get(module) or {}
        last_backup = record.get("timestamp")
        if last_backup is None:
            statuses.append(
                RPOStatus(
                    module=module,
                    last_backup=None,
                    rpo_seconds=None,
                    rpo_threshold_s=rpo_threshold_s,
                    rpo_violated=True,
                )
            )
            continue
        rpo_seconds = (now_dt - _parse_iso(last_backup)).total_seconds()
        statuses.append(
            RPOStatus(
                module=module,
                last_backup=last_backup,
                rpo_seconds=rpo_seconds,
                rpo_threshold_s=rpo_threshold_s,
                rpo_violated=rpo_seconds > rpo_threshold_s,
            )
        )
    return tuple(statuses)


def compute_rto(
    state_dir: str | os.PathLike[str],
    rto_threshold_s: float = DEFAULT_RTO_THRESHOLD_S,
    restore_throughput_bps: float = DEFAULT_RESTORE_THROUGHPUT_BPS,
) -> Tuple[RTOStatus, ...]:
    """RTO per module: estimated restore time = backup size / throughput."""
    info = last_backup_info(state_dir)
    statuses: List[RTOStatus] = []
    for module in sorted(info):
        record = info[module]
        backup_size_bytes = int(record.get("archive_size", 0))
        rto_seconds = backup_size_bytes / restore_throughput_bps
        statuses.append(
            RTOStatus(
                module=module,
                backup_size_bytes=backup_size_bytes,
                rto_seconds=rto_seconds,
                rto_threshold_s=rto_threshold_s,
                rto_violated=rto_seconds > rto_threshold_s,
            )
        )
    return tuple(statuses)


def compute_rpo_rto(
    state_dir: str | os.PathLike[str] = None,  # type: ignore[assignment]
    now: str | None = None,
    rpo_threshold_s: float = DEFAULT_RPO_THRESHOLD_S,
    rto_threshold_s: float = DEFAULT_RTO_THRESHOLD_S,
    restore_throughput_bps: float = DEFAULT_RESTORE_THROUGHPUT_BPS,
) -> RPORTORepport:
    """Combined RPO/RTO report with per-module threshold flags."""
    from .backup import DEFAULT_STATE_DIR

    if state_dir is None:
        state_dir = DEFAULT_STATE_DIR
    rpo_statuses = compute_rpo(state_dir, now=now, rpo_threshold_s=rpo_threshold_s)
    rto_statuses = compute_rto(
        state_dir,
        rto_threshold_s=rto_threshold_s,
        restore_throughput_bps=restore_throughput_bps,
    )
    rto_by_module = {status.module: status for status in rto_statuses}
    all_modules = sorted(set(list_modules(state_dir)) | set(rto_by_module.keys()))
    modules: List[ModuleRecoveryStatus] = []
    for module in all_modules:
        rpo = next((s for s in rpo_statuses if s.module == module), None)
        if rpo is None:
            rpo = RPOStatus(
                module=module,
                last_backup=None,
                rpo_seconds=None,
                rpo_threshold_s=rpo_threshold_s,
                rpo_violated=True,
            )
        rto = rto_by_module.get(
            module,
            RTOStatus(
                module=module,
                backup_size_bytes=0,
                rto_seconds=0.0,
                rto_threshold_s=rto_threshold_s,
                rto_violated=False,
            ),
        )
        modules.append(ModuleRecoveryStatus(module=module, rpo=rpo, rto=rto))
    overall_violated = any(status.rpo.rpo_violated or status.rto.rto_violated for status in modules)
    return RPORTORepport(
        generated_at=utc_now_iso(),
        rpo_threshold_s=rpo_threshold_s,
        rto_threshold_s=rto_threshold_s,
        restore_throughput_bps=restore_throughput_bps,
        modules=tuple(modules),
        overall_violated=overall_violated,
    )


def format_rpo_rto(report: RPORTORepport) -> str:
    """Deterministic, human-readable rendering of an RPORTORepport."""
    lines: List[str] = [
        "[C-UAS] Disaster Recovery RPO/RTO",
        f"  generated at           : {report.generated_at}",
        f"  RPO threshold          : {report.rpo_threshold_s:.0f}s",
        f"  RTO threshold          : {report.rto_threshold_s:.0f}s",
        f"  restore throughput     : {report.restore_throughput_bps / (1024 * 1024):.0f} MB/s",
        f"  overall violated       : {report.overall_violated}",
        "  modules:",
    ]
    if not report.modules:
        lines.append("    (no modules with backups recorded)")
    for status in report.modules:
        rpo = status.rpo
        rto = status.rto
        lines.append(f"    {status.module}:")
        lines.append(f"      last_backup     : {rpo.last_backup or '(none)'}")
        lines.append(
            f"      rpo_seconds     : {rpo.rpo_seconds if rpo.rpo_seconds is not None else 'n/a'}"
        )
        lines.append(f"      rpo_violated    : {rpo.rpo_violated}")
        lines.append(f"      backup_size     : {rto.backup_size_bytes} bytes")
        lines.append(f"      rto_seconds     : {rto.rto_seconds:.6f}")
        lines.append(f"      rto_violated    : {rto.rto_violated}")
    return "\n".join(lines)


def save_rpo_rto_report(report: RPORTORepport, state_dir: str | os.PathLike[str]) -> Path:
    """Persist the RPO/RTO report as JSON under ``<state_dir>/``."""
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    out_path = Path(state_dir) / "rpo_rto_latest.json"
    out_path.write_text(json.dumps(asdict(report), indent=2, sort_keys=True), encoding="utf-8")
    return out_path
