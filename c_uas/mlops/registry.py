"""Model registry: versioned model records with promote/demote lifecycle.

State persists under ``<state_dir>/registry/`` (default:
``~/.c-uas-platform/mlops/registry/``). Everything is a frozen dataclass plus
pure functions; the registry file is rewritten atomically (tmp file +
``os.replace``) so concurrent runs cannot tear it. Identical registration
calls are idempotent: re-registering the same ``(name, version)`` returns the
existing record untouched.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "mlops")
REGISTRY_SUBDIR = "registry"
REGISTRY_FILENAME = "registry.json"

STAGES = ("staging", "production", "archived")


@dataclass(frozen=True)
class ModelRecord:
    """One registered model version: immutable identity plus provenance."""

    name: str
    version: str
    stage: str
    artifact_path: str
    metrics_hash: str
    created_at: str
    updated_at: str


def utc_now_iso() -> str:
    """Current wall-clock UTC time as ISO-8601 (real time, not frozen)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _state_dir(state_dir: Optional[str] = None) -> str:
    if state_dir is not None:
        return state_dir
    return os.environ.get("CUAS_MLOPS_STATE_DIR", DEFAULT_STATE_DIR)


def _registry_path(state_dir: str) -> Path:
    return Path(state_dir) / REGISTRY_SUBDIR / REGISTRY_FILENAME


def _atomic_write_json(path: Path, payload: Any) -> None:
    """Write JSON atomically: temp file in same dir, then os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp_path, path)


def _load_registry(state_dir: str) -> Dict[str, Any]:
    path = _registry_path(state_dir)
    if not path.exists():
        return {"models": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {"models": []}
    if not isinstance(data, dict) or "models" not in data:
        return {"models": []}
    return data


def _save_registry(state_dir: str, registry: Dict[str, Any]) -> None:
    _atomic_write_json(_registry_path(state_dir), registry)


def _record_to_dict(record: ModelRecord) -> Dict[str, Any]:
    return asdict(record)


def _dict_to_record(data: Dict[str, Any]) -> ModelRecord:
    return ModelRecord(
        name=str(data["name"]),
        version=str(data["version"]),
        stage=str(data["stage"]),
        artifact_path=str(data["artifact_path"]),
        metrics_hash=str(data["metrics_hash"]),
        created_at=str(data["created_at"]),
        updated_at=str(data["updated_at"]),
    )


def register_model(
    name: str,
    version: str,
    artifact_path: str,
    metrics_hash: str,
    stage: str = "staging",
    state_dir: Optional[str] = None,
) -> ModelRecord:
    """Register ``(name, version)``; idempotent -- existing record is
    returned unchanged. New records start in ``staging`` by default."""
    sdir = _state_dir(state_dir)
    if not name or not version or not artifact_path or not metrics_hash:
        raise ValueError("name, version, artifact_path, and metrics_hash are required")
    if stage not in STAGES:
        raise ValueError(f"unknown stage: {stage!r} (expected one of {STAGES})")

    registry = _load_registry(sdir)
    for entry in registry.get("models", []):
        if entry.get("name") == name and entry.get("version") == version:
            return _dict_to_record(entry)

    now = utc_now_iso()
    record = ModelRecord(
        name=name,
        version=version,
        stage=stage,
        artifact_path=artifact_path,
        metrics_hash=metrics_hash,
        created_at=now,
        updated_at=now,
    )
    registry.setdefault("models", []).append(_record_to_dict(record))
    _save_registry(sdir, registry)
    return record


def list_models(
    state_dir: Optional[str] = None,
    name: Optional[str] = None,
    stage: Optional[str] = None,
) -> Tuple[ModelRecord, ...]:
    """All registered models, sorted by ``(name, version)``. Optional filters."""
    sdir = _state_dir(state_dir)
    if stage is not None and stage not in STAGES:
        raise ValueError(f"unknown stage: {stage!r} (expected one of {STAGES})")
    registry = _load_registry(sdir)
    records = [_dict_to_record(entry) for entry in registry.get("models", [])]
    if name is not None:
        records = [r for r in records if r.name == name]
    if stage is not None:
        records = [r for r in records if r.stage == stage]
    records.sort(key=lambda r: (r.name, r.version))
    return tuple(records)


def get_model(name: str, version: str, state_dir: Optional[str] = None) -> Optional[ModelRecord]:
    """Return the record for ``(name, version)``, or None if unregistered."""
    for record in list_models(state_dir):
        if record.name == name and record.version == version:
            return record
    return None


def set_stage(
    name: str,
    version: str,
    stage: str,
    state_dir: Optional[str] = None,
) -> ModelRecord:
    """Move ``(name, version)`` to ``stage``; KeyError if unregistered."""
    if stage not in STAGES:
        raise ValueError(f"unknown stage: {stage!r} (expected one of {STAGES})")
    sdir = _state_dir(state_dir)
    registry = _load_registry(sdir)
    updated: Optional[ModelRecord] = None
    for entry in registry.get("models", []):
        if entry.get("name") == name and entry.get("version") == version:
            entry["stage"] = stage
            entry["updated_at"] = utc_now_iso()
            updated = _dict_to_record(entry)
            break
    if updated is None:
        raise KeyError(f"model not registered: {name}@{version}")
    _save_registry(sdir, registry)
    return updated


def promote_model(name: str, version: str, state_dir: Optional[str] = None) -> ModelRecord:
    """Promote ``(name, version)`` to ``production``."""
    return set_stage(name, version, "production", state_dir=_state_dir(state_dir))


def demote_model(
    name: str,
    version: str,
    stage: str = "staging",
    state_dir: Optional[str] = None,
) -> ModelRecord:
    """Demote ``(name, version)`` to ``staging`` (default) or ``archived``."""
    if stage not in ("staging", "archived"):
        raise ValueError("demote target must be 'staging' or 'archived'")
    return set_stage(name, version, stage, state_dir=_state_dir(state_dir))


def archive_model(name: str, version: str, state_dir: Optional[str] = None) -> ModelRecord:
    """Archive ``(name, version)`` (stage = archived)."""
    return set_stage(name, version, "archived", state_dir=_state_dir(state_dir))


def remove_model(name: str, version: str, state_dir: Optional[str] = None) -> bool:
    """Drop ``(name, version)`` from the registry. True if removed."""
    sdir = _state_dir(state_dir)
    registry = _load_registry(sdir)
    models = registry.get("models", [])
    kept = [
        entry
        for entry in models
        if not (entry.get("name") == name and entry.get("version") == version)
    ]
    if len(kept) == len(models):
        return False
    registry["models"] = kept
    _save_registry(sdir, registry)
    return True
