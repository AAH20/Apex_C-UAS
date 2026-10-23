"""
Persistence for hardware abstraction layer state.

All state lives under ~/.c-uas-platform/hardware/ (outside the repo) so scan
results, fused tracks, and sensor status survive repo rebuilds. JSON-only
persistence; every write is an atomic replace of the whole file.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from .sensor_interface import Detection, Track

_DATA_DIR = Path.home() / ".c-uas-platform" / "hardware"
_DETECTIONS_FILE = _DATA_DIR / "detections.json"
_TRACKS_FILE = _DATA_DIR / "tracks.json"
_STATUS_FILE = _DATA_DIR / "status.json"


def _ensure_dir() -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load_json(path: Path) -> List[Dict[str, Any]]:
    _ensure_dir()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            return data
        return []
    except (json.JSONDecodeError, OSError):
        return []


def _save_json(path: Path, data: List[Dict[str, Any]]) -> None:
    _ensure_dir()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)


def save_detections(sensor_id: str, detections: List[Detection]) -> None:
    """Append one scan's detections to the persisted detection log."""

    _ensure_dir()
    records = _load_json(_DETECTIONS_FILE)
    records.append(
        {
            "sensor_id": sensor_id,
            "saved_at": time.time(),
            "count": len(detections),
            "detections": [asdict(d) for d in detections],
        }
    )
    _save_json(_DETECTIONS_FILE, records)


def load_detections(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Return persisted detection records (newest first)."""

    records = _load_json(_DETECTIONS_FILE)
    records.reverse()
    if limit is not None:
        records = records[:limit]
    return records


def save_tracks(tracks: List[Track]) -> None:
    """Persist the latest fused tracks (full replace)."""

    _ensure_dir()
    _save_json(_TRACKS_FILE, [asdict(t) for t in tracks])


def load_tracks() -> List[Dict[str, Any]]:
    """Return the latest persisted fused tracks."""

    return _load_json(_TRACKS_FILE)


def save_status(sensor_id: str, online: bool, simulation_mode: bool, message: str) -> None:
    """Persist the latest health-check status per sensor."""

    _ensure_dir()
    records = _load_json(_STATUS_FILE)
    records = [r for r in records if r.get("sensor_id") != sensor_id]
    records.append(
        {
            "sensor_id": sensor_id,
            "checked_at": time.time(),
            "online": online,
            "simulation_mode": simulation_mode,
            "message": message,
        }
    )
    _save_json(_STATUS_FILE, records)


def load_status() -> List[Dict[str, Any]]:
    """Return persisted sensor status records."""

    return _load_json(_STATUS_FILE)
