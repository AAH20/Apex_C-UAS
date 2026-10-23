"""
Persistent store for threat intelligence data.

All state lives under ~/.c-uas-platform/threat_intel/ (outside the repo)
so bundles, alerts, and channel configs survive repo rebuilds and are
verifiable across sessions. JSON-only persistence; every write is an
atomic replace of the whole file.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from .models import Alert, ChannelConfig

_DATA_DIR = Path.home() / ".c-uas-platform" / "threat_intel"
_BUNDLES_FILE = _DATA_DIR / "bundles.json"
_ALERTS_FILE = _DATA_DIR / "alerts.json"
_CHANNELS_FILE = _DATA_DIR / "channels.json"


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


class ThreatIntelStore:
    """CRUD over persisted bundles, alerts, and channel configs."""

    def __init__(self) -> None:
        _ensure_dir()

    # ---- bundles -----------------------------------------------------
    def save_bundle(self, bundle: Dict[str, Any]) -> None:
        bundles = self.list_bundles()
        bundle["_stored_at"] = time.time()
        bundles.append(bundle)
        _save_json(_BUNDLES_FILE, bundles)

    def list_bundles(self) -> List[Dict[str, Any]]:
        return _load_json(_BUNDLES_FILE)

    # ---- alerts ------------------------------------------------------
    def save_alert(self, alert: Alert) -> None:
        alerts = self.list_alerts()
        alerts.append(alert.to_dict())
        _save_json(_ALERTS_FILE, alerts)

    def list_alerts(self) -> List[Dict[str, Any]]:
        return _load_json(_ALERTS_FILE)

    # ---- channels ----------------------------------------------------
    def save_channels(self, channels: List[ChannelConfig]) -> None:
        _save_json(_CHANNELS_FILE, [c.to_dict() for c in channels])

    def load_channels(self) -> List[ChannelConfig]:
        channels: List[ChannelConfig] = []
        for raw in _load_json(_CHANNELS_FILE):
            channels.append(
                ChannelConfig(
                    kind=raw.get("kind", "console"),
                    enabled=bool(raw.get("enabled", True)),
                    webhook_url=raw.get("webhook_url"),
                    email_to=raw.get("email_to"),
                )
            )
        return channels
