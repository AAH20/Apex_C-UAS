"""
Persistent state for edge nodes.

All edge node state lives outside the repo under
~/.c-uas-platform/edge/<node_id>/ so a node keeps its configuration, queued
detections, tracks, and health history across sessions and upgrades.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

EDGE_ROOT = Path(os.environ.get("C_UAS_EDGE_STATE_DIR", Path.home() / ".c-uas-platform" / "edge"))


def node_dir(node_id: str) -> Path:
    """Return (and create) the state directory for one edge node."""
    d = EDGE_ROOT / node_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _atomic_write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    os.replace(tmp, path)


def save_json(node_id: str, name: str, data: Any) -> Path:
    """Persist JSON state for a node, atomically."""
    path = node_dir(node_id) / "{}.json".format(name)
    _atomic_write_json(path, data)
    return path


def load_json(node_id: str, name: str, default: Any = None) -> Any:
    """Load JSON state for a node, or default when nothing is stored yet."""
    path = node_dir(node_id) / "{}.json".format(name)
    if not path.exists():
        return default
    with path.open() as fh:
        return json.load(fh)
