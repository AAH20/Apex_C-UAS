"""
Hash-linked evidence chain for GRC_Clab agentic governance.

Implements a tamper-evident, hash-linked evidence log per ISO 42001 Clause 9:

- genesis hash "0" * 64 seeds the chain
- each entry links prev_hash -> entry_hash = sha256(prev_hash + canonical(payload))
- verify_chain() re-walks the chain, recomputing every hash
- persistence under ~/.c-uas-platform/grc_clab/evidence/

Conventions: frozen dataclasses, pure hash function, deterministic, real computed values.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

GENESIS_HASH = "0" * 64

_CHAIN_DIR = Path.home() / ".c-uas-platform" / "grc_clab" / "evidence"
_CHAIN_FILE = _CHAIN_DIR / "chain.json"


@dataclass(frozen=True)
class EvidenceEntry:
    """An immutable, hash-linked evidence entry."""

    entry_id: str
    timestamp: float
    event_type: str
    system_id: Optional[str]
    payload: Dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_entry_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
    """Pure function: entry_hash = sha256(prev_hash + canonical(payload))."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    material = prev_hash + canonical
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _ensure_dir() -> None:
    _CHAIN_DIR.mkdir(parents=True, exist_ok=True)


def _load_entries() -> List[EvidenceEntry]:
    _ensure_dir()
    if not _CHAIN_FILE.exists():
        return []
    try:
        rows = json.loads(_CHAIN_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    return [EvidenceEntry(**row) for row in rows]


def _save_entries(entries: List[EvidenceEntry]) -> None:
    _ensure_dir()
    _CHAIN_FILE.write_text(json.dumps([e.to_dict() for e in entries], indent=2))


class EvidenceChain:
    """Tamper-evident, hash-linked evidence chain."""

    def __init__(self) -> None:
        self._entries: List[EvidenceEntry] = _load_entries()

    def log(
        self,
        event_type: str,
        payload: Dict[str, Any],
        system_id: Optional[str] = None,
    ) -> EvidenceEntry:
        """Append a new evidence entry, hash-linked to its predecessor."""
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        entry_hash = compute_entry_hash(prev_hash, payload)
        entry = EvidenceEntry(
            entry_id=f"ev-{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            event_type=event_type,
            system_id=system_id,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        _save_entries(self._entries)
        return entry

    def list_all(self) -> List[EvidenceEntry]:
        return list(self._entries)

    def verify_chain(self) -> bool:
        """Re-walk the chain recomputing every hash; True iff intact."""
        prev_hash = GENESIS_HASH
        for entry in self._entries:
            expected_hash = compute_entry_hash(prev_hash, entry.payload)
            if entry.prev_hash != prev_hash:
                return False
            if entry.entry_hash != expected_hash:
                return False
            prev_hash = entry.entry_hash
        return True

    def re_walk(self) -> List[EvidenceEntry]:
        """Return entries only if the chain verifies; raise on tampering."""
        if not self.verify_chain():
            raise ValueError("Evidence chain tamper detected: hash mismatch on re-walk")
        return list(self._entries)

    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def entry_count(self) -> int:
        return len(self._entries)
