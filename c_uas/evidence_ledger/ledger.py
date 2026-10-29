"""
Immutable, tamper-evident evidence ledger for court-admissible C-UAS forensics.

Hash-linked, content-addressed ledger with Merkle tree root computation.

- genesis hash "0" * 64 seeds the chain
- each entry: entry_hash = sha256(prev_hash + canonical(payload))
  (reuses the c_uas.grc_clab.evidence_chain hashing scheme)
- content-addressed leaf hashing; Merkle root over all leaf hashes
- frozen dataclasses: LedgerEntry, LedgerState, MerkleNode
- deterministic: same entries -> same chain; sorted ordering; content-derived ids
- persistence under ~/.c-uas-platform/evidence_ledger/

Conventions: executable-analysis-modules (frozen dataclasses, pure functions,
deterministic, real computed values).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from c_uas.grc_clab.evidence_chain import GENESIS_HASH, compute_entry_hash

LEDGER_DIR = Path.home() / ".c-uas-platform" / "evidence_ledger"
LEDGER_FILE = LEDGER_DIR / "ledger.json"


@dataclass(frozen=True)
class MerkleNode:
    """A node in the Merkle tree over ledger leaf hashes."""

    node_hash: str
    left: Optional[str] = None
    right: Optional[str] = None
    entry_index: Optional[int] = None
    is_leaf: bool = False


@dataclass(frozen=True)
class LedgerEntry:
    """An immutable, hash-linked ledger entry."""

    index: int
    entry_id: str
    timestamp: float
    event_type: str
    system_id: Optional[str]
    payload: Dict[str, Any]
    prev_hash: str
    entry_hash: str
    leaf_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LedgerState:
    """Immutable snapshot of the ledger state."""

    root_hash: str
    head_hash: str
    entry_count: int
    genesis_hash: str


def canonical(payload: Dict[str, Any]) -> str:
    """Canonical JSON serialization of a payload (deterministic)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_leaf_hash(payload: Dict[str, Any]) -> str:
    """Content-addressed leaf hash: sha256(canonical(payload))."""
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def compute_entry_id(index: int, prev_hash: str, payload: Dict[str, Any], timestamp: float) -> str:
    """Deterministic, content-derived entry id."""
    material = f"{index}:{prev_hash}:{canonical(payload)}:{timestamp}"
    return "ev-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def compute_merkle_root(leaf_hashes: List[str]) -> str:
    """Pure function: Merkle root hash over a list of leaf hashes.

    Duplicates the last leaf when the count is odd (deterministic).
    Empty list -> GENESIS_HASH.
    """
    if not leaf_hashes:
        return GENESIS_HASH
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt: List[str] = []
        for i in range(0, len(level), 2):
            nxt.append(hashlib.sha256((level[i] + level[i + 1]).encode("utf-8")).hexdigest())
        level = nxt
    return level[0]


def compute_merkle_proof(leaf_hashes: List[str], index: int) -> List[Tuple[str, str]]:
    """Pure function: Merkle inclusion proof for leaf at ``index``.

    Returns a list of (direction, sibling_hash) where direction is "left" or
    "right" indicating which side the sibling sits on relative to the running
    hash.
    """
    if not leaf_hashes or index < 0 or index >= len(leaf_hashes):
        return []
    proof: List[Tuple[str, str]] = []
    level = list(leaf_hashes)
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if idx % 2 == 0:
            sibling = level[idx + 1]
            proof.append(("right", sibling))
        else:
            sibling = level[idx - 1]
            proof.append(("left", sibling))
        idx //= 2
        nxt: List[str] = []
        for i in range(0, len(level), 2):
            nxt.append(hashlib.sha256((level[i] + level[i + 1]).encode("utf-8")).hexdigest())
        level = nxt
    return proof


def verify_merkle_proof(
    root_hash: str, leaf_hash: str, proof: List[Tuple[str, str]], index: int
) -> bool:
    """Verify a Merkle inclusion proof against the root hash."""
    current = leaf_hash
    idx = index
    for direction, sibling in proof:
        if direction == "right":
            current = hashlib.sha256((current + sibling).encode("utf-8")).hexdigest()
        else:
            current = hashlib.sha256((sibling + current).encode("utf-8")).hexdigest()
        idx //= 2
    return current == root_hash


def _ensure_dir() -> None:
    LEDGER_DIR.mkdir(parents=True, exist_ok=True)


def _load_entries() -> List[LedgerEntry]:
    _ensure_dir()
    if not LEDGER_FILE.exists():
        return []
    try:
        rows = json.loads(LEDGER_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    return [LedgerEntry(**row) for row in rows]


def _save_entries(entries: List[LedgerEntry]) -> None:
    _ensure_dir()
    LEDGER_FILE.write_text(json.dumps([e.to_dict() for e in entries], indent=2))


def _compute_state(entries: List[LedgerEntry]) -> LedgerState:
    head_hash = entries[-1].entry_hash if entries else GENESIS_HASH
    leaf_hashes = [e.leaf_hash for e in entries]
    root_hash = compute_merkle_root(leaf_hashes)
    return LedgerState(
        root_hash=root_hash,
        head_hash=head_hash,
        entry_count=len(entries),
        genesis_hash=GENESIS_HASH,
    )


class Ledger:
    """Tamper-evident, hash-linked evidence ledger."""

    def __init__(self) -> None:
        self._entries: List[LedgerEntry] = _load_entries()

    def append(
        self,
        event_type: str,
        payload: Dict[str, Any],
        system_id: Optional[str] = None,
        timestamp: Optional[float] = None,
        entry_id: Optional[str] = None,
    ) -> LedgerEntry:
        """Append a new evidence entry, hash-linked to its predecessor."""
        ts = time.time() if timestamp is None else float(timestamp)
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        index = len(self._entries)
        if entry_id is None:
            entry_id = compute_entry_id(index, prev_hash, payload, ts)
        entry_hash = compute_entry_hash(prev_hash, payload)
        leaf_hash = compute_leaf_hash(payload)
        entry = LedgerEntry(
            index=index,
            entry_id=entry_id,
            timestamp=ts,
            event_type=event_type,
            system_id=system_id,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            leaf_hash=leaf_hash,
        )
        self._entries.append(entry)
        _save_entries(self._entries)
        return entry

    def list_all(self) -> List[LedgerEntry]:
        return list(self._entries)

    def entry_count(self) -> int:
        return len(self._entries)

    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def root_hash(self) -> str:
        return _compute_state(self._entries).root_hash

    def state(self) -> LedgerState:
        return _compute_state(self._entries)

    def get(self, index: int) -> Optional[LedgerEntry]:
        if 0 <= index < len(self._entries):
            return self._entries[index]
        return None

    def verify(self) -> bool:
        from c_uas.evidence_ledger.verify import verify_chain

        return verify_chain(self._entries)
