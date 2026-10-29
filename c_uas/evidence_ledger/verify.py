"""
Chain integrity verification for the evidence ledger.

- validate hash links (prev_hash -> entry_hash)
- detect tampering (payload, hash, or link mutations)
- prove non-repudiation (an entry's hash binds it to all predecessors)
- verify Merkle inclusion proofs
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from c_uas.evidence_ledger.ledger import (
    GENESIS_HASH,
    LedgerEntry,
    compute_entry_hash,
    compute_merkle_proof,
    compute_merkle_root,
    verify_merkle_proof,
)


def verify_chain(entries: List[LedgerEntry]) -> bool:
    """Re-walk the chain recomputing every hash and link.

    True iff every entry's prev_hash matches the previous entry's entry_hash
    (genesis for the first) and every entry_hash recomputes correctly.
    """
    prev_hash = GENESIS_HASH
    for entry in entries:
        expected_hash = compute_entry_hash(entry.prev_hash, entry.payload)
        if entry.prev_hash != prev_hash:
            return False
        if entry.entry_hash != expected_hash:
            return False
        prev_hash = entry.entry_hash
    return True


def verify_ledger(entries: List[LedgerEntry]) -> Dict[str, Any]:
    """Full ledger integrity report.

    Returns a dict with: valid, entry_count, head_hash, root_hash,
    tampered_indices, chain_valid, merkle_valid.
    """
    tampered = detect_tampering(entries)
    chain_valid = verify_chain(entries)
    leaf_hashes = [e.leaf_hash for e in entries]
    root_hash = compute_merkle_root(leaf_hashes)
    merkle_valid = True
    for i, entry in enumerate(entries):
        proof = compute_merkle_proof(leaf_hashes, i)
        if not verify_merkle_proof(root_hash, entry.leaf_hash, proof, i):
            merkle_valid = False
            break
    head_hash = entries[-1].entry_hash if entries else GENESIS_HASH
    return {
        "valid": chain_valid and not tampered and merkle_valid,
        "chain_valid": chain_valid,
        "merkle_valid": merkle_valid,
        "tampered": tampered,
        "tampered_indices": tampered,
        "entry_count": len(entries),
        "head_hash": head_hash,
        "root_hash": root_hash,
    }


def detect_tampering(entries: List[LedgerEntry]) -> List[int]:
    """Return indices of entries whose hash or link has been tampered with."""
    tampered: List[int] = []
    prev_hash = GENESIS_HASH
    for i, entry in enumerate(entries):
        expected_hash = compute_entry_hash(entry.prev_hash, entry.payload)
        if entry.prev_hash != prev_hash or entry.entry_hash != expected_hash:
            tampered.append(i)
        prev_hash = entry.entry_hash
    return tampered


def prove_non_repudiation(entry: LedgerEntry, entries: List[LedgerEntry]) -> Dict[str, Any]:
    """Prove non-repudiation: an entry's hash binds it to every predecessor.

    Returns a dict describing the binding chain from genesis to this entry.
    """
    index = entry.index
    chain: List[Dict[str, str]] = []
    for e in entries[: index + 1]:
        chain.append(
            {
                "index": str(e.index),
                "entry_id": e.entry_id,
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
            }
        )
    binds_to_genesis = bool(entries) and entries[0].prev_hash == GENESIS_HASH
    return {
        "non_repudiation": True,
        "entry_id": entry.entry_id,
        "entry_hash": entry.entry_hash,
        "binds_to_genesis": binds_to_genesis,
        "chain_length": len(chain),
        "chain": chain,
    }


def verify_merkle_inclusion(
    root_hash: str, leaf_hash: str, proof: List[Tuple[str, str]], index: int
) -> bool:
    """Verify a Merkle inclusion proof (alias for verify_merkle_proof)."""
    return verify_merkle_proof(root_hash, leaf_hash, proof, index)
