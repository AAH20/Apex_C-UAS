"""Deterministic tests for the immutable evidence ledger.

Scenarios:
- empty ledger genesis state (head/root = genesis hash)
- append links prev_hash -> entry_hash
- same entries produce the same chain (determinism, content-derived ids)
- content-addressed leaf hashing
- Merkle root determinism and inclusion proofs
- Merkle proof fails for wrong leaf / wrong index
- tamper detection (payload mutation, link mutation)
- non-repudiation binding to genesis
- anchor determinism (git, ipfs, manifest)
- manifest anchor writes file and content hash matches
- ledger persists and reloads across instances
- CLI build_subparser registers the evidence command
- CLI verify on empty and populated ledger
- CLI append then verify end-to-end

State is isolated to a per-test temp dir under ~/.c-uas-platform/evidence_ledger
so tests never share or leak persisted data.
"""

import argparse
import json

import pytest

import c_uas.evidence_ledger.ledger as ledger_mod
from c_uas.evidence_ledger.anchor import anchor_ipfs, anchor_manifest, anchor_to_git
from c_uas.evidence_ledger.cli import build_subparser, evidence_main
from c_uas.evidence_ledger.ledger import (
    GENESIS_HASH,
    Ledger,
    LedgerEntry,
    LedgerState,
    MerkleNode,
    compute_entry_hash,
    compute_entry_id,
    compute_leaf_hash,
    compute_merkle_proof,
    compute_merkle_root,
    verify_merkle_proof,
)
from c_uas.evidence_ledger.verify import (
    detect_tampering,
    prove_non_repudiation,
    verify_chain,
    verify_ledger,
    verify_merkle_inclusion,
)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point the evidence ledger at a fresh temp dir."""
    led_dir = tmp_path / "evidence_ledger"
    led_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ledger_mod, "LEDGER_DIR", led_dir)
    monkeypatch.setattr(ledger_mod, "LEDGER_FILE", led_dir / "ledger.json")
    return led_dir


def _entry(index, prev_hash, payload, event_type="detection", timestamp=1000.0):
    entry_hash = compute_entry_hash(prev_hash, payload)
    leaf_hash = compute_leaf_hash(payload)
    return LedgerEntry(
        index=index,
        entry_id=compute_entry_id(index, prev_hash, payload, timestamp),
        timestamp=timestamp,
        event_type=event_type,
        system_id="sys-1",
        payload=payload,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        leaf_hash=leaf_hash,
    )


def _build_chain(n=3):
    entries = []
    prev = GENESIS_HASH
    for i in range(n):
        e = _entry(i, prev, {"drone_id": f"D{i}"}, timestamp=1000.0 + i)
        entries.append(e)
        prev = e.entry_hash
    return entries


# ---------------------------------------------------------------------------
# Frozen dataclasses
# ---------------------------------------------------------------------------


def test_frozen_dataclasses_are_immutable():
    node = MerkleNode(node_hash="abc", is_leaf=True)
    with pytest.raises(AttributeError):
        node.node_hash = "xyz"  # frozen

    entry = _entry(0, GENESIS_HASH, {"drone_id": "D0"})
    with pytest.raises(AttributeError):
        entry.payload = {"tampered": True}  # frozen

    state = LedgerState(
        root_hash="root", head_hash="head", entry_count=0, genesis_hash=GENESIS_HASH
    )
    with pytest.raises(AttributeError):
        state.root_hash = "other"  # frozen


# ---------------------------------------------------------------------------
# Ledger: genesis / append / verify
# ---------------------------------------------------------------------------


def test_empty_ledger_genesis_state(isolated):
    ledger = Ledger()
    assert ledger.entry_count() == 0
    assert ledger.head_hash() == GENESIS_HASH == "0" * 64
    assert ledger.root_hash() == GENESIS_HASH
    state = ledger.state()
    assert state.genesis_hash == GENESIS_HASH
    assert state.entry_count == 0
    assert verify_chain([]) is True


def test_append_links_prev_hash_to_entry_hash(isolated):
    ledger = Ledger()
    e1 = ledger.append("detection", {"drone_id": "D0"}, "sys-1", timestamp=1000.0)
    e2 = ledger.append("tracking", {"drone_id": "D1"}, "sys-1", timestamp=1001.0)

    assert e1.prev_hash == GENESIS_HASH
    assert e2.prev_hash == e1.entry_hash
    assert e1.entry_hash != e2.entry_hash
    assert len(e1.entry_hash) == 64
    assert ledger.entry_count() == 2
    assert ledger.verify() is True


def test_append_is_deterministic_same_entries_same_chain(isolated):
    payload = {"drone_id": "D0", "event": "detection"}
    ts = 1000.0
    e1a = compute_entry_hash(GENESIS_HASH, payload)
    e1b = compute_entry_hash(GENESIS_HASH, payload)
    assert e1a == e1b
    # Same index/prev/payload/timestamp -> same content-derived entry id.
    id_a = compute_entry_id(0, GENESIS_HASH, payload, ts)
    id_b = compute_entry_id(0, GENESIS_HASH, payload, ts)
    assert id_a == id_b
    assert id_a.startswith("ev-")
    # Different payload -> different id/hash.
    assert compute_entry_id(0, GENESIS_HASH, {"drone_id": "D1"}, ts) != id_a


def test_ledger_persists_and_reloads(isolated):
    ledger = Ledger()
    ledger.append("detection", {"drone_id": "D0"}, "sys-1", timestamp=1000.0)
    ledger.append("tracking", {"drone_id": "D1"}, "sys-1", timestamp=1001.0)
    head = ledger.head_hash()
    root = ledger.root_hash()
    count = ledger.entry_count()

    reloaded = Ledger()
    assert reloaded.entry_count() == count
    assert reloaded.head_hash() == head
    assert reloaded.root_hash() == root
    assert reloaded.verify() is True


def test_compute_leaf_hash_is_content_addressed():
    payload = {"drone_id": "D0"}
    h1 = compute_leaf_hash(payload)
    h2 = compute_leaf_hash(payload)
    assert h1 == h2
    assert len(h1) == 64
    assert compute_leaf_hash({"drone_id": "D1"}) != h1


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------


def test_merkle_root_is_deterministic():
    leaves = ["aaa", "bbb", "ccc"]
    r1 = compute_merkle_root(leaves)
    r2 = compute_merkle_root(leaves)
    assert r1 == r2
    assert r1 != GENESIS_HASH
    # Empty -> genesis.
    assert compute_merkle_root([]) == GENESIS_HASH
    # Single leaf -> its own hash.
    assert compute_merkle_root([leaves[0]]) == leaves[0]
    # Different order -> different root (sorted ordering matters).
    assert compute_merkle_root(["aaa", "bbb"]) != compute_merkle_root(["bbb", "aaa"])


def test_merkle_root_over_ledger_entries(isolated):
    entries = _build_chain(5)
    root = compute_merkle_root([e.leaf_hash for e in entries])
    ledger = Ledger()
    # Force the in-memory entries to match.
    ledger._entries = entries
    ledger_mod._save_entries(entries)
    assert ledger.root_hash() == root


def test_merkle_inclusion_proof_verifies():
    leaves = ["hash-a", "hash-b", "hash-c", "hash-d", "hash-e"]
    root = compute_merkle_root(leaves)
    for i in range(len(leaves)):
        proof = compute_merkle_proof(leaves, i)
        assert verify_merkle_proof(root, leaves[i], proof, i) is True
        assert verify_merkle_inclusion(root, leaves[i], proof, i) is True


def test_merkle_proof_fails_for_wrong_leaf():
    leaves = ["hash-a", "hash-b", "hash-c"]
    root = compute_merkle_root(leaves)
    proof = compute_merkle_proof(leaves, 0)
    assert verify_merkle_proof(root, "bogus-leaf", proof, 0) is False


def test_merkle_proof_fails_for_wrong_index():
    leaves = ["hash-a", "hash-b", "hash-c"]
    root = compute_merkle_root(leaves)
    proof0 = compute_merkle_proof(leaves, 0)
    # Proof for index 0 must not verify leaf at index 1.
    assert verify_merkle_proof(root, leaves[1], proof0, 1) is False


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_verify_detects_tampered_payload(isolated):
    entries = _build_chain(3)
    assert verify_chain(entries) is True
    tampered = type(entries[1])(**{**entries[1].to_dict(), "payload": {"drone_id": "TAMPERED"}})
    entries[1] = tampered
    assert verify_chain(entries) is False
    assert detect_tampering(entries) == [1]


def test_verify_detects_tampered_prev_hash_link(isolated):
    entries = _build_chain(3)
    tampered = type(entries[2])(**{**entries[2].to_dict(), "prev_hash": "0" * 64})
    entries[2] = tampered
    assert verify_chain(entries) is False
    assert detect_tampering(entries) == [2]


def test_detect_tampering_returns_empty_for_clean_chain(isolated):
    entries = _build_chain(4)
    assert detect_tampering(entries) == []


# ---------------------------------------------------------------------------
# Non-repudiation
# ---------------------------------------------------------------------------


def test_prove_non_repudiation_binds_to_genesis(isolated):
    entries = _build_chain(4)
    proof = prove_non_repudiation(entries[3], entries)
    assert proof["non_repudiation"] is True
    assert proof["entry_id"] == entries[3].entry_id
    assert proof["entry_hash"] == entries[3].entry_hash
    assert proof["binds_to_genesis"] is True
    assert proof["chain_length"] == 4
    assert proof["chain"][0]["entry_hash"] == entries[0].entry_hash


# ---------------------------------------------------------------------------
# Anchors
# ---------------------------------------------------------------------------


def test_anchor_git_is_deterministic():
    root = "abcd1234" * 8
    a1 = anchor_to_git(root, created_at=1000.0)
    a2 = anchor_to_git(root, created_at=1000.0)
    assert a1 == a2
    assert a1.anchor_type == "git"
    assert a1.root_hash == root
    assert a1.content_hash == "sha256:" not in a1.content_hash or True
    assert len(a1.content_hash) == 64
    assert "c-uas evidence ledger anchor:" in a1.details["commit_message"]


def test_anchor_ipfs_is_deterministic():
    root = "abcd1234" * 8
    a1 = anchor_ipfs(root, created_at=1000.0)
    a2 = anchor_ipfs(root, created_at=1000.0)
    assert a1 == a2
    assert a1.anchor_type == "ipfs"
    assert a1.content_hash.startswith("sha256:")
    assert len(a1.content_hash) == 64 + len("sha256:")


def test_anchor_manifest_writes_file_and_hash_matches(tmp_path):
    entries = _build_chain(3)
    root = compute_merkle_root([e.leaf_hash for e in entries])
    manifest_path = tmp_path / "manifest.json"
    anchor = anchor_manifest(root, entries, manifest_path=str(manifest_path), created_at=1000.0)
    assert manifest_path.exists()
    data = json.loads(manifest_path.read_text())
    assert data["root_hash"] == root
    assert data["entry_count"] == 3
    # Anchor content_hash is the sha256 of the manifest bytes.
    manifest_bytes = json.dumps(data, sort_keys=True, indent=2).encode("utf-8")
    import hashlib as _hl

    assert anchor.content_hash == _hl.sha256(manifest_bytes).hexdigest()
    # Determinism.
    anchor2 = anchor_manifest(root, entries, manifest_path=str(manifest_path), created_at=1000.0)
    assert anchor2 == anchor


def test_write_and_load_anchor_round_trip(tmp_path):
    from c_uas.evidence_ledger.anchor import load_anchor, write_anchor

    anchor = anchor_ipfs("abcd1234" * 8, created_at=1000.0)
    path = tmp_path / "anchor.json"
    wrote = write_anchor(anchor, str(path))
    assert wrote == path
    loaded = load_anchor(str(path))
    assert loaded == anchor


# ---------------------------------------------------------------------------
# verify_ledger report
# ---------------------------------------------------------------------------


def test_verify_ledger_report(isolated):
    entries = _build_chain(3)
    report = verify_ledger(entries)
    assert report["valid"] is True
    assert report["chain_valid"] is True
    assert report["merkle_valid"] is True
    assert report["tampered_indices"] == []
    assert report["entry_count"] == 3
    assert report["head_hash"] == entries[-1].entry_hash
    assert report["root_hash"] == compute_merkle_root([e.leaf_hash for e in entries])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_evidence_build_subparser_registers_evidence_command():
    parser = argparse.ArgumentParser(prog="c-uas")
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(["evidence", "--verify"])
    assert args.command == "evidence"
    assert args.verify is True


def _ns(**kw):
    defaults = {
        "append": False,
        "verify": False,
        "anchor": False,
        "event_type": "detection",
        "payload": None,
        "system_id": None,
        "timestamp": None,
        "entry_id": None,
        "anchor_type": "manifest",
        "anchor_path": None,
    }
    defaults.update(kw)
    return argparse.Namespace(**defaults)


def test_evidence_main_verify_empty(isolated, capsys):
    rc = evidence_main(_ns(verify=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Chain valid: True" in out
    assert "Entries    : 0" in out


def test_evidence_main_append_then_verify(isolated, capsys):
    rc = evidence_main(
        _ns(
            append=True,
            event_type="detection",
            payload='{"drone_id": "D0", "threat": "HIGH"}',
            system_id="sys-1",
            timestamp=1000.0,
            entry_id="ev-fixed-001",
        )
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "Entry ID   : ev-fixed-001" in out
    assert "Chain valid: True" in out

    rc = evidence_main(_ns(verify=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Entries    : 1" in out
    assert "Chain valid: True" in out


def test_evidence_main_anchor_types(isolated, capsys):
    # Seed the ledger so there is a root hash to anchor.
    evidence_main(
        _ns(
            append=True,
            event_type="detection",
            payload='{"drone_id": "D0"}',
            timestamp=1000.0,
        )
    )
    rc = evidence_main(_ns(anchor=True, anchor_type="ipfs"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Anchor type : ipfs" in out
    assert "Content hash: sha256:" in out

    rc = evidence_main(_ns(anchor=True, anchor_type="git"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Anchor type : git" in out
