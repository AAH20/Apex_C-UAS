"""
CLI for the immutable evidence ledger: c-uas evidence --append|--verify|--anchor.

Pattern: build_subparser(subparsers) + evidence_main(args).
Deterministic output, real computed values, no mocks.
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Optional

from c_uas.evidence_ledger.anchor import anchor_ipfs, anchor_manifest, anchor_to_git
from c_uas.evidence_ledger.ledger import Ledger
from c_uas.evidence_ledger.verify import verify_ledger


def build_subparser(subparsers: Any) -> Any:
    ev_p = subparsers.add_parser(
        "evidence",
        help="Immutable evidence ledger: append, verify, and anchor forensic evidence",
    )
    ev_p.add_argument(
        "--append",
        action="store_true",
        help="Append a new evidence entry to the ledger",
    )
    ev_p.add_argument(
        "--verify",
        action="store_true",
        help="Verify the ledger chain integrity and Merkle proofs",
    )
    ev_p.add_argument(
        "--anchor",
        action="store_true",
        help="Anchor the ledger root hash (git | ipfs | manifest)",
    )
    ev_p.add_argument(
        "--event-type",
        type=str,
        default="detection",
        help="Evidence event type (for --append)",
    )
    ev_p.add_argument(
        "--payload",
        type=str,
        default=None,
        help="JSON payload string (for --append)",
    )
    ev_p.add_argument(
        "--system-id",
        type=str,
        default=None,
        help="System id associated with the evidence (for --append)",
    )
    ev_p.add_argument(
        "--timestamp",
        type=float,
        default=None,
        help="Deterministic timestamp (for --append)",
    )
    ev_p.add_argument(
        "--entry-id",
        type=str,
        default=None,
        help="Deterministic entry id (for --append)",
    )
    ev_p.add_argument(
        "--anchor-type",
        type=str,
        default="manifest",
        help="Anchor backend: git, ipfs, or manifest (for --anchor)",
    )
    ev_p.add_argument(
        "--anchor-path",
        type=str,
        default=None,
        help="Manifest output path (for --anchor manifest)",
    )
    return ev_p


def _parse_payload(raw: Optional[str]) -> dict:
    if raw is None:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"note": raw}


def evidence_main(args: argparse.Namespace) -> int:
    if args.append:
        ledger = Ledger()
        payload = _parse_payload(args.payload)
        entry = ledger.append(
            event_type=args.event_type,
            payload=payload,
            system_id=args.system_id,
            timestamp=args.timestamp,
            entry_id=args.entry_id,
        )
        state = ledger.state()
        print("[C-UAS] Evidence ledger: entry appended")
        print(f"  Entry ID   : {entry.entry_id}")
        print(f"  Index      : {entry.index}")
        print(f"  Event type : {entry.event_type}")
        print(f"  Prev hash  : {entry.prev_hash[:16]}...")
        print(f"  Entry hash : {entry.entry_hash[:16]}...")
        print(f"  Head hash  : {state.head_hash[:16]}...")
        print(f"  Root hash  : {state.root_hash[:16]}...")
        print(f"  Chain valid: {ledger.verify()}")
        return 0

    if args.verify:
        ledger = Ledger()
        report = verify_ledger(ledger.list_all())
        print("[C-UAS] Evidence ledger: chain verification")
        print(f"  Entries    : {report['entry_count']}")
        print(f"  Head hash  : {report['head_hash'][:16]}...")
        print(f"  Root hash  : {report['root_hash'][:16]}...")
        print(f"  Chain valid: {report['chain_valid']}")
        print(f"  Merkle valid: {report['merkle_valid']}")
        print(f"  Tampered   : {report['tampered_indices']}")
        return 0 if report["valid"] else 1

    if args.anchor:
        ledger = Ledger()
        state = ledger.state()
        if args.anchor_type == "git":
            anchor = anchor_to_git(state.root_hash)
        elif args.anchor_type == "ipfs":
            anchor = anchor_ipfs(state.root_hash)
        elif args.anchor_type == "manifest":
            anchor = anchor_manifest(state.root_hash, ledger.list_all(), args.anchor_path)
        else:
            print(
                f"[C-UAS] Unknown anchor type: {args.anchor_type} (expected git, ipfs, or manifest)"
            )
            return 1
        print("[C-UAS] Evidence ledger: anchor created")
        print(f"  Anchor type : {anchor.anchor_type}")
        print(f"  Root hash   : {anchor.root_hash[:16]}...")
        print(f"  Content hash: {anchor.content_hash}")
        print(f"  Created at  : {anchor.created_at}")
        return 0

    print("[C-UAS] evidence: specify --append, --verify, or --anchor")
    return 1
