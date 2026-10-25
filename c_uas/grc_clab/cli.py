"""
CLI for GRC_Clab agentic governance: c-uas grc --chain|--monitor|--remediate.

Pattern: build_subparser(subparsers) + grc_main(args).
Deterministic output, real computed values, no mocks.
"""

from __future__ import annotations

import argparse
from typing import Any

from c_uas.grc_clab.autonomous_agent import DEFAULT_SCAN_INTERVAL_S, AutonomousAgent
from c_uas.grc_clab.evidence_chain import EvidenceChain
from c_uas.grc_clab.remediation import RemediationPlanner, dependency_order


def build_subparser(subparsers: Any) -> Any:
    grc_p = subparsers.add_parser(
        "grc",
        help="GRC_Clab agentic governance: evidence chain, compliance monitoring, remediation",
    )
    grc_p.add_argument(
        "--chain",
        action="store_true",
        help="Show the hash-linked evidence chain and verify tamper-evidence",
    )
    grc_p.add_argument(
        "--monitor",
        action="store_true",
        help="Run one autonomous compliance monitoring cycle",
    )
    grc_p.add_argument(
        "--remediate",
        action="store_true",
        help="Propose and dependency-order remediation actions",
    )
    grc_p.add_argument(
        "--interval-s",
        type=float,
        default=DEFAULT_SCAN_INTERVAL_S,
        help="Scan interval in seconds for the autonomous agent",
    )


def grc_main(args: argparse.Namespace) -> int:
    if args.chain:
        chain = EvidenceChain()
        valid = chain.verify_chain()
        print(f"[C-UAS] GRC evidence chain: {chain.entry_count()} entries, valid={valid}")
        print(f"  Head hash   : {chain.head_hash()}")
        print(f"  Genesis hash: {'0' * 64}")
        for entry in chain.list_all():
            print(
                f"  {entry.entry_id}  {entry.event_type}  "
                f"prev={entry.prev_hash[:16]}...  hash={entry.entry_hash[:16]}..."
            )
        return 0 if valid else 1

    if args.monitor:
        agent = AutonomousAgent(interval_s=args.interval_s)
        from c_uas.governance import AISystemRegistry, ControlImplementation

        registry = AISystemRegistry()
        controller = ControlImplementation()
        systems = registry.list_all()
        controls = controller.list_all()
        result = agent.run_tick(systems, controls)
        print("[C-UAS] GRC autonomous compliance monitor")
        print(f"  Systems scanned   : {result.systems_scanned}")
        print(f"  Violations        : {len(result.violations)}")
        print(f"  Evidence entries  : {len(result.evidence_entries)}")
        print(f"  Remediation actions: {len(result.remediation_actions)}")
        for v in result.violations:
            print(f"  - {v.control_id}  {v.severity}  {v.description[:80]}")
        return 0

    if args.remediate:
        planner = RemediationPlanner()
        ordered = dependency_order(planner.list_actions())
        if not ordered:
            print("[C-UAS] GRC remediation: no proposed remediation actions.")
            print("  Run `c-uas grc --monitor` to detect violations and propose actions.")
            return 0
        print(f"[C-UAS] GRC remediation plan: {len(ordered)} action(s)")
        total_effort = 0.0
        for i, a in enumerate(ordered, 1):
            total_effort += a.estimated_effort_hours
            deps = ", ".join(a.depends_on) or "(none)"
            print(
                f"  {i}. {a.action_id}  {a.control_id}  "
                f"priority={a.priority_score}  effort={a.estimated_effort_hours}h  "
                f"status={a.status}  depends={deps}"
            )
            print(f"     {a.description}")
        print(f"  Total estimated effort : {total_effort:.1f} hours")
        return 0

    print("[C-UAS] grc: specify --chain, --monitor, or --remediate")
    return 1
