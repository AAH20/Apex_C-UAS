"""``c-uas security`` production hardening and security CLI.

Usage:
    c-uas security --audit [--report PATH]
    c-uas security --penetrate [--report PATH]
    c-uas security --compliance [--report PATH]

Subcommands:
    --audit        Run the hardening audit (tenant isolation, RLS, secret
                   management, zero-trust network, audit trail).
    --penetrate    Run penetration test scenarios (auth bypass, injection,
                   privilege escalation, IDOR, SSRF).
    --compliance   Show the ISO 42001 / SOC 2 control matrix with gaps.
    --report PATH  Also write a JSON report to PATH (and persist state
                   under ~/.c-uas-platform/security/).

Output is deterministic: identical inputs produce identical output.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .compliance_matrix import (
    DEFAULT_STATE_DIR,
    ComplianceMatrixStore,
    build_matrix,
)
from .hardening import (
    HardeningAuditStore,
    PlatformConfig,
    run_audit,
)
from .penetration import (
    ALL_SCENARIOS,
    PenTestReportStore,
    run_penetration_test,
)

# Baseline platform configuration: deterministic, represents the current
# deployment posture. All values are configuration flags, never secrets.
BASELINE_CONFIG = PlatformConfig(
    tenant_isolation_enforced=True,
    tenant_scoped_queries=True,
    cross_tenant_access_blocked=True,
    rls_enabled=True,
    rls_applied_to_all_tables=False,
    secret_rotation_days=60,
    secrets_in_environment=True,
    no_plaintext_secrets_in_code=True,
    key_management_service=True,
    zero_trust_network_policies=True,
    mtls_enforced=False,
    default_deny_ingress=True,
    network_segmentation=False,
    audit_logging_enabled=True,
    audit_trail_retention_days=365,
    audit_logs_immutable=False,
    audit_events_cover_authz=True,
)


def build_subparser(subparsers: Any) -> Any:
    """Register the ``security`` subcommand on a parent parser."""
    parser = subparsers.add_parser(
        "security",
        help="Production hardening and security: audit, penetration test, compliance",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run the hardening audit (deterministic security scoring)",
    )
    parser.add_argument(
        "--penetrate",
        action="store_true",
        help="Run penetration test scenarios with pass/fail per scenario",
    )
    parser.add_argument(
        "--compliance",
        action="store_true",
        help="Show the ISO 42001 / SOC 2 control matrix with gap analysis",
    )
    parser.add_argument(
        "--report",
        type=str,
        default=None,
        help="Write a JSON report to this path (state is always persisted)",
    )
    return parser


# --------------------------------------------------------------------------- #
# Renderers (pure text, deterministic)
# --------------------------------------------------------------------------- #


def _check_line(check: Any) -> str:
    mark = "PASS" if check.passed else "FAIL"
    return "  %-10s %-7s score=%5.1f weight=%.2f  %s" % (
        check.check_id,
        mark,
        check.score,
        check.weight,
        check.title,
    )


def render_audit(audit: Any) -> str:
    lines: List[str] = []
    lines.append("[C-UAS] Production hardening audit")
    lines.append("=" * 42)
    by_category: Dict[str, List[Any]] = {}
    for check in audit.checks:
        by_category.setdefault(check.category, []).append(check)
    for category in sorted(by_category):
        weight = sum(check.weight for check in by_category[category])
        category_score = sum(check.weight * check.score for check in by_category[category])
        lines.append("Category: %-24s weight=%.2f score=%.1f" % (category, weight, category_score))
        for check in sorted(by_category[category], key=lambda c: c.check_id):
            lines.append(_check_line(check))
            lines.append("      evidence: %s" % check.evidence)
            if not check.passed:
                lines.append("      remediation: %s" % check.remediation)
    lines.append("-" * 42)
    lines.append("Overall score: %.1f   Grade: %s" % (audit.overall_score, audit.grade))
    lines.append(
        "Checks passed: %d/%d" % (sum(1 for c in audit.checks if c.passed), len(audit.checks))
    )
    lines.append("Audit ID: %s" % audit.audit_id)
    lines.append("Config hash: %s" % audit.config_hash)
    return "\n".join(lines)


def _result_line(result: Any) -> str:
    mark = "PASS" if result.passed else "FAIL"
    return "  %-10s %-7s risk=%-6s  %s" % (
        result.scenario_id,
        mark,
        result.risk_level,
        result.evidence,
    )


def render_penetration(report: Any) -> str:
    lines: List[str] = []
    lines.append("[C-UAS] Penetration test results")
    lines.append("=" * 36)
    scenario_map = {s.scenario_id: s for s in ALL_SCENARIOS}
    for result in sorted(report.results, key=lambda r: r.scenario_id):
        scenario = scenario_map[result.scenario_id]
        lines.append(
            "Scenario: %-10s %-7s risk=%-6s  %s"
            % (
                result.scenario_id,
                "PASS" if result.passed else "FAIL",
                result.risk_level,
                scenario.name,
            )
        )
        lines.append("      attack_vector: %s" % scenario.attack_vector)
        lines.append("      severity: %s" % scenario.severity)
        lines.append("      evidence: %s" % result.evidence)
        if not result.passed:
            lines.append("      remediation: %s" % scenario.remediation)
    lines.append("-" * 36)
    lines.append("Overall passed: %s" % report.overall_passed)
    lines.append("Pass rate: %.1f%%" % report.pass_rate)
    lines.append("Report ID: %s" % report.report_id)
    lines.append("Config hash: %s" % report.config_hash)
    return "\n".join(lines)


def render_compliance(matrix: Any) -> str:
    lines: List[str] = []
    lines.append("[C-UAS] ISO 42001 / SOC 2 compliance matrix")
    lines.append("=" * 48)
    by_framework: Dict[str, List[Any]] = {}
    for control in matrix.controls:
        by_framework.setdefault(control.framework, []).append(control)
    for framework in sorted(by_framework):
        implemented = [c for c in by_framework[framework] if c.implemented]
        lines.append(
            "Framework: %-12s coverage=%.1f%%  (%d/%d controls)"
            % (
                framework,
                matrix.iso_coverage if framework == "ISO 42001" else matrix.soc2_coverage,
                len(implemented),
                len(by_framework[framework]),
            )
        )
        for control in sorted(by_framework[framework], key=lambda c: c.control_id):
            mark = "OK" if control.implemented else "GAP"
            lines.append(
                "  %-8s %-7s %s  %s" % (control.control_id, mark, control.domain, control.title)
            )
            for ref in control.evidence_refs:
                lines.append("      evidence: %s" % ref)
            if control.gap:
                lines.append("      gap: %s" % control.gap)
    lines.append("-" * 48)
    lines.append("Overall coverage: %.1f%%" % matrix.overall_coverage)
    lines.append("Gaps: %d" % len(matrix.gaps))
    for gap in matrix.gaps:
        lines.append("  - %s" % gap)
    lines.append("Matrix ID: %s" % matrix.matrix_id)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #


def handle_audit(state_dir: str = DEFAULT_STATE_DIR) -> str:
    store = HardeningAuditStore(state_dir=state_dir)
    audit = run_audit(BASELINE_CONFIG)
    store.save_audit(audit)
    return render_audit(audit)


def handle_penetrate(state_dir: str = DEFAULT_STATE_DIR) -> str:
    store = PenTestReportStore(state_dir=state_dir)
    report = run_penetration_test(BASELINE_CONFIG)
    store.save_report(report)
    return render_penetration(report)


def handle_compliance(state_dir: str = DEFAULT_STATE_DIR) -> str:
    audit_store = HardeningAuditStore(state_dir=state_dir)
    pen_store = PenTestReportStore(state_dir=state_dir)
    audit = audit_store.latest_audit() or run_audit(BASELINE_CONFIG)
    report = pen_store.latest_report() or run_penetration_test(BASELINE_CONFIG)
    matrix = build_matrix(audit, report)
    ComplianceMatrixStore(state_dir=state_dir).save_matrix(matrix)
    return render_compliance(matrix)


def write_report(path: str, state_dir: str = DEFAULT_STATE_DIR) -> None:
    """Write a combined JSON report to ``path``."""
    audit = run_audit(BASELINE_CONFIG)
    report = run_penetration_test(BASELINE_CONFIG)
    matrix = build_matrix(audit, report)
    payload: Dict[str, Any] = {
        "audit": asdict(audit),
        "penetration": asdict(report),
        "compliance": asdict(matrix),
    }
    payload["audit"]["checks"] = [dict(c) for c in payload["audit"]["checks"]]
    payload["penetration"]["results"] = [dict(r) for r in payload["penetration"]["results"]]
    payload["compliance"]["controls"] = [dict(c) for c in payload["compliance"]["controls"]]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def main(argv: Optional[list] = None) -> int:
    if argv is None:
        import sys

        argv = sys.argv[1:]
    return security_main_from_argv(argv)


def security_main_from_argv(argv: list) -> int:
    parser = argparse.ArgumentParser(
        prog="c-uas security",
        description="Production hardening and security for the C-UAS platform",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run the hardening audit (deterministic security scoring)",
    )
    parser.add_argument(
        "--penetrate",
        action="store_true",
        help="Run penetration test scenarios with pass/fail per scenario",
    )
    parser.add_argument(
        "--compliance",
        action="store_true",
        help="Show the ISO 42001 / SOC 2 control matrix with gap analysis",
    )
    parser.add_argument(
        "--report",
        type=str,
        default=None,
        help="Write a JSON report to this path (state is always persisted)",
    )
    args = parser.parse_args(argv)
    return security_main(args)


def security_main(args: argparse.Namespace) -> int:
    if not any([args.audit, args.penetrate, args.compliance]):
        print("[C-UAS] security: specify --audit, --penetrate, or --compliance")
        print("  c-uas security --audit")
        print("  c-uas security --penetrate")
        print("  c-uas security --compliance --report PATH")
        return 1

    output = ""
    if args.audit:
        output = handle_audit()
    elif args.penetrate:
        output = handle_penetrate()
    elif args.compliance:
        output = handle_compliance()

    print(output)
    if args.report:
        write_report(args.report)
        print("[C-UAS] JSON report written to %s" % args.report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
