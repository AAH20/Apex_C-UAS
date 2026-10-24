"""Deterministic tests for the C-UAS production hardening and security module.

Covers the hardening audit (scoring, grades, persistence), the
penetration test framework (pass/fail per scenario), the ISO 42001 /
SOC 2 compliance matrix (evidence linkage, gap analysis), and the CLI
(deterministic output). All values are real computations -- no mocks,
no fabricated metrics, no network.
"""

from __future__ import annotations

import os

from c_uas.security.cli import handle_audit, handle_compliance, handle_penetrate, main
from c_uas.security.compliance_matrix import build_matrix
from c_uas.security.hardening import (
    DEFAULT_STATE_DIR,
    HardeningAuditStore,
    PlatformConfig,
    config_hash,
    grade_for,
    run_audit,
)
from c_uas.security.penetration import (
    ALL_SCENARIOS,
    PenTestReportStore,
    run_penetration_test,
)

REQUIRED_CATEGORIES = [
    "tenant_isolation",
    "rls",
    "secret_management",
    "zero_trust_network",
    "audit_trail",
]

REQUIRED_SCENARIOS = [
    "AUTH-001",
    "INJ-001",
    "PRIVESC-001",
    "IDOR-001",
    "SSRF-001",
]


def disabled_config() -> PlatformConfig:
    return PlatformConfig()


def enabled_config() -> PlatformConfig:
    return PlatformConfig(
        tenant_isolation_enforced=True,
        tenant_scoped_queries=True,
        cross_tenant_access_blocked=True,
        rls_enabled=True,
        rls_applied_to_all_tables=True,
        secret_rotation_days=60,
        secrets_in_environment=True,
        no_plaintext_secrets_in_code=True,
        key_management_service=True,
        zero_trust_network_policies=True,
        mtls_enforced=True,
        default_deny_ingress=True,
        network_segmentation=True,
        audit_logging_enabled=True,
        audit_trail_retention_days=365,
        audit_logs_immutable=True,
        audit_events_cover_authz=True,
    )


# --------------------------------------------------------------------------- #
# Hardening audit: scoring and grades
# --------------------------------------------------------------------------- #


def test_audit_all_disabled_score_zero_grade_f() -> None:
    audit = run_audit(disabled_config())
    assert audit.overall_score == 0.0
    assert audit.grade == "F"
    assert not any(check.passed for check in audit.checks)


def test_audit_all_enabled_score_hundred_grade_a() -> None:
    audit = run_audit(enabled_config())
    assert audit.overall_score == 100.0
    assert audit.grade == "A"
    assert all(check.passed for check in audit.checks)


def test_grade_bands() -> None:
    assert grade_for(100.0) == "A"
    assert grade_for(90.0) == "A"
    assert grade_for(89.9) == "B"
    assert grade_for(80.0) == "B"
    assert grade_for(79.9) == "C"
    assert grade_for(70.0) == "C"
    assert grade_for(69.9) == "D"
    assert grade_for(60.0) == "D"
    assert grade_for(59.9) == "F"
    assert grade_for(0.0) == "F"


def test_audit_is_deterministic() -> None:
    config = PlatformConfig(
        tenant_isolation_enforced=True,
        rls_enabled=True,
        secret_rotation_days=30,
        audit_logging_enabled=True,
    )
    first = run_audit(config)
    second = run_audit(config)
    assert first == second
    assert first.audit_id == second.audit_id
    assert first.config_hash == second.config_hash


def test_config_hash_is_deterministic() -> None:
    config = PlatformConfig(rls_enabled=True)
    assert config_hash(config) == config_hash(config)


def test_category_weights_sum_to_one() -> None:
    from c_uas.security.hardening import CATEGORY_WEIGHTS

    total = sum(CATEGORY_WEIGHTS.values())
    assert abs(total - 1.0) < 1e-9


def test_check_weights_sum_to_one_per_category() -> None:
    by_category: dict = {}
    for check in run_audit(enabled_config()).checks:
        by_category.setdefault(check.category, []).append(check.weight)
    for category, weights in by_category.items():
        assert abs(sum(weights) - 1.0) < 1e-9, category


def test_all_five_categories_audited() -> None:
    audit = run_audit(enabled_config())
    categories = {check.category for check in audit.checks}
    assert set(REQUIRED_CATEGORIES).issubset(categories)


def test_eleven_checks_returned() -> None:
    audit = run_audit(enabled_config())
    assert len(audit.checks) == 11


def test_check_ids_deterministic_and_ordered() -> None:
    audit = run_audit(enabled_config())
    ids = [check.check_id for check in audit.checks]
    expected = [
        "TENANT-001",
        "TENANT-002",
        "RLS-001",
        "RLS-002",
        "SECRET-001",
        "SECRET-002",
        "NET-001",
        "NET-002",
        "AUDIT-001",
        "AUDIT-002",
        "AUDIT-003",
    ]
    assert ids == expected
    assert ids == [check.check_id for check in run_audit(enabled_config()).checks]


def test_evidence_and_remediation_present() -> None:
    audit = run_audit(disabled_config())
    for check in audit.checks:
        assert isinstance(check.evidence, str) and check.evidence, check.check_id
        assert isinstance(check.remediation, str) and check.remediation, check.check_id
        assert check.score in (0.0, 100.0)
        assert 0.0 < check.weight <= 1.0


def test_audit_id_changes_when_config_changes() -> None:
    base = run_audit(disabled_config())
    changed = run_audit(PlatformConfig(rls_enabled=True))
    assert base.audit_id != changed.audit_id
    assert base.config_hash != changed.config_hash


# --------------------------------------------------------------------------- #
# Hardening audit: persistence (outside the repo)
# --------------------------------------------------------------------------- #


def test_audit_persistence_round_trip(tmp_path) -> None:
    store = HardeningAuditStore(state_dir=str(tmp_path))
    audit = run_audit(enabled_config())
    audit_id = store.save_audit(audit)
    assert audit_id == audit.audit_id
    loaded = store.load_audit(audit.audit_id)
    assert loaded == audit
    assert store.latest_audit_id() == audit.audit_id
    assert store.latest_audit() == audit


def test_audit_state_dir_is_outside_repo() -> None:
    assert DEFAULT_STATE_DIR == os.path.join(os.path.expanduser("~"), ".c-uas-platform", "security")
    assert DEFAULT_STATE_DIR.endswith(".c-uas-platform/security")


# --------------------------------------------------------------------------- #
# Penetration test framework: scenarios and pass/fail
# --------------------------------------------------------------------------- #


def test_penetration_scenarios_cover_required_areas() -> None:
    ids = [scenario.scenario_id for scenario in ALL_SCENARIOS]
    for required in REQUIRED_SCENARIOS:
        assert required in ids
    categories = {scenario.category for scenario in ALL_SCENARIOS}
    assert {
        "auth_bypass",
        "injection",
        "privilege_escalation",
        "idor",
        "ssrf",
    }.issubset(categories)


def test_penetration_all_disabled_all_fail() -> None:
    report = run_penetration_test(disabled_config())
    assert not report.overall_passed
    assert report.pass_rate == 0.0
    for result in report.results:
        assert not result.passed
        assert result.risk_level == "HIGH"


def test_penetration_all_enabled_all_pass() -> None:
    report = run_penetration_test(enabled_config())
    assert report.overall_passed
    assert report.pass_rate == 100.0
    for result in report.results:
        assert result.passed
        assert result.risk_level == "LOW"


def test_penetration_is_deterministic() -> None:
    config = PlatformConfig(
        rls_enabled=True,
        no_plaintext_secrets_in_code=True,
        key_management_service=True,
        zero_trust_network_policies=True,
        default_deny_ingress=True,
    )
    first = run_penetration_test(config)
    second = run_penetration_test(config)
    assert first == second
    assert first.report_id == second.report_id
    assert [r.scenario_id for r in first.results] == REQUIRED_SCENARIOS


def test_penetration_pass_rate_and_overall() -> None:
    # AUTH-001 passes (keys protected), the rest fail with all defaults off.
    report = run_penetration_test(disabled_config())
    # Only controls present in enabled subsets: none pass here since every
    # scenario needs at least one control that is off by default.
    assert report.pass_rate == 0.0
    config = PlatformConfig(
        no_plaintext_secrets_in_code=True,
        key_management_service=True,
        audit_logging_enabled=True,
        rls_enabled=True,
        rls_applied_to_all_tables=True,
        tenant_isolation_enforced=True,
        tenant_scoped_queries=True,
        zero_trust_network_policies=True,
        default_deny_ingress=True,
        network_segmentation=True,
    )
    partial = run_penetration_test(config)
    passed = sum(1 for r in partial.results if r.passed)
    assert partial.pass_rate == passed / len(partial.results) * 100.0
    assert partial.overall_passed == (passed == len(partial.results))


def test_penetration_results_have_evidence_and_risk() -> None:
    report = run_penetration_test(disabled_config())
    for result in report.results:
        assert isinstance(result.evidence, str) and result.evidence
        assert result.risk_level in ("LOW", "HIGH")


# --------------------------------------------------------------------------- #
# Penetration test: persistence
# --------------------------------------------------------------------------- #


def test_penetration_persistence_round_trip(tmp_path) -> None:
    store = PenTestReportStore(state_dir=str(tmp_path))
    report = run_penetration_test(enabled_config())
    report_id = store.save_report(report)
    assert report_id == report.report_id
    assert store.load_report(report.report_id) == report
    assert store.latest_report() == report


# --------------------------------------------------------------------------- #
# Compliance matrix: ISO 42001 / SOC 2 mapping and gap analysis
# --------------------------------------------------------------------------- #


def test_compliance_matrix_has_both_frameworks() -> None:
    audit = run_audit(enabled_config())
    report = run_penetration_test(enabled_config())
    matrix = build_matrix(audit, report)
    frameworks = {control.framework for control in matrix.controls}
    assert frameworks == {"ISO 42001", "SOC 2"}


def test_controls_have_evidence_refs() -> None:
    matrix = build_matrix(run_audit(enabled_config()), run_penetration_test(enabled_config()))
    for control in matrix.controls:
        assert isinstance(control.evidence_refs, tuple) and control.evidence_refs
        for ref in control.evidence_refs:
            assert isinstance(ref, str) and ref


def test_compliance_all_enabled_full_coverage_no_gaps() -> None:
    matrix = build_matrix(run_audit(enabled_config()), run_penetration_test(enabled_config()))
    assert matrix.iso_coverage == 100.0
    assert matrix.soc2_coverage == 100.0
    assert matrix.overall_coverage == 100.0
    assert matrix.gaps == ()
    assert all(control.implemented for control in matrix.controls)


def test_compliance_all_disabled_all_gaps() -> None:
    matrix = build_matrix(run_audit(disabled_config()), run_penetration_test(disabled_config()))
    assert matrix.iso_coverage == 0.0
    assert matrix.soc2_coverage == 0.0
    assert matrix.overall_coverage == 0.0
    assert len(matrix.gaps) == len(matrix.controls)
    assert not any(control.implemented for control in matrix.controls)


def test_compliance_baseline_coverage_is_deterministic() -> None:
    matrix = build_matrix(run_audit(disabled_config()), run_penetration_test(disabled_config()))
    again = build_matrix(run_audit(disabled_config()), run_penetration_test(disabled_config()))
    assert matrix == again
    assert matrix.matrix_id == again.matrix_id


# --------------------------------------------------------------------------- #
# CLI: deterministic output
# --------------------------------------------------------------------------- #


def test_cli_audit_output_is_deterministic(tmp_path) -> None:
    first = handle_audit(state_dir=str(tmp_path))
    second = handle_audit(state_dir=str(tmp_path))
    assert first == second
    assert "[C-UAS] Production hardening audit" in first
    assert "Overall score:" in first
    assert "Grade:" in first
    for required in ["TENANT-001", "RLS-001", "SECRET-001", "NET-001", "AUDIT-001"]:
        assert required in first


def test_cli_penetrate_output_contains_all_scenarios(tmp_path) -> None:
    output = handle_penetrate(state_dir=str(tmp_path))
    for required in REQUIRED_SCENARIOS:
        assert required in output
    assert "Pass rate:" in output
    assert "Overall passed:" in output


def test_cli_compliance_output_contains_frameworks(tmp_path) -> None:
    output = handle_compliance(state_dir=str(tmp_path))
    assert "ISO 42001" in output
    assert "SOC 2" in output
    assert "Overall coverage:" in output
    assert "coverage=" in output


def test_cli_main_requires_a_flag() -> None:
    assert main([]) == 1


def test_cli_main_audit_runs() -> None:
    assert main(["--audit"]) == 0


def test_cli_report_writes_json(tmp_path) -> None:
    report_path = os.path.join(str(tmp_path), "security_report.json")
    assert main(["--audit", "--report", report_path]) == 0
    assert os.path.exists(report_path)
    import json

    with open(report_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    assert "audit" in payload
    assert "penetration" in payload
    assert "compliance" in payload
    assert "overall_score" in payload["audit"]
    assert "overall_passed" in payload["penetration"]
    assert "overall_coverage" in payload["compliance"]
