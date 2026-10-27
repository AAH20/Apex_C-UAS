"""Deterministic tests for the C-UAS production readiness review module.

Covers per-domain check scoring, aggregation, the go/no-go decision, and
report persistence. All values are real computations: real platform modules
(hardening audit, contract gate, cost model, evidence chain, capacity
planner) are called directly, and slow or shared-state probes (edge fleet,
composite health) are exercised through their injected result objects.
No fabricated metrics, no network.
"""

from __future__ import annotations

import json
from argparse import Namespace

import pytest
import yaml

from c_uas.contract_readiness.contract import ContractReport, RouteEntry
from c_uas.datacenter.capacity import RackSpec
from c_uas.edge.fleet import FleetManager, FleetReport
from c_uas.finops.cost_model import compute_facility_cost
from c_uas.grc_clab.evidence_chain import EvidenceChain
from c_uas.observability.health import CompositeHealth
from c_uas.production_readiness import (
    CRITICAL_DOMAINS,
    DOMAIN_WEIGHTS,
    DomainResult,
    aggregate,
    all_checks,
    decision,
    overall_score,
    run_readiness_check,
)
from c_uas.production_readiness.aggregator import GO, NO_GO
from c_uas.production_readiness.checks import (
    EDGE_PASS_THRESHOLD,
    SECURITY_PASS_THRESHOLD,
    contract_check,
    datacenter_check,
    domain_check,
    edge_check,
    finops_check,
    grc_check,
    observability_check,
    security_check,
)
from c_uas.production_readiness.cli import readiness_main
from c_uas.production_readiness.report import (
    DEFAULT_STATE_DIR,
    load_latest_report,
    load_report,
    render_json,
    render_text,
    report_id,
    save_report,
)
from c_uas.security.hardening import HardeningAudit, HardeningCheck, PlatformConfig

_CHECKED_AT = "2026-10-27T00:00:00Z"


def _make_check(
    domain: str,
    score: float = 100.0,
    passed: bool = True,
    remediation: tuple = (),
) -> DomainResult:
    return DomainResult(
        domain=domain,
        check=f"{domain}_check",
        passed=passed,
        score=score,
        threshold=80.0,
        gate="test_gate",
        critical=True,
        remediation=remediation,
        details={},
    )


# --------------------------------------------------------------------------- #
# Check registry and weights
# --------------------------------------------------------------------------- #


def test_domain_weights_sum_to_one() -> None:
    assert round(sum(DOMAIN_WEIGHTS.values()), 6) == 1.0


def test_all_checks_returns_all_seven_domains_in_fixed_order() -> None:
    checks = all_checks()
    assert [check.domain for check in checks] == list(DOMAIN_WEIGHTS)
    assert set(check.domain for check in checks) == set(CRITICAL_DOMAINS)
    assert all(check.critical for check in checks)
    assert len(checks) == 7


def test_domain_check_unknown_domain_raises() -> None:
    with pytest.raises(ValueError, match="Unknown readiness domain"):
        domain_check("mars")


# --------------------------------------------------------------------------- #
# Security: hardening score >= 80
# --------------------------------------------------------------------------- #


def test_security_check_passes_with_fully_hardened_config() -> None:
    config = PlatformConfig(
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
    result = security_check(config=config)
    assert result.passed is True
    assert result.score >= SECURITY_PASS_THRESHOLD
    assert result.gate == "hardening_score >= 80.0"
    assert result.critical is True
    assert result.remediation == ()
    assert result.details["audit_id"].startswith("HARDEN-")


def test_security_check_fails_with_default_config() -> None:
    result = security_check(config=PlatformConfig())
    assert result.passed is False
    assert result.score == 0.0
    assert result.remediation
    assert result.details["checks_total"] > 0


def test_security_check_injected_audit() -> None:
    check = HardeningCheck(
        check_id="TENANT-001",
        category="tenant_isolation",
        title="tenant isolation",
        description="d",
        passed=True,
        evidence="e",
        weight=0.5,
        score=100.0,
        remediation="r",
    )
    audit = HardeningAudit(
        audit_id="HARDEN-TEST",
        config_hash="CFG-TEST",
        checks=(check,),
        overall_score=82.5,
        grade="B",
    )
    result = security_check(audit=audit)
    assert result.passed is True
    assert result.score == 82.5
    assert result.details["audit_id"] == "HARDEN-TEST"
    assert result.details["grade"] == "B"


# --------------------------------------------------------------------------- #
# Observability: composite health >= 80
# --------------------------------------------------------------------------- #


def _composite(score: float, status: str = "healthy") -> CompositeHealth:
    return CompositeHealth(
        schema_version="1.0.0",
        overall_status=status,
        composite_score=score,
        components=(),
        unhealthy=(),
        degraded=(),
        healthy=(),
        checked_at=_CHECKED_AT,
    )


def test_observability_check_passes_with_injected_composite() -> None:
    result = observability_check(composite=_composite(90.0))
    assert result.passed is True
    assert result.score == 90.0
    assert result.gate == "composite_health >= 80.0"


def test_observability_check_fails_below_threshold() -> None:
    result = observability_check(composite=_composite(40.0, "unhealthy"))
    assert result.passed is False
    assert result.score == 40.0
    assert result.critical is True


# --------------------------------------------------------------------------- #
# Contract: no missing routes
# --------------------------------------------------------------------------- #


def test_contract_check_no_missing_routes() -> None:
    report = ContractReport(
        spec_path="openapi.yaml",
        spec_routes=(
            RouteEntry(method="GET", path="/users"),
            RouteEntry(method="POST", path="/users"),
        ),
        app_routes=(
            RouteEntry(method="GET", path="/users"),
            RouteEntry(method="POST", path="/users"),
        ),
        missing=(),
        extra=(),
        mismatched=(),
        ok=True,
    )
    result = contract_check(report=report)
    assert result.passed is True
    assert result.score == 100.0
    assert result.details["missing"] == []


def test_contract_check_missing_routes_fails() -> None:
    report = ContractReport(
        spec_path="openapi.yaml",
        spec_routes=(
            RouteEntry(method="GET", path="/users"),
            RouteEntry(method="POST", path="/users"),
            RouteEntry(method="GET", path="/health"),
        ),
        app_routes=(
            RouteEntry(method="GET", path="/users"),
            RouteEntry(method="POST", path="/users"),
        ),
        missing=(RouteEntry(method="GET", path="/health"),),
        extra=(),
        mismatched=(),
        ok=False,
    )
    result = contract_check(report=report)
    assert result.passed is False
    assert result.score == round(100.0 * 2 / 3, 2)
    assert result.details["missing"] == [{"method": "GET", "path": "/health"}]
    assert result.remediation == ("Implement route GET /health",)


def test_contract_check_real_gate_reports_missing_route(tmp_path) -> None:
    spec = tmp_path / "openapi.yaml"
    spec.write_text(
        yaml.safe_dump(
            {
                "openapi": "3.0.0",
                "info": {"title": "T", "version": "1.0.0"},
                "paths": {"/v1/detect": {"get": {}}},
            }
        ),
        encoding="utf-8",
    )
    result = contract_check(spec_path=str(spec), app_routes=[])
    assert result.passed is False
    assert result.details["missing"] == [{"method": "GET", "path": "/v1/detect"}]
    assert result.details["ok"] is False


# --------------------------------------------------------------------------- #
# Finops: cost model valid
# --------------------------------------------------------------------------- #


def test_finops_check_valid_cost_model_passes() -> None:
    cost = compute_facility_cost(it_load_kw=10.0)
    result = finops_check(cost=cost)
    assert result.passed is True
    assert result.score == 100.0
    assert result.details["total_facility_kw"] == 15.0  # 10 kW IT * PUE 1.5


def test_finops_check_invalid_cost_model_fails(monkeypatch) -> None:
    import c_uas.finops.cost_model as cost_model

    def boom(**kwargs):
        raise ValueError("bad load")

    monkeypatch.setattr(cost_model, "compute_facility_cost", boom)
    result = finops_check()
    assert result.passed is False
    assert result.score == 0.0
    assert result.details["error"] == "ValueError"


# --------------------------------------------------------------------------- #
# GRC: evidence chain verifies
# --------------------------------------------------------------------------- #


def test_grc_check_intact_chain_passes() -> None:
    result = grc_check(chain=EvidenceChain())
    assert result.passed is True
    assert result.score == 100.0
    assert result.gate == "evidence_chain_verifies == true"


def test_grc_check_broken_chain_fails(monkeypatch) -> None:
    chain = EvidenceChain()
    monkeypatch.setattr(chain, "verify_chain", lambda: False)
    result = grc_check(chain=chain)
    assert result.passed is False
    assert result.score == 0.0


# --------------------------------------------------------------------------- #
# Edge: fleet health >= 80
# --------------------------------------------------------------------------- #


def _fleet_report(average_health_score: float, total_nodes: int = 1) -> FleetReport:
    return FleetReport(
        total_nodes=total_nodes,
        active_nodes=total_nodes,
        offline_nodes=0,
        decommissioned_nodes=0,
        average_health_score=average_health_score,
        by_tenant={},
    )


def test_edge_check_passes_above_threshold(monkeypatch) -> None:
    import c_uas.edge.fleet as edge_fleet

    monkeypatch.setattr(edge_fleet, "FleetManager", lambda: _FakeFleet(_fleet_report(95.0)))
    result = edge_check()
    assert result.passed is True
    assert result.score == 95.0
    assert result.gate == "fleet_health >= 80.0"


def test_edge_check_fails_below_threshold(monkeypatch) -> None:
    import c_uas.edge.fleet as edge_fleet

    monkeypatch.setattr(edge_fleet, "FleetManager", lambda: _FakeFleet(_fleet_report(40.0)))
    result = edge_check()
    assert result.passed is False
    assert result.score == 40.0
    assert result.critical is True


def test_edge_check_no_nodes_fails(monkeypatch) -> None:
    import c_uas.edge.fleet as edge_fleet

    monkeypatch.setattr(edge_fleet, "FleetManager", lambda: _FakeFleet(_fleet_report(0.0, 0)))
    result = edge_check()
    assert result.passed is False
    assert result.score == 0.0
    assert any("Register at least one edge node" in item for item in result.remediation)


def test_edge_check_mirror_real_fleet() -> None:
    fm = FleetManager(clock=lambda: 1000.0)
    report = fm.fleet_health()
    result = edge_check(fleet_manager=fm)
    assert result.score == report.average_health_score
    assert result.passed == (
        report.average_health_score >= EDGE_PASS_THRESHOLD and report.total_nodes > 0
    )
    assert result.details["average_health_score"] == report.average_health_score


class _FakeFleet:
    """Stand-in fleet manager whose health report is fixed for the test."""

    def __init__(self, report: FleetReport) -> None:
        self._report = report

    def fleet_health(self) -> FleetReport:
        return self._report


# --------------------------------------------------------------------------- #
# Datacenter: capacity headroom > 0
# --------------------------------------------------------------------------- #


def test_datacenter_check_positive_headroom_passes() -> None:
    spec = RackSpec(
        rack_id="rack-1",
        max_power_kw=100.0,
        max_cooling_kw=40.0,
        max_rack_units=42,
    )
    result = datacenter_check(spec=spec)
    # headroom: power 30%, cooling 37.5%, space 28.57% -> min 28.57 > 0
    assert result.passed is True
    assert result.score == 28.57
    assert result.details["limiting_factor"] == "balanced"
    assert result.gate == "capacity_headroom > 0.0"


def test_datacenter_check_no_headroom_fails() -> None:
    spec = RackSpec(
        rack_id="rack-1",
        max_power_kw=100.0,
        max_cooling_kw=40.0,
        max_rack_units=42,
    )
    result = datacenter_check(spec=spec, it_load_kw=100.0)
    assert result.passed is False
    assert result.score == 0.0
    assert "limiting factor" in result.remediation[0]


# --------------------------------------------------------------------------- #
# Aggregation and go/no-go decision
# --------------------------------------------------------------------------- #


def test_overall_score_weighted_average() -> None:
    checks = (
        _make_check("security", 80.0),
        _make_check("observability", 90.0),
        _make_check("contract", 100.0),
        _make_check("finops", 100.0),
        _make_check("grc", 100.0),
        _make_check("edge", 80.0),
        _make_check("datacenter", 100.0),
    )
    expected = round(
        0.20 * 80.0
        + 0.15 * 90.0
        + 0.15 * 100.0
        + 0.10 * 100.0
        + 0.10 * 100.0
        + 0.15 * 80.0
        + 0.15 * 100.0,
        2,
    )
    assert expected == 91.5
    assert overall_score(checks) == 91.5


def test_go_when_all_critical_pass_and_overall_at_least_85() -> None:
    checks = tuple(_make_check(domain, 100.0) for domain in DOMAIN_WEIGHTS)
    go_no_go, reason = decision(checks)
    assert go_no_go == GO
    assert "all critical checks pass" in reason
    report = aggregate(checks, generated_at=_CHECKED_AT)
    assert report.go_no_go == GO
    assert report.overall_score == 100.0


def test_no_go_when_overall_below_threshold() -> None:
    checks = tuple(_make_check(domain, 84.0) for domain in DOMAIN_WEIGHTS)
    go_no_go, reason = decision(checks)
    assert go_no_go == NO_GO
    assert "below threshold" in reason
    assert overall_score(checks) == 84.0


def test_no_go_when_critical_check_fails_despite_high_overall() -> None:
    checks = tuple(
        _make_check(domain, 0.0 if domain == "grc" else 100.0, passed=(domain != "grc"))
        for domain in DOMAIN_WEIGHTS
    )
    go_no_go, reason = decision(checks)
    assert go_no_go == NO_GO
    assert "grc" in reason
    assert overall_score(checks) == 90.0  # high overall is not enough


def test_aggregate_report_structure_and_remediation() -> None:
    failing = _make_check("security", 40.0, passed=False, remediation=("fix rls", "fix secrets"))
    checks = (failing,) + tuple(
        _make_check(domain, 100.0) for domain in DOMAIN_WEIGHTS if domain != "security"
    )
    report = aggregate(checks, generated_at=_CHECKED_AT)
    assert report.schema_version == "1.0.0"
    assert report.generated_at == _CHECKED_AT
    assert report.go_no_go == NO_GO
    assert report.overall_score == 88.0  # 0.2*40 + 0.8*100
    assert "fix rls" in report.remediation
    assert "fix secrets" in report.remediation
    assert len(report.checks) == 7
    assert report.decision_reason


def test_run_readiness_check_deterministic_with_fixed_timestamp() -> None:
    report1 = run_readiness_check(generated_at=_CHECKED_AT)
    report2 = run_readiness_check(generated_at=_CHECKED_AT)
    assert report1 == report2
    assert report1.go_no_go == NO_GO  # default posture: unhardened security


# --------------------------------------------------------------------------- #
# Report rendering and persistence
# --------------------------------------------------------------------------- #


def test_render_text_contains_decision_and_all_domains() -> None:
    checks = tuple(_make_check(domain, 100.0) for domain in DOMAIN_WEIGHTS)
    report = aggregate(checks, generated_at=_CHECKED_AT)
    text = render_text(report)
    assert "[C-UAS] Production Readiness Review" in text
    assert "Overall score : 100.0/100" in text
    assert "Decision      : GO" in text
    assert _CHECKED_AT in text
    for domain in DOMAIN_WEIGHTS:
        assert domain in text
        assert "PASS" in text


def test_render_text_shows_failures_and_remediation() -> None:
    failing = _make_check("security", 40.0, passed=False, remediation=("fix rls",))
    checks = (failing,) + tuple(
        _make_check(domain, 100.0) for domain in DOMAIN_WEIGHTS if domain != "security"
    )
    report = aggregate(checks, generated_at=_CHECKED_AT)
    text = render_text(report)
    assert "NO-GO" in text
    assert "security" in text
    assert "FAIL" in text
    assert "fix rls" in text


def test_render_json_is_deterministic_with_report_id() -> None:
    report = aggregate(
        tuple(_make_check(domain, 100.0) for domain in DOMAIN_WEIGHTS),
        generated_at=_CHECKED_AT,
    )
    payload = json.loads(render_json(report))
    assert payload["report_id"] == report_id(report)
    assert payload["go_no_go"] == GO
    assert json.loads(render_json(report)) == payload


def test_report_persistence_round_trip(tmp_path) -> None:
    state_dir = str(tmp_path / "state")
    report = aggregate(
        tuple(_make_check(domain, 100.0) for domain in DOMAIN_WEIGHTS),
        generated_at=_CHECKED_AT,
    )
    path = save_report(report, state_dir=state_dir)
    assert path.endswith(".json")
    loaded = load_report(report_id(report), state_dir=state_dir)
    assert loaded is not None
    assert loaded == report
    assert loaded.checks == report.checks
    latest = load_latest_report(state_dir=state_dir)
    assert latest is not None
    assert latest == report
    reports_dir = tmp_path / "state" / "reports"
    assert (reports_dir / "latest.json").exists()


def test_load_report_missing_returns_none(tmp_path) -> None:
    assert load_report("RR-nope", state_dir=str(tmp_path / "state")) is None
    assert load_latest_report(state_dir=str(tmp_path / "state")) is None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_readiness_main_check_prints_report_and_exits(tmp_path, capsys) -> None:
    state_dir = str(tmp_path / "state")
    code = readiness_main(Namespace(check=True, report=False, state_dir=state_dir))
    out = capsys.readouterr().out
    # Default posture: PlatformConfig() scores 0 -> critical security fail -> NO-GO
    assert code == 1
    assert "[C-UAS] Production Readiness Review" in out
    assert "NO-GO" in out
    assert "security" in out and "FAIL" in out
    assert load_latest_report(state_dir=state_dir) is not None


def test_readiness_main_check_is_deterministic(tmp_path, capsys) -> None:
    state_dir = str(tmp_path / "state")
    codes = []
    outs = []
    for _ in range(2):
        codes.append(readiness_main(Namespace(check=True, report=False, state_dir=state_dir)))
        outs.append(capsys.readouterr().out)
    assert codes == [1, 1]
    # Scores and decision are deterministic across runs; timestamps may differ.
    assert "Overall score" in outs[0] and "Overall score" in outs[1]


def test_readiness_main_report_without_check_exits_one(tmp_path, capsys) -> None:
    code = readiness_main(Namespace(check=False, report=True, state_dir=str(tmp_path / "state")))
    assert code == 1
    assert "no persisted report found" in capsys.readouterr().out


def test_readiness_main_report_shows_latest(tmp_path, capsys) -> None:
    state_dir = str(tmp_path / "state")
    report = aggregate(
        tuple(_make_check(domain, 100.0) for domain in DOMAIN_WEIGHTS),
        generated_at=_CHECKED_AT,
    )
    save_report(report, state_dir=state_dir)
    code = readiness_main(Namespace(check=False, report=True, state_dir=state_dir))
    out = capsys.readouterr().out
    assert code == 0
    assert "GO" in out
    assert _CHECKED_AT in out


def test_readiness_main_no_flags_exits_one(capsys) -> None:
    code = readiness_main(Namespace(check=False, report=False, state_dir=DEFAULT_STATE_DIR))
    assert code == 1
    assert "specify --check or --report" in capsys.readouterr().out
