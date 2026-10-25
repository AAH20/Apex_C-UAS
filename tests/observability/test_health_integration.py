"""
Deterministic cross-module health integration tests.

Covers the real-component health probes (performance scheduler Pk, security
hardening score, gateway circuit-breaker state, websockets connection count,
chaos resilience score, edge fleet health + zero-trust compliance), the
weighted-average composite score, the unhealthy-components list (score < 80),
state persistence under ~/.c-uas-platform/observability/health/, and the obs
--health CLI. No mocks, no fabricated metrics.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from c_uas.edge.fleet import FleetManager
from c_uas.observability.cli import handle_health
from c_uas.observability.health import (
    HealthStatus,
    new_aggregator,
    probe_chaos,
    probe_edge,
    probe_gateway,
    probe_performance,
    probe_security,
    probe_websockets,
    run_all_probes,
)
from c_uas.security.hardening import PlatformConfig

UNHEALTHY_SCORE_THRESHOLD = 80.0


# --------------------------------------------------------------------------- #
# Performance probe (scheduler Pk)
# --------------------------------------------------------------------------- #


def test_probe_performance_real_scheduler_pk() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_perf")
    health = probe_performance(agg)
    assert health.component == "performance"
    # 5 tracks, scheduler engages 4 (track 3 misses its 20s deadline):
    # expected_kills = 0.9 + 0.8 + 0.7 + 0.55 = 2.95, total Pk = 4.0
    assert health.details["expected_kills"] == 2.95
    assert health.details["total_pk"] == 4.0
    assert health.details["engaged_targets"] == 4
    assert health.details["leaked_targets"] == 1
    assert health.score == 73.75
    assert 0.0 <= health.score <= 100.0
    assert health.status == HealthStatus.from_score(health.score)
    assert health.status == HealthStatus.UNHEALTHY  # below 80 threshold


def test_probe_performance_deterministic() -> None:
    h1 = probe_performance(new_aggregator(state_dir="/tmp/htest_perf_det1"))
    h2 = probe_performance(new_aggregator(state_dir="/tmp/htest_perf_det2"))
    assert h1.score == h2.score == 73.75
    assert h1.details == h2.details


def test_probe_performance_all_engaged_is_healthy() -> None:
    # Widely spaced arrivals, pk_base 1.0: all five targets engaged before
    # their deadlines. Effective Pk with thermal bloom: 1.0, 0.95, 0.9,
    # 0.85, 0.8 -> 4.5 / 5.0 = 90.0.
    from c_uas.engagement.scheduler import DroneTrack

    tracks = tuple(
        DroneTrack(track_id=i, arrival_time_s=4.0 + i * 5.5, pk_base=1.0, priority=3)
        for i in range(5)
    )
    agg = new_aggregator(state_dir="/tmp/htest_perf_all")
    health = probe_performance(agg, tracks=tracks, time_limit_s=100.0)
    assert health.details["engaged_targets"] == 5
    assert health.details["leaked_targets"] == 0
    assert health.score == 90.0
    assert health.status == HealthStatus.HEALTHY


# --------------------------------------------------------------------------- #
# Security probe (hardening audit)
# --------------------------------------------------------------------------- #


def test_probe_security_compliant_config_is_healthy() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_sec_ok")
    config = PlatformConfig(
        tenant_isolation_enforced=True,
        tenant_scoped_queries=True,
        cross_tenant_access_blocked=True,
        rls_enabled=True,
        rls_applied_to_all_tables=True,
        secret_rotation_days=30,
        secrets_in_environment=True,
        no_plaintext_secrets_in_code=True,
        key_management_service=True,
        zero_trust_network_policies=True,
        mtls_enforced=True,
        default_deny_ingress=True,
        network_segmentation=True,
        audit_logging_enabled=True,
        audit_trail_retention_days=90,
        audit_logs_immutable=True,
        audit_events_cover_authz=True,
    )
    health = probe_security(agg, config=config)
    assert health.score == 100.0
    assert health.status == HealthStatus.HEALTHY
    assert health.details["grade"] == "A"
    assert health.details["checks_passed"] == health.details["checks_total"]


def test_probe_security_default_config_is_unknown() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_sec_default")
    health = probe_security(agg)
    assert health.score == 0.0
    assert health.status == HealthStatus.UNKNOWN
    assert health.details["checks_passed"] == 0


def test_probe_security_partial_config_is_deterministic() -> None:
    # Only the tenant-isolation category passes (weight 0.25, both checks pass).
    agg = new_aggregator(state_dir="/tmp/htest_sec_partial")
    config = PlatformConfig(
        tenant_isolation_enforced=True,
        tenant_scoped_queries=True,
        cross_tenant_access_blocked=True,
    )
    health = probe_security(agg, config=config)
    assert health.score == 25.0
    assert health.status == HealthStatus.UNHEALTHY  # below 80

    # Deterministic: same configuration -> same score.
    agg2 = new_aggregator(state_dir="/tmp/htest_sec_partial2")
    health2 = probe_security(agg2, config=config)
    assert health2.score == health.score


# --------------------------------------------------------------------------- #
# Gateway probe (circuit breaker state)
# --------------------------------------------------------------------------- #


def test_probe_gateway_all_circuits_closed_is_healthy() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_gw_ok")
    health = probe_gateway(agg)
    assert health.score == 100.0
    assert health.status == HealthStatus.HEALTHY
    assert health.details["closed_circuits"] == 3
    assert health.details["total_circuits"] == 3
    assert all(cs["circuit"] == "closed" for cs in health.details["backends"].values())


def test_probe_gateway_tripped_circuit_is_unhealthy() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_gw_trip")
    health = probe_gateway(agg, trip_backend="tracking-1")
    assert health.score == 66.67  # 2 of 3 circuits closed
    assert health.status == HealthStatus.UNHEALTHY
    states = {bid: cs["circuit"] for bid, cs in health.details["backends"].items()}
    assert states["tracking-1"] == "open"
    assert states["detection-1"] == "closed"
    assert states["engagement-1"] == "closed"


# --------------------------------------------------------------------------- #
# Websockets probe (connection count)
# --------------------------------------------------------------------------- #


def test_probe_websockets_connection_count() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_ws")
    health = probe_websockets(agg)
    assert health.component == "websockets"
    assert health.score == 100.0
    assert health.status == HealthStatus.HEALTHY
    assert health.details["connected_clients"] == 0
    assert health.details["max_connections"] == 1024


# --------------------------------------------------------------------------- #
# Chaos probe (resilience score)
# --------------------------------------------------------------------------- #


def test_probe_chaos_resilience_is_deterministic() -> None:
    h1 = probe_chaos(new_aggregator(state_dir="/tmp/htest_chaos1"))
    h2 = probe_chaos(new_aggregator(state_dir="/tmp/htest_chaos2"))
    assert h1.score == h2.score == 68.0  # 17 of 25 probes succeed under loss fault
    assert h1.details["probes_total"] == 25
    assert h1.details["probes_succeeded"] == 17
    assert h1.details["probes_failed"] == 8
    assert h1.details["failure_modes"] == ["RuntimeError"]
    assert 0.0 <= h1.score <= 100.0


def test_probe_chaos_total_failure_is_zero() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_chaos_zero")
    health = probe_chaos(agg, fault_severity=1.0, fault_seed=5)
    assert health.score == 0.0
    assert health.status == HealthStatus.UNKNOWN
    assert health.details["probes_succeeded"] == 0


# --------------------------------------------------------------------------- #
# Edge probe (fleet health + zero-trust compliance)
# --------------------------------------------------------------------------- #


def _empty_fleet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from c_uas.edge import fleet as edge_fleet_module

    fleet_dir = tmp_path / "fleet"
    fleet_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(edge_fleet_module, "FLEET_DIR", fleet_dir)


def test_probe_edge_empty_fleet_is_healthy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _empty_fleet(tmp_path, monkeypatch)
    agg = new_aggregator(state_dir="/tmp/htest_edge_empty")
    health = probe_edge(agg)
    assert health.score == 100.0  # 0.5 * 100 (no nodes) + 0.5 * 100 (zero trust)
    assert health.status == HealthStatus.HEALTHY
    assert health.details["fleet_total_nodes"] == 0
    assert health.details["zero_trust_score"] == 100.0


def test_probe_edge_nodes_zero_trust(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _empty_fleet(tmp_path, monkeypatch)

    fixed_now = 1_700_000_000.0
    mgr = FleetManager(clock=lambda: fixed_now)
    mgr.register_node("n-1", "tenant-a", "site-1", heartbeat_interval_s=60.0)
    mgr.register_node("n-2", "tenant-b", "site-2", heartbeat_interval_s=60.0)
    mgr.heartbeat("n-1", timestamp=fixed_now)
    mgr.heartbeat("n-2", timestamp=fixed_now)

    agg = new_aggregator(state_dir="/tmp/htest_edge_nodes")
    health = probe_edge(agg, fleet_manager=mgr)
    assert health.details["fleet_total_nodes"] == 2
    assert health.details["fleet_active_nodes"] == 2
    assert health.details["fleet_average_health_score"] == 100.0
    assert health.details["by_tenant"] == {"tenant-a": 1, "tenant-b": 1}
    assert health.score == 100.0
    assert health.status == HealthStatus.HEALTHY


# --------------------------------------------------------------------------- #
# Composite: weighted average, unhealthy list (< 80), status rollup
# --------------------------------------------------------------------------- #


def test_composite_weighted_average() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_comp_avg")
    agg.check_component("performance", HealthStatus.HEALTHY, 100.0, {})
    agg.check_component("security", HealthStatus.UNHEALTHY, 50.0, {})
    composite = agg.composite()
    assert composite.composite_score == round((100.0 + 50.0) / 2.0, 2) == 75.0


def test_composite_unhealthy_list_below_80() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_comp_unhealthy")
    agg.check_component("performance", HealthStatus.HEALTHY, 90.0, {})
    agg.check_component("security", HealthStatus.UNHEALTHY, 75.0, {})
    agg.check_component("gateway", HealthStatus.UNHEALTHY, 60.0, {})
    composite = agg.composite()
    assert composite.composite_score == 75.0
    assert composite.overall_status == HealthStatus.UNHEALTHY
    assert composite.unhealthy == ("gateway", "security")  # score < 80
    assert composite.degraded == ()
    assert composite.healthy == ("performance",)
    assert agg.unhealthy_components() == ["gateway", "security"]


def test_composite_degraded_band() -> None:
    # 80 <= score < 90 is degraded, not unhealthy.
    agg = new_aggregator(state_dir="/tmp/htest_comp_degraded")
    agg.check_component("edge", HealthStatus.DEGRADED, 85.0, {})
    composite = agg.composite()
    assert composite.composite_score == 85.0
    assert composite.overall_status == HealthStatus.DEGRADED
    assert composite.degraded == ("edge",)
    assert composite.unhealthy == ()


def test_composite_all_healthy() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_comp_healthy")
    for component in ("performance", "security", "gateway", "websockets", "chaos", "edge"):
        agg.check_component(component, HealthStatus.HEALTHY, 95.0, {})
    composite = agg.composite()
    assert composite.composite_score == 95.0
    assert composite.overall_status == HealthStatus.HEALTHY
    assert composite.unhealthy == ()
    assert len(composite.healthy) == 6


def test_composite_all_unknown() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_comp_unknown")
    composite = agg.composite()
    assert composite.composite_score == 0.0
    assert composite.overall_status == HealthStatus.UNKNOWN
    assert composite.unhealthy == ()


def test_composite_score_always_in_bounds() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_comp_bounds")
    agg.check_component("performance", HealthStatus.HEALTHY, 100.0, {})
    agg.check_component("security", HealthStatus.UNHEALTHY, 0.5, {})
    composite = agg.composite()
    assert 0.0 <= composite.composite_score <= 100.0


def test_from_score_thresholds() -> None:
    assert HealthStatus.from_score(100.0) == HealthStatus.HEALTHY
    assert HealthStatus.from_score(90.0) == HealthStatus.HEALTHY
    assert HealthStatus.from_score(89.99) == HealthStatus.DEGRADED
    assert HealthStatus.from_score(80.0) == HealthStatus.DEGRADED
    assert HealthStatus.from_score(79.99) == HealthStatus.UNHEALTHY
    assert HealthStatus.from_score(1.0) == HealthStatus.UNHEALTHY
    assert HealthStatus.from_score(0.0) == HealthStatus.UNKNOWN


# --------------------------------------------------------------------------- #
# Real-probe aggregation + persistence
# --------------------------------------------------------------------------- #


def test_run_all_probes_covers_all_components() -> None:
    agg = new_aggregator(state_dir="/tmp/htest_all_probes")
    results = run_all_probes(agg)
    assert {r.component for r in results} == {
        "performance",
        "security",
        "gateway",
        "websockets",
        "chaos",
        "edge",
    }
    composite = agg.composite()
    assert len(composite.components) == 6
    assert 0.0 <= composite.composite_score <= 100.0
    assert isinstance(composite.unhealthy, tuple)


def test_state_persisted_under_observability_health_dir(tmp_path: Path) -> None:
    state_dir = tmp_path / "observability" / "health"
    agg = new_aggregator(state_dir=str(state_dir))
    agg.check_component("security", HealthStatus.UNHEALTHY, 40.0, {"grade": "D"})
    composite = agg.composite()
    component_file = state_dir / "security.json"
    composite_file = state_dir / "composite.json"
    assert component_file.exists()
    assert composite_file.exists()
    data = json.loads(component_file.read_text())
    assert data["component"] == "security"
    assert data["score"] == 40.0
    composite_data = json.loads(composite_file.read_text())
    assert composite_data["composite_score"] == composite.composite_score
    assert composite_data["unhealthy"] == ["security"]  # JSON serializes tuples as lists


# --------------------------------------------------------------------------- #
# CLI --health uses real probes
# --------------------------------------------------------------------------- #


def test_cli_health_uses_real_probes() -> None:
    out1 = handle_health()
    out2 = handle_health()
    assert out1 == out2  # deterministic
    assert "[C-UAS] Composite Health:" in out1
    assert "Composite score:" in out1
    # Unhealthy components are listed by name in the text render.
    assert "Unhealthy components:" in out1
    import re

    match = re.search(r"Composite score:\s*([\d.]+)/100", out1)
    assert match is not None
    assert 0.0 <= float(match.group(1)) <= 100.0

    # The CLI runs the same real probes and registers all six components.
    agg = new_aggregator(state_dir="/tmp/htest_cli_probes")
    results = run_all_probes(agg)
    assert {r.component for r in results} == {
        "performance",
        "security",
        "gateway",
        "websockets",
        "chaos",
        "edge",
    }
    assert all(0.0 <= r.score <= 100.0 for r in results)
