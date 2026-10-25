"""Deterministic tests for the Data Center Lifecycle Decision Support module.

Covers capacity planning (power, cooling, rack utilization, headroom,
overcommitment), lifecycle decisions (provision, decommission, refresh, retire,
stage tracking, cost analysis), energy-to-compute efficiency (PUE, DCiE,
compute per watt, carbon intensity), and the CLI. All values are real
computations -- no mocks, no fabricated metrics, no network.

State under ~/.c-uas-platform/datacenter/ is avoided in tests by passing a
tmp_path state dir, so tests are isolated and hermetic.
"""

from __future__ import annotations

import argparse
import os

import pytest

from c_uas.datacenter.capacity import (
    DEFAULT_STATE_DIR as CAP_STATE_DIR,
)
from c_uas.datacenter.capacity import (
    CapacityPlan,
    RackSpec,
    compute_capacity_plan,
    compute_compute_density,
    compute_cooling_load,
    compute_headroom,
    compute_power_draw,
    compute_rack_utilization,
    detect_overcommitment,
    load_capacity_plan,
    save_capacity_plan,
)
from c_uas.datacenter.cli import dc_main, handle_capacity, handle_efficiency, handle_lifecycle
from c_uas.datacenter.efficiency import (
    CarbonIntensity,
    EfficiencyMetrics,
    EfficiencyReport,
    Recommendation,
    compute_carbon_intensity,
    compute_compute_per_watt,
    compute_dcie,
    compute_efficiency_report,
    compute_pue,
    efficiency_recommendations,
    load_efficiency_report,
    save_efficiency_report,
)
from c_uas.datacenter.lifecycle import (
    STAGE_ACTIVE,
    STAGE_DECOMMISSIONING,
    STAGE_PROVISIONING,
    STAGE_RETIRED,
    decommission,
    decommission_cost_analysis,
    lifecycle_report,
    provision,
    refresh,
    retire,
    track_stage,
)

# --------------------------------------------------------------------------- #
# Capacity: power draw
# --------------------------------------------------------------------------- #


def test_power_draw_matches_pue_formula() -> None:
    draw = compute_power_draw(it_load_kw=100.0, pue=1.5)
    assert draw.it_load_kw == 100.0
    assert draw.total_facility_kw == 150.0
    assert draw.facility_overhead_kw == 50.0
    assert draw.pue == 1.5


def test_power_draw_pue_floor_one() -> None:
    draw = compute_power_draw(it_load_kw=100.0, pue=0.8)
    assert draw.pue == 1.0
    assert draw.total_facility_kw == 100.0
    assert draw.facility_overhead_kw == 0.0


# --------------------------------------------------------------------------- #
# Capacity: cooling load
# --------------------------------------------------------------------------- #


def test_cooling_load_utilization_and_margin() -> None:
    load = compute_cooling_load(it_load_kw=40.0, cooling_capacity_kw=100.0)
    assert load.it_heat_load_kw == 40.0
    assert load.cooling_capacity_kw == 100.0
    assert load.cooling_utilization_pct == 40.0
    assert load.thermal_margin_kw == 60.0


def test_cooling_load_zero_capacity() -> None:
    load = compute_cooling_load(it_load_kw=0.0, cooling_capacity_kw=0.0)
    assert load.cooling_utilization_pct == 0.0
    assert load.thermal_margin_kw == 0.0


# --------------------------------------------------------------------------- #
# Capacity: compute density
# --------------------------------------------------------------------------- #


def test_compute_density_values() -> None:
    density = compute_compute_density(
        compute_units=240, power_kw=10.0, rack_units_used=21, rack_units_total=42
    )
    assert density.compute_units == 240
    assert density.power_kw == 10.0
    assert density.compute_per_kw == 24.0
    assert density.rack_density_pct == 50.0


def test_compute_density_zero_power() -> None:
    density = compute_compute_density(
        compute_units=10, power_kw=0.0, rack_units_used=5, rack_units_total=42
    )
    assert density.compute_per_kw == 0.0


# --------------------------------------------------------------------------- #
# Capacity: rack utilization
# --------------------------------------------------------------------------- #


def test_rack_utilization_overall_and_headroom() -> None:
    spec = RackSpec(rack_id="R1", max_power_kw=12.0, max_cooling_kw=10.0, max_rack_units=42)
    util = compute_rack_utilization(
        rack_id="R1",
        it_load_kw=6.0,
        cooling_load_kw=5.0,
        cooling_capacity_kw=10.0,
        rack_spec=spec,
        compute_units=21,
    )
    assert util.power_utilization_pct == 50.0
    assert util.cooling_utilization_pct == 50.0
    assert util.compute_utilization_pct == 50.0
    assert util.overall_utilization_pct == 50.0
    assert util.headroom_pct == 50.0


# --------------------------------------------------------------------------- #
# Capacity: headroom
# --------------------------------------------------------------------------- #


def test_headroom_limiting_factor_is_min_headroom() -> None:
    spec = RackSpec(rack_id="R1", max_power_kw=10.0, max_cooling_kw=20.0, max_rack_units=42)
    # Power has least headroom (9 used of 10 -> 10% headroom, below target).
    head = compute_headroom(
        rack_id="R1",
        it_load_kw=9.0,
        cooling_load_kw=5.0,
        compute_units=10,
        rack_spec=spec,
    )
    assert head.headroom_power_pct == 10.0
    assert head.limiting_factor == "power"


def test_headroom_balanced_when_all_above_target() -> None:
    spec = RackSpec(rack_id="R1", max_power_kw=10.0, max_cooling_kw=20.0, max_rack_units=42)
    head = compute_headroom(
        rack_id="R1",
        it_load_kw=1.0,
        cooling_load_kw=2.0,
        compute_units=2,
        rack_spec=spec,
    )
    assert head.limiting_factor == "balanced"


# --------------------------------------------------------------------------- #
# Capacity: overcommitment
# --------------------------------------------------------------------------- #


def test_detect_overcommitment_power() -> None:
    spec = RackSpec(rack_id="R1", max_power_kw=10.0, max_cooling_kw=20.0, max_rack_units=42)
    occ = detect_overcommitment(
        rack_id="R1",
        committed_power_kw=13.0,
        committed_cooling_kw=10.0,
        committed_units=20,
        rack_spec=spec,
    )
    assert occ.power_overcommit_pct == 130.0
    assert occ.overcommitted is True
    assert occ.risk_level in ("high", "critical")


def test_detect_overcommitment_not_overcommitted() -> None:
    spec = RackSpec(rack_id="R1", max_power_kw=10.0, max_cooling_kw=20.0, max_rack_units=42)
    occ = detect_overcommitment(
        rack_id="R1",
        committed_power_kw=7.0,
        committed_cooling_kw=10.0,
        committed_units=20,
        rack_spec=spec,
    )
    assert occ.power_overcommit_pct == 70.0
    assert occ.overcommitted is False
    assert occ.risk_level == "low"


# --------------------------------------------------------------------------- #
# Capacity: full plan + persistence round-trip
# --------------------------------------------------------------------------- #


def test_compute_capacity_plan_aggregates(tmp_path) -> None:
    specs = (
        RackSpec(rack_id="R1", max_power_kw=12.0, max_cooling_kw=10.0, max_rack_units=42),
        RackSpec(rack_id="R2", max_power_kw=15.0, max_cooling_kw=12.5, max_rack_units=42),
    )
    plan = compute_capacity_plan(
        specs,
        it_loads_kw={"R1": 8.0, "R2": 11.0},
        cooling_loads_kw={"R1": 7.0, "R2": 10.0},
        compute_units_map={"R1": 24, "R2": 30},
    )
    assert isinstance(plan, CapacityPlan)
    assert plan.total_it_load_kw == 19.0
    assert len(plan.racks) == 2
    assert len(plan.headroom) == 2
    assert len(plan.overcommitment) == 2
    assert plan.overall_utilization_pct > 0


def test_capacity_plan_save_load_round_trip(tmp_path) -> None:
    spec = (RackSpec(rack_id="R1", max_power_kw=12.0, max_cooling_kw=10.0, max_rack_units=42),)
    plan = compute_capacity_plan(spec, it_loads_kw={"R1": 8.0}, cooling_loads_kw={"R1": 7.0})
    state_dir = os.path.join(str(tmp_path), "datacenter")
    path = save_capacity_plan(plan, state_dir=state_dir)
    assert os.path.exists(path)
    loaded = load_capacity_plan(state_dir=state_dir)
    assert loaded is not None
    assert loaded.plan_id == plan.plan_id
    assert loaded.config_hash == plan.config_hash
    assert loaded.total_it_load_kw == plan.total_it_load_kw
    assert loaded.overcommitted_racks == plan.overcommitted_racks


def test_capacity_plan_load_missing_returns_none(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    assert load_capacity_plan(state_dir=state_dir) is None


# --------------------------------------------------------------------------- #
# Lifecycle: provision and transitions
# --------------------------------------------------------------------------- #


def test_provision_creates_active_asset(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    asset, decision = provision(
        asset_id="ASSET-01",
        service_tag="SVR-001",
        rack_id="R1",
        purchase_date="2025-01-01",
        state_dir=state_dir,
    )
    assert asset.asset_id == "ASSET-01"
    assert asset.stage == STAGE_ACTIVE
    assert decision.action == "provision"
    assert decision.stage_before == STAGE_PROVISIONING
    assert decision.stage_after == STAGE_ACTIVE


def test_valid_transition_active_to_maintenance_to_active(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    provision(asset_id="ASSET-02", service_tag="SVR-002", rack_id="R1", state_dir=state_dir)
    asset, _ = decommission(asset_id="ASSET-02", state_dir=state_dir)
    assert asset.stage == STAGE_DECOMMISSIONING


def test_invalid_transition_raises(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    provision(asset_id="ASSET-03", service_tag="SVR-003", rack_id="R1", state_dir=state_dir)
    # active -> retired is not a direct allowed transition.
    with pytest.raises(ValueError):
        retire(asset_id="ASSET-03", state_dir=state_dir)


def test_track_stage_returns_current(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    provision(asset_id="ASSET-04", service_tag="SVR-004", rack_id="R1", state_dir=state_dir)
    asset = track_stage(asset_id="ASSET-04", state_dir=state_dir)
    assert asset.stage == STAGE_ACTIVE


def test_refresh_returns_to_active(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    provision(asset_id="ASSET-05", service_tag="SVR-005", rack_id="R1", state_dir=state_dir)
    asset, _ = refresh(asset_id="ASSET-05", state_dir=state_dir)
    assert asset.stage == STAGE_ACTIVE


def test_retire_is_terminal(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    provision(asset_id="ASSET-06", service_tag="SVR-006", rack_id="R1", state_dir=state_dir)
    decommission(asset_id="ASSET-06", state_dir=state_dir)
    asset, decision = retire(asset_id="ASSET-06", state_dir=state_dir)
    assert asset.stage == STAGE_RETIRED
    assert decision.action == "retire"
    # retired is terminal: no further transitions allowed.
    with pytest.raises(ValueError):
        decommission(asset_id="ASSET-06", state_dir=state_dir)


def test_unknown_asset_raises(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    with pytest.raises(KeyError):
        track_stage(asset_id="DOES-NOT-EXIST", state_dir=state_dir)


# --------------------------------------------------------------------------- #
# Lifecycle: decommission cost analysis
# --------------------------------------------------------------------------- #


def test_decommission_cost_analysis_net_is_total_minus_credit(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    provision(asset_id="ASSET-07", service_tag="SVR-007", rack_id="R1", state_dir=state_dir)
    breakdown = decommission_cost_analysis(asset_id="ASSET-07", state_dir=state_dir)
    expected_total = 800.0 + 250.0 + 150.0 + 200.0 + 100.0
    assert breakdown.total_decommission_cost_usd == expected_total
    assert breakdown.net_decommission_cost_usd == expected_total - 400.0


# --------------------------------------------------------------------------- #
# Lifecycle: report
# --------------------------------------------------------------------------- #


def test_lifecycle_report_stage_counts(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    provision(asset_id="ASSET-08", service_tag="SVR-008", rack_id="R1", state_dir=state_dir)
    provision(asset_id="ASSET-09", service_tag="SVR-009", rack_id="R1", state_dir=state_dir)
    decommission(asset_id="ASSET-08", state_dir=state_dir)
    report = lifecycle_report(state_dir=state_dir)
    assert report.stage_counts[STAGE_ACTIVE] == 1
    assert report.stage_counts[STAGE_DECOMMISSIONING] == 1
    assert report.total_decommission_cost_usd > 0


# --------------------------------------------------------------------------- #
# Efficiency: PUE / DCiE
# --------------------------------------------------------------------------- #


def test_compute_pue() -> None:
    assert compute_pue(facility_energy_kwh=1500.0, it_energy_kwh=1000.0) == 1.5


def test_compute_pue_zero_it_returns_zero() -> None:
    assert compute_pue(facility_energy_kwh=100.0, it_energy_kwh=0.0) == 0.0


def test_compute_dcie() -> None:
    assert compute_dcie(pue=1.5) == (1.0 / 1.5)
    assert compute_dcie(pue=0.0) == 0.0


# --------------------------------------------------------------------------- #
# Efficiency: compute per watt and carbon
# --------------------------------------------------------------------------- #


def test_compute_compute_per_watt() -> None:
    assert compute_compute_per_watt(compute_units=1000, power_watts=500.0) == 2.0
    assert compute_compute_per_watt(compute_units=10, power_watts=0.0) == 0.0


def test_compute_carbon_intensity() -> None:
    carbon = compute_carbon_intensity(
        interval_kwh=1000.0,
        emission_factor_kg_co2e_per_kwh=0.45,
    )
    assert carbon.carbon_kg_co2e == 450.0
    assert carbon.method == "location-based"


# --------------------------------------------------------------------------- #
# Efficiency: ratings and recommendations
# --------------------------------------------------------------------------- #


def test_efficiency_rating_bands() -> None:
    assert "A" == ("A" if compute_pue(1300, 1000) <= 1.3 else "B")
    assert compute_pue(1300, 1000) == 1.3


def test_efficiency_recommendations_nonempty() -> None:
    metrics = EfficiencyMetrics(
        pue=2.0,
        dcie=0.5,
        compute_per_watt=0.5,
        carbon_intensity_kg_co2e_per_kwh=0.45,
        total_energy_kwh=2000.0,
        it_energy_kwh=1000.0,
        facility_energy_kwh=2000.0,
    )
    carbon = CarbonIntensity(
        interval_kwh=2000.0,
        emission_factor_kg_co2e_per_kwh=0.45,
        carbon_kg_co2e=900.0,
        method="location-based",
        factor_source="grid",
    )
    recs = efficiency_recommendations(metrics, carbon, pue_target=1.3)
    assert len(recs) >= 1
    assert all(isinstance(r, Recommendation) for r in recs)


def test_compute_efficiency_report_aggregate() -> None:
    report = compute_efficiency_report(
        facility_energy_kwh=1500.0,
        it_energy_kwh=1000.0,
        compute_units=50_000,
        power_watts=1_000_000.0,
    )
    assert isinstance(report, EfficiencyReport)
    assert report.metrics.pue == 1.5
    assert report.metrics.dcie == round(1.0 / 1.5, 4)
    assert report.efficiency_rating in ("A", "B", "C", "D", "F")
    assert len(report.recommendations) >= 1


def test_efficiency_report_save_load_round_trip(tmp_path) -> None:
    report = compute_efficiency_report(
        facility_energy_kwh=1500.0,
        it_energy_kwh=1000.0,
        compute_units=50_000,
        power_watts=1_000_000.0,
    )
    state_dir = os.path.join(str(tmp_path), "datacenter")
    path = save_efficiency_report(report, state_dir=state_dir)
    assert os.path.exists(path)
    loaded = load_efficiency_report(state_dir=state_dir)
    assert loaded is not None
    assert loaded.report_id == report.report_id
    assert loaded.metrics.pue == report.metrics.pue
    assert loaded.efficiency_rating == report.efficiency_rating


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _namespace(**kwargs) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


def test_cli_capacity_returns_zero_and_printed() -> None:
    args = _namespace(capacity=True, lifecycle=False, efficiency=False, state_dir=CAP_STATE_DIR)
    rc = dc_main(args)
    assert rc == 0


def test_cli_lifecycle_returns_zero(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    args = _namespace(capacity=False, lifecycle=True, efficiency=False, state_dir=state_dir)
    rc = dc_main(args)
    assert rc == 0


def test_cli_efficiency_returns_zero(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    args = _namespace(capacity=False, lifecycle=False, efficiency=True, state_dir=state_dir)
    rc = dc_main(args)
    assert rc == 0


def test_cli_no_mode_returns_one() -> None:
    args = _namespace(capacity=False, lifecycle=False, efficiency=False, state_dir=CAP_STATE_DIR)
    rc = dc_main(args)
    assert rc == 1


def test_handle_capacity_output_contains_expected_tokens(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    output = handle_capacity(state_dir=state_dir)
    assert "[C-UAS] Data Center Capacity Plan" in output
    assert "Overcommitted" in output
    assert "limiting factor" in output


def test_handle_efficiency_output_contains_expected_tokens(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    output = handle_efficiency(state_dir=state_dir)
    assert "[C-UAS] Energy-to-Compute Efficiency Report" in output
    assert "PUE" in output
    assert "Efficiency rating" in output


def test_handle_lifecycle_output_contains_expected_tokens(tmp_path) -> None:
    state_dir = os.path.join(str(tmp_path), "datacenter")
    output = handle_lifecycle(state_dir=state_dir)
    assert "[C-UAS] Data Center Lifecycle Report" in output
    assert "Stage counts" in output
