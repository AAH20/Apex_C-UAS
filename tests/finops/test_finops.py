"""Deterministic tests for the FinOps / Cost Optimization module.

Covers the cost model (IT load -> facility overhead -> monthly power cost,
cooling cost share, PUE-based cost multiplier), unit economics
(compute-per-dollar, cost-per-compute-unit, cost-per-watt, rack cost per
month), carbon intensity (gCO2/kWh by region, carbon per compute hour, carbon
cost at $/ton, region ranking), and cost optimization (right-sizing,
overcommitment tradeoff, PUE improvement ROI, region migration), plus the CLI.

All values are real computations -- no mocks, no fabricated metrics, no
network. State under ~/.c-uas-platform/finops/ is avoided in tests by passing
a tmp_path state dir, so tests are isolated and hermetic.
"""

from __future__ import annotations

import argparse

import pytest

from c_uas.finops.carbon import (
    CarbonIntensity,
    CarbonResult,
    carbon_cost_per_ton,
    carbon_intensity_for_region,
    carbon_per_compute_hour,
    ranked_regions_by_carbon,
)
from c_uas.finops.cli import build_subparser, finops_main
from c_uas.finops.cost_model import (
    DEFAULT_ELECTRICITY_USD_PER_KWH,
    DEFAULT_HOURS_PER_MONTH,
    DEFAULT_PUE,
    FacilityCost,
    ITLoadConfig,
    PowerDraw,
    compute_facility_cost,
    compute_monthly_power_cost,
    compute_power_draw,
    pue_cost_multiplier,
)
from c_uas.finops.optimizer import (
    OvercommitmentTradeoff,
    PueImprovementRoi,
    RegionMigrationAnalysis,
    RightSizingRecommendation,
    analyze_overcommitment_tradeoff,
    analyze_pue_improvement_roi,
    analyze_region_migration,
    build_optimization_recommendations,
    right_size_recommendation,
)
from c_uas.finops.unit_cost import (
    RackCost,
    UnitCostInputs,
    UnitCostResult,
    compute_rack_cost_per_month,
    compute_unit_cost,
)

# --------------------------------------------------------------------------- #
# Cost model: power draw
# --------------------------------------------------------------------------- #


def test_power_draw_matches_pue_formula() -> None:
    draw = compute_power_draw(it_load_kw=100.0, pue=1.5)
    assert isinstance(draw, PowerDraw)
    assert draw.it_load_kw == 100.0
    assert draw.total_facility_kw == 150.0
    assert draw.facility_overhead_kw == 50.0
    assert draw.pue == 1.5


def test_power_draw_pue_floor_one() -> None:
    draw = compute_power_draw(it_load_kw=100.0, pue=0.8)
    assert draw.pue == 1.0
    assert draw.total_facility_kw == 100.0
    assert draw.facility_overhead_kw == 0.0


def test_power_draw_zero_load() -> None:
    draw = compute_power_draw(it_load_kw=0.0, pue=2.0)
    assert draw.total_facility_kw == 0.0
    assert draw.facility_overhead_kw == 0.0


def test_power_draw_negative_load_raises() -> None:
    with pytest.raises(ValueError):
        compute_power_draw(it_load_kw=-1.0, pue=1.5)


# --------------------------------------------------------------------------- #
# Cost model: monthly power cost
# --------------------------------------------------------------------------- #


def test_monthly_power_cost_formula() -> None:
    cost = compute_monthly_power_cost(
        it_load_kw=100.0, pue=1.5, electricity_usd_per_kwh=0.12, hours_per_month=730.0
    )
    # 100 kW * 1.5 PUE * 730 h * $0.12 = $13,140.00
    assert cost == 13140.0


def test_monthly_power_cost_defaults() -> None:
    cost = compute_monthly_power_cost(it_load_kw=100.0)
    assert cost == compute_monthly_power_cost(
        it_load_kw=100.0,
        pue=DEFAULT_PUE,
        electricity_usd_per_kwh=DEFAULT_ELECTRICITY_USD_PER_KWH,
        hours_per_month=DEFAULT_HOURS_PER_MONTH,
    )


# --------------------------------------------------------------------------- #
# Cost model: facility cost breakdown
# --------------------------------------------------------------------------- #


def test_facility_cost_breakdown() -> None:
    cost = compute_facility_cost(
        it_load_kw=100.0,
        pue=1.5,
        electricity_usd_per_kwh=0.12,
        hours_per_month=730.0,
        cooling_share_of_overhead_pct=40.0,
    )
    assert isinstance(cost, FacilityCost)
    assert cost.it_load_kw == 100.0
    assert cost.total_facility_kw == 150.0
    assert cost.monthly_power_cost_usd == 13140.0
    # IT energy = 100*730 = 73000 kWh * 0.12 = $8760
    assert cost.it_monthly_cost_usd == 8760.0
    # Overhead = 13140 - 8760 = $4380; cooling = 40% * 4380 = $1752
    assert cost.overhead_monthly_cost_usd == 4380.0
    assert cost.cooling_cost_usd == 1752.0
    assert cost.cooling_cost_share_pct == 40.0
    # PUE cost multiplier = total / IT = 13140 / 8760 = 1.5
    assert cost.pue_cost_multiplier == 1.5


def test_pue_cost_multiplier_equals_pue() -> None:
    assert pue_cost_multiplier(1.5) == 1.5
    assert pue_cost_multiplier(2.0) == 2.0
    assert pue_cost_multiplier(0.5) == 1.0  # floored


def test_it_load_config_validation() -> None:
    with pytest.raises(ValueError):
        ITLoadConfig(it_load_kw=-1.0)
    with pytest.raises(ValueError):
        ITLoadConfig(it_load_kw=100.0, pue=0.5)
    with pytest.raises(ValueError):
        ITLoadConfig(it_load_kw=100.0, electricity_usd_per_kwh=-0.1)
    with pytest.raises(ValueError):
        ITLoadConfig(it_load_kw=100.0, hours_per_month=0.0)
    with pytest.raises(ValueError):
        ITLoadConfig(it_load_kw=100.0, cooling_share_of_overhead_pct=110.0)


# --------------------------------------------------------------------------- #
# Unit economics
# --------------------------------------------------------------------------- #


def test_compute_unit_cost() -> None:
    inputs = UnitCostInputs(
        compute_units=10_000,
        power_kw=100.0,
        monthly_cost_usd=1000.0,
        carbon_intensity_gco2_per_kwh=380.0,
        carbon_usd_per_ton=50.0,
    )
    result = compute_unit_cost(inputs)
    assert isinstance(result, UnitCostResult)
    # compute_per_dollar = 10000 / 1000 = 10
    assert result.compute_per_dollar == 10.0
    # cost_per_compute_unit = 1000 / 10000 = 0.1
    assert result.cost_per_compute_unit_usd == 0.1
    # cost_per_watt = 1000 / (100*1000) = 0.01
    assert result.cost_per_watt_usd == 0.01
    # carbon cost per unit: 100kW*730h=73000kWh * 380g/1000 = 27740 kg = 27.74 t
    # * $50 = $1387; /10000 = $0.1387
    assert result.carbon_cost_per_compute_unit_usd == pytest.approx(0.1387, rel=1e-6)
    assert result.monthly_cost_usd == 1000.0


def test_compute_unit_cost_zero_compute_units() -> None:
    inputs = UnitCostInputs(compute_units=0, power_kw=100.0, monthly_cost_usd=1000.0)
    result = compute_unit_cost(inputs)
    assert result.compute_per_dollar == 0.0
    assert result.cost_per_compute_unit_usd == 0.0
    assert result.carbon_cost_per_compute_unit_usd == 0.0


def test_compute_unit_cost_zero_cost() -> None:
    inputs = UnitCostInputs(compute_units=10_000, power_kw=0.0, monthly_cost_usd=0.0)
    result = compute_unit_cost(inputs)
    assert result.compute_per_dollar == 0.0
    assert result.cost_per_watt_usd == 0.0


def test_compute_rack_cost_per_month() -> None:
    rack = compute_rack_cost_per_month(
        rack_id="RACK-01",
        rack_power_kw=10.0,
        pue=1.5,
        electricity_usd_per_kwh=0.12,
        hours_per_month=730.0,
        compute_units=1000,
    )
    assert isinstance(rack, RackCost)
    assert rack.rack_id == "RACK-01"
    # 10 kW * 1.5 * 730 h * 0.12 = $1314.00
    assert rack.monthly_rack_cost_usd == 1314.0
    assert rack.pue == 1.5
    # cost per compute unit = 1314 / 1000 = $1.314
    assert rack.cost_per_compute_unit_usd == pytest.approx(1.314, rel=1e-6)


def test_compute_rack_cost_no_compute_units() -> None:
    rack = compute_rack_cost_per_month(
        rack_id="RACK-01",
        rack_power_kw=10.0,
        pue=1.5,
        electricity_usd_per_kwh=0.12,
        hours_per_month=730.0,
    )
    assert rack.cost_per_compute_unit_usd is None


def test_compute_rack_cost_validation() -> None:
    with pytest.raises(ValueError):
        compute_rack_cost_per_month("R1", -1.0, 1.5, 0.12)
    with pytest.raises(ValueError):
        compute_rack_cost_per_month("R1", 1.0, 0.5, 0.12)


# --------------------------------------------------------------------------- #
# Carbon intensity
# --------------------------------------------------------------------------- #


def test_carbon_intensity_known_region() -> None:
    ci = carbon_intensity_for_region("us-east-1")
    assert isinstance(ci, CarbonIntensity)
    assert ci.region == "us-east-1"
    assert ci.carbon_intensity_gco2_per_kwh == 380.0


def test_carbon_intensity_unknown_region_falls_back() -> None:
    ci = carbon_intensity_for_region("no-such-region")
    assert ci.carbon_intensity_gco2_per_kwh > 0
    assert ci.source.endswith("fallback")


def test_carbon_per_compute_hour() -> None:
    result = carbon_per_compute_hour(
        power_kw=100.0,
        region="us-east-1",
        hours=1.0,
        carbon_usd_per_ton=50.0,
    )
    assert isinstance(result, CarbonResult)
    assert result.region == "us-east-1"
    assert result.power_kw == 100.0
    assert result.energy_kwh == 100.0
    # 100 kWh * 380 g / 1000 = 38 kg CO2e
    assert result.carbon_kg_co2e == 38.0
    # 38 kg = 0.038 t * $50 = $1.90
    assert result.carbon_cost_usd == pytest.approx(1.9, rel=1e-9)
    assert result.carbon_tons_co2e == pytest.approx(0.038, rel=1e-9)


def test_carbon_cost_per_ton() -> None:
    assert carbon_cost_per_ton(1000.0, 50.0) == 50.0  # 1000 kg = 1 t * $50
    assert carbon_cost_per_ton(0.0, 50.0) == 0.0
    with pytest.raises(ValueError):
        carbon_cost_per_ton(-1.0, 50.0)


def test_ranked_regions_by_carbon() -> None:
    ranked = ranked_regions_by_carbon()
    assert ranked[0] == ("sa-east-1", 90.0)  # most efficient (lowest carbon)
    intensities = [g for _, g in ranked]
    assert intensities == sorted(intensities)
    # Custom map overrides default
    custom = ranked_regions_by_carbon({"A": 10.0, "B": 5.0})
    assert custom == [("B", 5.0), ("A", 10.0)]


# --------------------------------------------------------------------------- #
# Cost optimization
# --------------------------------------------------------------------------- #


def test_right_size_recommendation() -> None:
    rec = right_size_recommendation(
        resource_id="RACK-01",
        current_allocated_kw=100.0,
        actual_peak_kw=60.0,
        electricity_usd_per_kwh=0.12,
        hours_per_month=730.0,
    )
    assert isinstance(rec, RightSizingRecommendation)
    # recommended = 60 * 1.2 = 72 kW (capped at 100)
    assert rec.recommended_kw == 72.0
    assert rec.savings_kw == 28.0
    # 28 kW * 730 h * 0.12 = $2452.80
    assert rec.monthly_savings_usd == pytest.approx(2452.8, rel=1e-9)
    assert rec.utilization_pct == pytest.approx(60.0, rel=1e-9)
    assert "overprovisioning" in rec.reason


def test_right_size_no_opportunity() -> None:
    rec = right_size_recommendation(
        resource_id="RACK-01",
        current_allocated_kw=100.0,
        actual_peak_kw=100.0,
        electricity_usd_per_kwh=0.12,
        hours_per_month=730.0,
    )
    assert rec.savings_kw == 0.0
    assert rec.monthly_savings_usd == 0.0


def test_overcommitment_tradeoff() -> None:
    trade = analyze_overcommitment_tradeoff(
        resource_id="RACK-01",
        committed_kw=120.0,
        physical_kw=100.0,
        extra_revenue_usd_per_month=200.0,
        risk_penalty_usd_per_month=50.0,
    )
    assert isinstance(trade, OvercommitmentTradeoff)
    assert trade.overcommitment_pct == pytest.approx(120.0, rel=1e-9)
    assert trade.net_tradeoff_usd_per_month == pytest.approx(150.0, rel=1e-9)
    assert trade.recommended is True


def test_overcommitment_tradeoff_not_recommended() -> None:
    trade = analyze_overcommitment_tradeoff(
        resource_id="RACK-01",
        committed_kw=120.0,
        physical_kw=100.0,
        extra_revenue_usd_per_month=20.0,
        risk_penalty_usd_per_month=50.0,
    )
    assert trade.net_tradeoff_usd_per_month == pytest.approx(-30.0, rel=1e-9)
    assert trade.recommended is False


def test_pue_improvement_roi() -> None:
    roi = analyze_pue_improvement_roi(
        current_pue=1.5,
        target_pue=1.3,
        it_load_kw=100.0,
        electricity_usd_per_kwh=0.12,
        hours_per_month=730.0,
        upgrade_cost_usd=5000.0,
    )
    assert isinstance(roi, PueImprovementRoi)
    # delta = 0.2 * 100 kW * 730 h * 0.12 = $1752.00 / month
    assert roi.monthly_savings_usd == pytest.approx(1752.0, rel=1e-9)
    assert roi.annual_savings_usd == pytest.approx(21024.0, rel=1e-9)
    # payback = 5000 / 1752 = 2.85 (rounded to 2 decimals)
    assert roi.payback_months == pytest.approx(2.85, rel=1e-9)
    # ROI = (21024 - 5000) / 5000 * 100 = 320.48%
    assert roi.roi_pct == pytest.approx(320.48, rel=1e-2)


def test_pue_improvement_roi_free() -> None:
    roi = analyze_pue_improvement_roi(
        current_pue=1.5,
        target_pue=1.3,
        it_load_kw=100.0,
        upgrade_cost_usd=0.0,
    )
    assert roi.payback_months == 0.0
    assert roi.roi_pct == 100.0


def test_pue_improvement_validation() -> None:
    with pytest.raises(ValueError):
        analyze_pue_improvement_roi(current_pue=0.5, target_pue=1.3, it_load_kw=100.0)
    with pytest.raises(ValueError):
        analyze_pue_improvement_roi(
            current_pue=1.5, target_pue=1.6, it_load_kw=100.0
        )  # target > current


def test_region_migration_analysis() -> None:
    mig = analyze_region_migration(
        source_region="us-east-1",
        target_region="sa-east-1",
        power_kw=100.0,
        hours_per_month=730.0,
        carbon_usd_per_ton=50.0,
    )
    assert isinstance(mig, RegionMigrationAnalysis)
    assert mig.source_region == "us-east-1"
    assert mig.target_region == "sa-east-1"
    # source: 100*730*380/1000 = 27740 kg; target: 100*730*90/1000 = 6570 kg
    assert mig.source_carbon_kg_per_month == pytest.approx(27740.0, rel=1e-9)
    assert mig.target_carbon_kg_per_month == pytest.approx(6570.0, rel=1e-9)
    assert mig.carbon_reduction_kg_per_month == pytest.approx(21170.0, rel=1e-9)
    assert mig.carbon_reduction_pct == pytest.approx(76.32, rel=1e-9)
    assert mig.carbon_cost_savings_usd_per_month > 0


# --------------------------------------------------------------------------- #
# Optimization recommendations aggregation
# --------------------------------------------------------------------------- #


def test_build_optimization_recommendations() -> None:
    right_sizing = [right_size_recommendation("R1", 100.0, 50.0, 0.12, 730.0)]
    overcommitment = [analyze_overcommitment_tradeoff("R1", 120.0, 100.0, 200.0, 50.0)]
    pue_roi = [analyze_pue_improvement_roi(1.5, 1.3, 100.0, upgrade_cost_usd=5000.0)]
    migration = [analyze_region_migration("us-east-1", "sa-east-1", 100.0)]
    recs = build_optimization_recommendations(
        right_sizing=right_sizing,
        overcommitment=overcommitment,
        pue_roi=pue_roi,
        region_migration=migration,
    )
    assert len(recs) == 4
    # Sorted by savings descending
    savings = [r.estimated_monthly_savings_usd for r in recs]
    assert savings == sorted(savings, reverse=True)
    categories = {r.category for r in recs}
    assert categories == {"right_size", "overcommitment", "pue", "region_migration"}


def test_build_optimization_recommendations_empty() -> None:
    assert build_optimization_recommendations() == []


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _make_namespace(**overrides):
    ns = argparse.Namespace(
        cost=False,
        unit=False,
        carbon=False,
        optimize=False,
        it_load_kw=100.0,
        pue=1.5,
        rate=0.12,
        hours=730.0,
        source_region="us-east-1",
        target_region="sa-east-1",
        carbon_price=50.0,
        state_dir=None,
    )
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


def test_cli_build_subparser_adds_finops() -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="c-uas")
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(["finops", "--cost"])
    assert args.command == "finops"
    assert args.cost is True


def test_cli_finops_cost(tmp_path) -> None:
    ns = _make_namespace(cost=True, state_dir=str(tmp_path / "finops"))
    code = finops_main(ns)
    assert code == 0


def test_cli_finops_unit(tmp_path) -> None:
    ns = _make_namespace(unit=True, state_dir=str(tmp_path / "finops"))
    code = finops_main(ns)
    assert code == 0


def test_cli_finops_carbon(tmp_path) -> None:
    ns = _make_namespace(carbon=True, state_dir=str(tmp_path / "finops"))
    code = finops_main(ns)
    assert code == 0


def test_cli_finops_optimize(tmp_path) -> None:
    ns = _make_namespace(optimize=True, state_dir=str(tmp_path / "finops"))
    code = finops_main(ns)
    assert code == 0


def test_cli_finops_no_flag_returns_one() -> None:
    ns = _make_namespace()
    code = finops_main(ns)
    assert code == 1
