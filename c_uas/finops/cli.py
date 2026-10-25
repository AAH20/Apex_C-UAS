"""``c-uas finops`` subcommand: FinOps / Cost Optimization.

    c-uas finops --cost
    c-uas finops --unit
    c-uas finops --carbon
    c-uas finops --optimize

Models infrastructure cost from power, cooling, compute, and carbon intensity.
All output is deterministic: identical inputs produce identical output. State
persists under ~/.c-uas-platform/finops/ (outside the repo). Advisory only --
no facility actuation.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from typing import Any, Optional, Sequence

from .carbon import (
    DEFAULT_CARBON_USD_PER_TON,
    REGION_CARBON_INTENSITY,
    carbon_per_compute_hour,
    save_carbon_result,
)
from .cost_model import (
    DEFAULT_ELECTRICITY_USD_PER_KWH,
    DEFAULT_HOURS_PER_MONTH,
    ITLoadConfig,
    compute_facility_cost,
    save_facility_cost,
)
from .optimizer import (
    analyze_overcommitment_tradeoff,
    analyze_pue_improvement_roi,
    analyze_region_migration,
    build_optimization_recommendations,
    right_size_recommendation,
    save_optimizer_result,
)
from .unit_cost import (
    UnitCostInputs,
    compute_rack_cost_per_month,
    compute_unit_cost,
    save_unit_cost,
)

EXAMPLE_IT_LOAD_KW = 100.0
EXAMPLE_PUE = 1.5
EXAMPLE_REGION_SOURCE = "us-east-1"
EXAMPLE_REGION_TARGET = "eu-west-1"


def _render_cost(cost) -> str:
    lines: list = []
    lines.append("[C-UAS] FinOps Cost Model")
    lines.append("=" * 44)
    lines.append("IT load          : %.2f kW" % cost.it_load_kw)
    lines.append("Total facility   : %.2f kW" % cost.total_facility_kw)
    lines.append("PUE cost mult.   : %.4fx" % cost.pue_cost_multiplier)
    lines.append("Monthly power    : $%.4f" % cost.monthly_power_cost_usd)
    lines.append("IT monthly cost  : $%.4f" % cost.it_monthly_cost_usd)
    lines.append("Overhead monthly : $%.4f" % cost.overhead_monthly_cost_usd)
    lines.append("Cooling cost     : $%.4f" % cost.cooling_cost_usd)
    lines.append("Cooling share    : %.1f%%" % cost.cooling_cost_share_pct)
    return "\n".join(lines)


def _render_unit(result, rack) -> str:
    lines: list = []
    lines.append("[C-UAS] FinOps Unit Economics")
    lines.append("=" * 44)
    lines.append("Compute per dollar : %.6f units/$" % result.compute_per_dollar)
    lines.append("Cost per compute   : $%.6f /unit" % result.cost_per_compute_unit_usd)
    lines.append("Cost per watt      : $%.6f /W/mo" % result.cost_per_watt_usd)
    lines.append("Carbon cost/unit   : $%.6f /unit" % result.carbon_cost_per_compute_unit_usd)
    lines.append("Monthly cost       : $%.4f" % result.monthly_cost_usd)
    lines.append("")
    lines.append("[C-UAS] Rack Cost (RACK-01)")
    lines.append("=" * 44)
    lines.append("Rack power       : %.2f kW" % rack.rack_power_kw)
    lines.append("PUE              : %.4f" % rack.pue)
    lines.append("Monthly rack cost: $%.4f" % rack.monthly_rack_cost_usd)
    if rack.cost_per_compute_unit_usd is not None:
        lines.append("Cost/compute unit: $%.6f /unit" % rack.cost_per_compute_unit_usd)
    return "\n".join(lines)


def _render_carbon(result) -> str:
    lines: list = []
    lines.append("[C-UAS] FinOps Carbon Intensity")
    lines.append("=" * 44)
    lines.append("Region           : %s" % result.region)
    lines.append("Power            : %.2f kW" % result.power_kw)
    lines.append("Hours            : %.1f" % result.hours)
    lines.append("Energy           : %.4f kWh" % result.energy_kwh)
    lines.append("Intensity        : %.2f gCO2/kWh" % result.carbon_intensity_gco2_per_kwh)
    lines.append("Carbon           : %.4f kg CO2e" % result.carbon_kg_co2e)
    lines.append("Carbon (tons)    : %.6f t CO2e" % result.carbon_tons_co2e)
    lines.append("Carbon cost      : $%.6f" % result.carbon_cost_usd)
    lines.append("Carbon price     : $%.2f /ton" % result.carbon_usd_per_ton)
    return "\n".join(lines)


def _render_optimize(recs) -> str:
    lines: list = []
    lines.append("[C-UAS] FinOps Optimization Recommendations")
    lines.append("=" * 44)
    if not recs:
        lines.append("No optimization opportunities identified.")
        return "\n".join(lines)
    for i, r in enumerate(recs, 1):
        lines.append("  %d. [%s] %s" % (i, r.priority.upper(), r.title))
        lines.append("     %s" % r.description)
        lines.append("     Est. savings : $%.4f /month" % r.estimated_monthly_savings_usd)
    return "\n".join(lines)


def build_subparser(subparsers: Any) -> Any:
    """Register the ``finops`` subcommand on a parent parser (e.g. c_uas.cli)."""
    parser = subparsers.add_parser(
        "finops",
        help=(
            "FinOps / Cost Optimization: model infrastructure cost from power, "
            "cooling, compute, and carbon intensity"
        ),
    )
    parser.add_argument(
        "--cost",
        action="store_true",
        help="Run the cost model (IT load -> facility overhead -> monthly power cost)",
    )
    parser.add_argument(
        "--unit",
        action="store_true",
        help="Run unit economics (compute-per-dollar, cost-per-compute-unit, rack cost)",
    )
    parser.add_argument(
        "--carbon",
        action="store_true",
        help="Run carbon intensity analysis by region",
    )
    parser.add_argument(
        "--optimize",
        action="store_true",
        help="Run cost optimization (right-sizing, overcommitment, PUE ROI, region migration)",
    )
    parser.add_argument(
        "--it-load-kw",
        type=float,
        default=EXAMPLE_IT_LOAD_KW,
        help="IT load in kW for cost model (default: %.1f)" % EXAMPLE_IT_LOAD_KW,
    )
    parser.add_argument(
        "--pue",
        type=float,
        default=EXAMPLE_PUE,
        help="PUE (Power Usage Effectiveness), >= 1.0 (default: %.1f)" % EXAMPLE_PUE,
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=DEFAULT_ELECTRICITY_USD_PER_KWH,
        help="Electricity rate in USD/kWh (default: %.4f)" % DEFAULT_ELECTRICITY_USD_PER_KWH,
    )
    parser.add_argument(
        "--hours",
        type=float,
        default=DEFAULT_HOURS_PER_MONTH,
        help="Billing hours per month (default: %.1f)" % DEFAULT_HOURS_PER_MONTH,
    )
    parser.add_argument(
        "--source-region",
        type=str,
        default=EXAMPLE_REGION_SOURCE,
        help="Source region for carbon / migration analysis",
    )
    parser.add_argument(
        "--target-region",
        type=str,
        default=EXAMPLE_REGION_TARGET,
        help="Target region for migration analysis",
    )
    parser.add_argument(
        "--carbon-price",
        type=float,
        default=DEFAULT_CARBON_USD_PER_TON,
        help="Carbon price in USD/ton CO2e (default: %.2f)" % DEFAULT_CARBON_USD_PER_TON,
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default=None,
        help="State directory for persisted finops reports (default: ~/.c-uas-platform/finops/)",
    )
    return parser


def _default_state_dir(args: argparse.Namespace) -> str:
    state_dir = getattr(args, "state_dir", None)
    if state_dir:
        return state_dir
    from .cost_model import DEFAULT_STATE_DIR as COST_STATE_DIR

    return COST_STATE_DIR


def handle_cost(args: argparse.Namespace) -> str:
    cost = compute_facility_cost(
        it_load_kw=args.it_load_kw,
        pue=args.pue,
        electricity_usd_per_kwh=args.rate,
        hours_per_month=args.hours,
    )
    config = ITLoadConfig(
        it_load_kw=args.it_load_kw,
        pue=args.pue,
        electricity_usd_per_kwh=args.rate,
        hours_per_month=args.hours,
    )
    save_facility_cost(cost, config, state_dir=_default_state_dir(args))
    return _render_cost(cost)


def handle_unit(args: argparse.Namespace) -> str:
    cost = compute_facility_cost(
        it_load_kw=args.it_load_kw,
        pue=args.pue,
        electricity_usd_per_kwh=args.rate,
        hours_per_month=args.hours,
    )
    intensity = REGION_CARBON_INTENSITY.get(args.source_region, 380.0)
    inputs = UnitCostInputs(
        compute_units=10_000,
        power_kw=args.it_load_kw,
        monthly_cost_usd=cost.monthly_power_cost_usd,
        carbon_intensity_gco2_per_kwh=intensity,
        carbon_usd_per_ton=args.carbon_price,
    )
    result = compute_unit_cost(inputs)
    rack = compute_rack_cost_per_month(
        rack_id="RACK-01",
        rack_power_kw=args.it_load_kw,
        pue=args.pue,
        electricity_usd_per_kwh=args.rate,
        hours_per_month=args.hours,
        compute_units=10_000,
    )
    save_unit_cost(result, inputs, state_dir=_default_state_dir(args))
    return _render_unit(result, rack)


def handle_carbon(args: argparse.Namespace) -> str:
    result = carbon_per_compute_hour(
        power_kw=args.it_load_kw,
        region=args.source_region,
        hours=args.hours,
        carbon_usd_per_ton=args.carbon_price,
    )
    save_carbon_result(
        result,
        args.source_region,
        args.it_load_kw,
        args.hours,
        args.carbon_price,
        state_dir=_default_state_dir(args),
    )
    return _render_carbon(result)


def handle_optimize(args: argparse.Namespace) -> str:
    right_sizing = [
        right_size_recommendation(
            resource_id="RACK-01",
            current_allocated_kw=args.it_load_kw,
            actual_peak_kw=args.it_load_kw * 0.6,
            electricity_usd_per_kwh=args.rate,
            hours_per_month=args.hours,
        )
    ]
    overcommitment = [
        analyze_overcommitment_tradeoff(
            resource_id="RACK-01",
            committed_kw=args.it_load_kw * 1.2,
            physical_kw=args.it_load_kw,
            extra_revenue_usd_per_month=200.0,
            risk_penalty_usd_per_month=50.0,
        )
    ]
    target_pue = max(1.2, args.pue - 0.2)
    pue_roi = [
        analyze_pue_improvement_roi(
            current_pue=args.pue,
            target_pue=target_pue,
            it_load_kw=args.it_load_kw,
            electricity_usd_per_kwh=args.rate,
            hours_per_month=args.hours,
            upgrade_cost_usd=5000.0,
        )
    ]
    migration = [
        analyze_region_migration(
            source_region=args.source_region,
            target_region=args.target_region,
            power_kw=args.it_load_kw,
            hours_per_month=args.hours,
            carbon_usd_per_ton=args.carbon_price,
        )
    ]
    recs = build_optimization_recommendations(
        right_sizing=right_sizing,
        overcommitment=overcommitment,
        pue_roi=pue_roi,
        region_migration=migration,
    )
    save_optimizer_result(
        {
            "right_sizing": [asdict(r) for r in right_sizing],
            "overcommitment": [asdict(o) for o in overcommitment],
            "pue_roi": [asdict(p) for p in pue_roi],
            "region_migration": [asdict(m) for m in migration],
            "recommendations": [asdict(r) for r in recs],
        },
        state_dir=_default_state_dir(args),
    )
    return _render_optimize(recs)


def finops_main(args: argparse.Namespace) -> int:
    if args.cost:
        print(handle_cost(args))
        return 0
    if args.unit:
        print(handle_unit(args))
        return 0
    if args.carbon:
        print(handle_carbon(args))
        return 0
    if args.optimize:
        print(handle_optimize(args))
        return 0
    print("[C-UAS] finops: specify --cost, --unit, --carbon, or --optimize")
    print("  c-uas finops --cost")
    print("  c-uas finops --unit")
    print("  c-uas finops --carbon")
    print("  c-uas finops --optimize")
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Standalone entry point: ``python -m c_uas.finops.cli``."""
    parser = argparse.ArgumentParser(
        prog="c-uas finops",
        description="FinOps / Cost Optimization for the C-UAS platform",
    )
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 1
    return finops_main(args)


if __name__ == "__main__":
    import sys

    sys.exit(main())
