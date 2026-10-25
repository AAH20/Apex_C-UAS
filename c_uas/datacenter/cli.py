"""``c-uas dc`` subcommand: Data Center Lifecycle Decision Support.

Usage:
    c-uas dc --capacity
    c-uas dc --lifecycle
    c-uas dc --efficiency

Integrates Data Center Commander (DCC) concepts into the C-UAS platform:
production-grade capacity planning, lifecycle decisions, and energy-to-compute
efficiency analysis. All output is deterministic: identical inputs produce
identical output. State persists under ~/.c-uas-platform/datacenter/
(outside the repo). Advisory only -- no facility actuation.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import argparse
from typing import Any, Optional

from .capacity import (
    DEFAULT_STATE_DIR,
    RackSpec,
    compute_capacity_plan,
    save_capacity_plan,
)
from .efficiency import (
    compute_efficiency_report,
    save_efficiency_report,
)
from .lifecycle import (
    decommission_cost_analysis,
    lifecycle_report,
    provision,
    refresh,
)

EXAMPLE_RACKS = (
    RackSpec(rack_id="RACK-01", max_power_kw=12.0, max_cooling_kw=10.0, max_rack_units=42),
    RackSpec(rack_id="RACK-02", max_power_kw=15.0, max_cooling_kw=12.5, max_rack_units=42),
    RackSpec(rack_id="RACK-03", max_power_kw=10.0, max_cooling_kw=9.0, max_rack_units=42),
)


def build_subparser(subparsers: Any) -> Any:
    """Register the ``dc`` subcommand on a parent parser."""
    parser = subparsers.add_parser(
        "dc",
        help=(
            "Data Center Lifecycle Decision Support: capacity planning, "
            "lifecycle decisions, energy-to-compute efficiency"
        ),
    )
    parser.add_argument(
        "--capacity",
        action="store_true",
        help=(
            "Run data center capacity planning (power, cooling, rack "
            "utilization, headroom, overcommitment)"
        ),
    )
    parser.add_argument(
        "--lifecycle",
        action="store_true",
        help=(
            "Run data center lifecycle decisions (provision, decommission, "
            "refresh, retire, stage tracking)"
        ),
    )
    parser.add_argument(
        "--efficiency",
        action="store_true",
        help=(
            "Run energy-to-compute efficiency analysis (PUE, DCiE, compute "
            "per watt, carbon intensity)"
        ),
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default=DEFAULT_STATE_DIR,
        help=(
            "State directory for persisted datacenter reports "
            "(default: ~/.c-uas-platform/datacenter/)"
        ),
    )
    return parser


# --------------------------------------------------------------------------- #
# Renderers (pure text, deterministic)
# --------------------------------------------------------------------------- #


def _render_capacity(plan) -> str:
    lines: list = []
    lines.append("[C-UAS] Data Center Capacity Plan")
    lines.append("=" * 44)
    lines.append("Plan ID        : %s" % plan.plan_id)
    lines.append("Config hash    : %s" % plan.config_hash)
    lines.append("Total IT load  : %.2f kW" % plan.total_it_load_kw)
    lines.append("Total facility : %.2f kW" % plan.total_facility_kw)
    lines.append("Overall util.  : %.1f%%" % plan.overall_utilization_pct)
    lines.append("Overcommitted  : %d rack(s)" % plan.overcommitted_racks)
    lines.append("-" * 44)
    lines.append("Per-rack utilization:")
    for r in sorted(plan.racks, key=lambda x: x.rack_id):
        lines.append(
            "  %-9s power=%5.1f%% cooling=%5.1f%% compute=%5.1f%% "
            "overall=%5.1f%% headroom=%5.1f%%"
            % (
                r.rack_id,
                r.power_utilization_pct,
                r.cooling_utilization_pct,
                r.compute_utilization_pct,
                r.overall_utilization_pct,
                r.headroom_pct,
            )
        )
    lines.append("-" * 44)
    lines.append("Headroom / limiting factor:")
    for h in sorted(plan.headroom, key=lambda x: x.rack_id):
        lines.append(
            "  %-9s power=%5.1f%% cooling=%5.1f%% space=%5.1f%% -> %s"
            % (
                h.rack_id,
                h.headroom_power_pct,
                h.headroom_cooling_pct,
                h.headroom_units_pct,
                h.limiting_factor,
            )
        )
    lines.append("-" * 44)
    lines.append("Overcommitment detection:")
    for o in sorted(plan.overcommitment, key=lambda x: x.rack_id):
        mark = "OVERCOMMITTED" if o.overcommitted else "ok"
        lines.append(
            "  %-9s committed=%.1f kW / %.1f kW physical  space=%d/%d  "
            "risk=%s  %s"
            % (
                o.rack_id,
                o.committed_power_kw,
                o.physical_power_kw,
                o.committed_units,
                o.physical_units,
                o.risk_level,
                mark,
            )
        )
    return "\n".join(lines)


def _render_lifecycle(report) -> str:
    lines: list = []
    lines.append("[C-UAS] Data Center Lifecycle Report")
    lines.append("=" * 44)
    lines.append("Report ID          : %s" % report.report_id)
    lines.append("Config hash        : %s" % report.config_hash)
    lines.append("Total assets       : %d" % len(report.assets))
    lines.append("Assets needing retirement: %d" % report.assets_needing_retirement)
    lines.append("Total decommission cost basis: $%.2f" % report.total_decommission_cost_usd)
    lines.append("-" * 44)
    lines.append("Stage counts:")
    for stage in sorted(report.stage_counts):
        lines.append("  %-18s %d" % (stage, report.stage_counts[stage]))
    lines.append("-" * 44)
    lines.append("Asset inventory:")
    for a in sorted(report.assets, key=lambda x: x.asset_id):
        eos = a.end_of_support_date or "(none)"
        lines.append(
            "  %-10s stage=%-16s rack=%s eos=%s last=%s"
            % (a.asset_id, a.stage, a.rack_id, eos, a.last_decision or "(none)")
        )
    return "\n".join(lines)


def _render_efficiency(report) -> str:
    lines: list = []
    lines.append("[C-UAS] Energy-to-Compute Efficiency Report")
    lines.append("=" * 44)
    lines.append("Report ID          : %s" % report.report_id)
    lines.append("Config hash        : %s" % report.config_hash)
    m = report.metrics
    lines.append("PUE                : %.4f" % m.pue)
    lines.append("DCiE               : %.4f (%.1f%%)" % (m.dcie, m.dcie * 100.0))
    lines.append("Compute per watt   : %.4f units/W" % m.compute_per_watt)
    lines.append("Total energy       : %.2f kWh" % m.total_energy_kwh)
    lines.append("IT energy          : %.2f kWh" % m.it_energy_kwh)
    lines.append("Facility energy    : %.2f kWh" % m.facility_energy_kwh)
    lines.append("Carbon intensity   : %.6f kg CO2e/kWh" % m.carbon_intensity_kg_co2e_per_kwh)
    lines.append("Efficiency rating  : %s" % report.efficiency_rating)
    lines.append("-" * 44)
    lines.append(
        "Carbon (interval): %.2f kWh x %.6f = %.4f kg CO2e [%s]"
        % (
            report.carbon.interval_kwh,
            report.carbon.emission_factor_kg_co2e_per_kwh,
            report.carbon.carbon_kg_co2e,
            report.carbon.method,
        )
    )
    lines.append("-" * 44)
    lines.append("Recommendations:")
    for r in report.recommendations:
        lines.append(
            "  [%s] %-32s (est. savings %.1f%%)"
            % (r.priority.upper(), r.title, r.estimated_savings_pct)
        )
        lines.append("      %s" % r.description)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #


def handle_capacity(state_dir: str = DEFAULT_STATE_DIR) -> str:
    it_loads = {"RACK-01": 8.0, "RACK-02": 11.0, "RACK-03": 6.0}
    cooling_loads = {"RACK-01": 7.5, "RACK-02": 10.5, "RACK-03": 5.5}
    compute_units = {"RACK-01": 24, "RACK-02": 36, "RACK-03": 18}
    plan = compute_capacity_plan(
        EXAMPLE_RACKS,
        it_loads_kw=it_loads,
        cooling_loads_kw=cooling_loads,
        compute_units_map=compute_units,
    )
    save_capacity_plan(plan, state_dir=state_dir)
    return _render_capacity(plan)


def handle_lifecycle(state_dir: str = DEFAULT_STATE_DIR) -> str:
    # Provision three representative assets idempotently-ish (each run
    # re-creates assets from a deterministic baseline so output is stable).
    assets = [
        ("DC-ASSET-01", "SVR-1001", "RACK-01", "2025-03-10", None),
        ("DC-ASSET-02", "SVR-1002", "RACK-02", "2024-07-20", "2027-01-01"),
        ("DC-ASSET-03", "SW-1003", "RACK-03", "2023-11-05", "2026-06-01"),
    ]
    from .lifecycle import _save_state

    # Reset to a deterministic baseline each run for stable CLI output.
    _save_state((), state_dir)
    for asset_id, service_tag, rack_id, purchase_date, eos in assets:
        provision(
            asset_id=asset_id,
            service_tag=service_tag,
            rack_id=rack_id,
            purchase_date=purchase_date,
            end_of_support_date=eos,
            state_dir=state_dir,
        )
    # Apply a deterministic lifecycle sequence: refresh asset 01, decommission
    # asset 03 (past EOS), showing transitions.
    refresh(
        asset_id="DC-ASSET-01",
        reason="Refresh to current-gen CPU, return to active",
        state_dir=state_dir,
    )
    decommission_cost_analysis(asset_id="DC-ASSET-03", state_dir=state_dir)
    report = lifecycle_report(state_dir=state_dir)
    return _render_lifecycle(report)


def handle_efficiency(state_dir: str = DEFAULT_STATE_DIR) -> str:
    report = compute_efficiency_report(
        facility_energy_kwh=1500.0,
        it_energy_kwh=1000.0,
        compute_units=50_000,
        power_watts=1_000_000.0,
        interval_kwh=1500.0,
        emission_factor_kg_co2e_per_kwh=0.45,
        pue_target=1.3,
    )
    save_efficiency_report(report, state_dir=state_dir)
    return _render_efficiency(report)


def dc_main(args: argparse.Namespace) -> int:
    state_dir = getattr(args, "state_dir", DEFAULT_STATE_DIR)
    if args.capacity:
        output = handle_capacity(state_dir=state_dir)
    elif args.lifecycle:
        output = handle_lifecycle(state_dir=state_dir)
    elif args.efficiency:
        output = handle_efficiency(state_dir=state_dir)
    else:
        print("[C-UAS] dc: specify --capacity, --lifecycle, or --efficiency")
        print("  c-uas dc --capacity")
        print("  c-uas dc --lifecycle")
        print("  c-uas dc --efficiency")
        return 1
    print(output)
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="c-uas dc",
        description="Data Center Lifecycle Decision Support (DCC concepts)",
    )
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 1
    return dc_main(args)


if __name__ == "__main__":
    import sys

    sys.exit(main())
