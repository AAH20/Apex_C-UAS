"""FinOps / Cost Optimization module for the C-UAS platform.

Models infrastructure cost from power, cooling, compute, and carbon intensity:
cost model (IT load -> facility overhead -> monthly power cost), unit economics
(compute-per-dollar, cost-per-compute-unit, rack cost per month), carbon
intensity by region, and cost optimization (right-sizing, overcommitment,
PUE improvement ROI, region migration).

All functions are pure and deterministic. Output is advisory only -- no
facility actuation. State persists under ~/.c-uas-platform/finops/ (outside
the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

from .carbon import (
    REGION_CARBON_INTENSITY,
    CarbonIntensity,
    CarbonResult,
    carbon_cost_per_ton,
    carbon_intensity_for_region,
    carbon_per_compute_hour,
    ranked_regions_by_carbon,
)
from .cli import build_subparser, finops_main
from .cost_model import (
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
from .optimizer import (
    OptimizationRecommendation,
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
from .unit_cost import (
    RackCost,
    UnitCostInputs,
    UnitCostResult,
    compute_rack_cost_per_month,
    compute_unit_cost,
)

__all__ = [
    "build_subparser",
    "finops_main",
    # cost model
    "DEFAULT_PUE",
    "DEFAULT_HOURS_PER_MONTH",
    "DEFAULT_ELECTRICITY_USD_PER_KWH",
    "ITLoadConfig",
    "PowerDraw",
    "FacilityCost",
    "compute_power_draw",
    "compute_monthly_power_cost",
    "compute_facility_cost",
    "pue_cost_multiplier",
    # unit cost
    "UnitCostInputs",
    "UnitCostResult",
    "RackCost",
    "compute_unit_cost",
    "compute_rack_cost_per_month",
    # carbon
    "REGION_CARBON_INTENSITY",
    "CarbonIntensity",
    "CarbonResult",
    "carbon_intensity_for_region",
    "carbon_per_compute_hour",
    "carbon_cost_per_ton",
    "ranked_regions_by_carbon",
    # optimizer
    "RightSizingRecommendation",
    "OvercommitmentTradeoff",
    "PueImprovementRoi",
    "RegionMigrationAnalysis",
    "OptimizationRecommendation",
    "right_size_recommendation",
    "analyze_overcommitment_tradeoff",
    "analyze_pue_improvement_roi",
    "analyze_region_migration",
    "build_optimization_recommendations",
]
