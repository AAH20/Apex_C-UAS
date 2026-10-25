"""Data Center Lifecycle Decision Support module.

Integrates Data Center Commander (DCC) concepts into the C-UAS platform:
production-grade capacity planning, lifecycle decisions, and energy-to-compute
efficiency analysis. All evaluations are deterministic, advisory (never
actuate facility systems), and computed from real inputs -- no mocks, no
fabricated metrics, no network.

State persists under ~/.c-uas-platform/datacenter/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

from .capacity import (
    DEFAULT_STATE_DIR,
    CapacityPlan,
    CoolingLoad,
    HeadroomAnalysis,
    OvercommitmentResult,
    PowerDraw,
    RackUtilization,
    compute_capacity_plan,
    compute_cooling_load,
    compute_headroom,
    compute_power_draw,
    compute_rack_utilization,
    detect_overcommitment,
)
from .cli import build_subparser, dc_main
from .efficiency import (
    CarbonIntensity,
    EfficiencyMetrics,
    Recommendation,
    compute_carbon_intensity,
    compute_compute_per_watt,
    compute_dcie,
    compute_pue,
    efficiency_recommendations,
)
from .lifecycle import (
    AssetRecord,
    LifecycleDecision,
    decommission,
    decommission_cost_analysis,
    provision,
    refresh,
    retire,
    track_stage,
)

__all__ = [
    "DEFAULT_STATE_DIR",
    "build_subparser",
    "dc_main",
    # capacity
    "CapacityPlan",
    "CoolingLoad",
    "HeadroomAnalysis",
    "OvercommitmentResult",
    "PowerDraw",
    "RackUtilization",
    "compute_capacity_plan",
    "compute_cooling_load",
    "compute_headroom",
    "compute_power_draw",
    "compute_rack_utilization",
    "detect_overcommitment",
    # efficiency
    "CarbonIntensity",
    "EfficiencyMetrics",
    "Recommendation",
    "compute_carbon_intensity",
    "compute_compute_per_watt",
    "compute_dcie",
    "compute_pue",
    "efficiency_recommendations",
    # lifecycle
    "AssetRecord",
    "LifecycleDecision",
    "decommission",
    "decommission_cost_analysis",
    "provision",
    "refresh",
    "retire",
    "track_stage",
]
