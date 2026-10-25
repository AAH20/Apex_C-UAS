"""Cost optimization: right-sizing recommendations, overcommitment cost
tradeoff, PUE improvement ROI, region migration carbon/cost analysis.

All functions are pure and deterministic. Figures are computed from real
engineering inputs and labeled illustrative where they represent operator
estimates.

State persists under ~/.c-uas-platform/finops/optimizer/ (outside the repo).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "finops")
OPTIMIZER_SUBDIR = "optimizer"
LATEST_FILENAME = "latest_optimizer.json"

# Default billing hours per month, electricity rate, carbon price.
DEFAULT_HOURS_PER_MONTH = 730.0
DEFAULT_ELECTRICITY_USD_PER_KWH = 0.12
DEFAULT_CARBON_USD_PER_TON = 50.0


@dataclass(frozen=True)
class RightSizingRecommendation:
    """Recommendation to right-size an overprovisioned resource."""

    resource_id: str
    current_allocated_kw: float
    recommended_kw: float
    savings_kw: float
    monthly_savings_usd: float
    utilization_pct: float
    reason: str


@dataclass(frozen=True)
class OvercommitmentTradeoff:
    """Cost vs risk tradeoff for overcommitting a resource."""

    resource_id: str
    committed_kw: float
    physical_kw: float
    overcommitment_pct: float
    extra_revenue_usd_per_month: float
    risk_penalty_usd_per_month: float
    net_tradeoff_usd_per_month: float
    recommended: bool  # True if net tradeoff is positive


@dataclass(frozen=True)
class PueImprovementRoi:
    """ROI analysis for lowering PUE (e.g. cooling / power efficiency)."""

    current_pue: float
    target_pue: float
    it_load_kw: float
    electricity_usd_per_kwh: float
    hours_per_month: float
    upgrade_cost_usd: float
    monthly_savings_usd: float
    annual_savings_usd: float
    payback_months: float
    roi_pct: float


@dataclass(frozen=True)
class RegionMigrationAnalysis:
    """Carbon/cost analysis for migrating a workload between regions."""

    source_region: str
    target_region: str
    power_kw: float
    hours_per_month: float
    source_carbon_intensity_gco2_per_kwh: float
    target_carbon_intensity_gco2_per_kwh: float
    source_carbon_kg_per_month: float
    target_carbon_kg_per_month: float
    carbon_reduction_kg_per_month: float
    carbon_cost_usd_per_ton: float
    source_carbon_cost_usd_per_month: float
    target_carbon_cost_usd_per_month: float
    carbon_cost_savings_usd_per_month: float
    carbon_reduction_pct: float


@dataclass(frozen=True)
class OptimizationRecommendation:
    """Aggregate optimization recommendation."""

    category: str  # "right_size" | "overcommitment" | "pue" | "region_migration"
    title: str
    description: str
    estimated_monthly_savings_usd: float
    priority: str  # "low" | "medium" | "high"


def right_size_recommendation(
    resource_id: str,
    current_allocated_kw: float,
    actual_peak_kw: float,
    electricity_usd_per_kwh: float = DEFAULT_ELECTRICITY_USD_PER_KWH,
    hours_per_month: float = DEFAULT_HOURS_PER_MONTH,
    headroom_pct: float = 20.0,
) -> RightSizingRecommendation:
    """Recommend right-sizing an overprovisioned resource.

    recommended_kw = actual_peak_kw * (1 + headroom_pct/100), floored at
    actual_peak_kw and capped at current_allocated_kw.
    savings = (current - recommended) * hours * rate.
    """
    if current_allocated_kw < 0:
        raise ValueError("current_allocated_kw must be >= 0")
    if actual_peak_kw < 0:
        raise ValueError("actual_peak_kw must be >= 0")
    if electricity_usd_per_kwh < 0:
        raise ValueError("electricity_usd_per_kwh must be >= 0")
    if hours_per_month <= 0:
        raise ValueError("hours_per_month must be > 0")
    if not 0.0 <= headroom_pct <= 100.0:
        raise ValueError("headroom_pct must be in [0, 100]")

    recommended_kw = actual_peak_kw * (1.0 + headroom_pct / 100.0)
    recommended_kw = max(recommended_kw, actual_peak_kw)
    recommended_kw = min(recommended_kw, current_allocated_kw)

    savings_kw = current_allocated_kw - recommended_kw
    monthly_savings = savings_kw * hours_per_month * electricity_usd_per_kwh

    utilization_pct = (
        (actual_peak_kw / current_allocated_kw * 100.0) if current_allocated_kw > 0 else 0.0
    )

    if savings_kw <= 0:
        reason = "No right-sizing opportunity; allocation matches demand."
    elif utilization_pct < 50.0:
        reason = "Significant overprovisioning; reduce allocation."
    else:
        reason = "Mild overprovisioning; consider modest reduction."

    return RightSizingRecommendation(
        resource_id=resource_id,
        current_allocated_kw=round(current_allocated_kw, 4),
        recommended_kw=round(recommended_kw, 4),
        savings_kw=round(savings_kw, 4),
        monthly_savings_usd=round(monthly_savings, 4),
        utilization_pct=round(utilization_pct, 2),
        reason=reason,
    )


def analyze_overcommitment_tradeoff(
    resource_id: str,
    committed_kw: float,
    physical_kw: float,
    extra_revenue_usd_per_month: float,
    risk_penalty_usd_per_month: float,
) -> OvercommitmentTradeoff:
    """Cost vs risk tradeoff for overcommitting a resource.

    overcommitment_pct = committed / physical * 100
    net_tradeoff = extra_revenue - risk_penalty
    recommended = net_tradeoff > 0
    """
    if committed_kw < 0:
        raise ValueError("committed_kw must be >= 0")
    if physical_kw <= 0:
        raise ValueError("physical_kw must be > 0")

    overcommitment_pct = (committed_kw / physical_kw) * 100.0
    net_tradeoff = extra_revenue_usd_per_month - risk_penalty_usd_per_month

    return OvercommitmentTradeoff(
        resource_id=resource_id,
        committed_kw=round(committed_kw, 4),
        physical_kw=round(physical_kw, 4),
        overcommitment_pct=round(overcommitment_pct, 2),
        extra_revenue_usd_per_month=round(extra_revenue_usd_per_month, 4),
        risk_penalty_usd_per_month=round(risk_penalty_usd_per_month, 4),
        net_tradeoff_usd_per_month=round(net_tradeoff, 4),
        recommended=net_tradeoff > 0,
    )


def analyze_pue_improvement_roi(
    current_pue: float,
    target_pue: float,
    it_load_kw: float,
    electricity_usd_per_kwh: float = DEFAULT_ELECTRICITY_USD_PER_KWH,
    hours_per_month: float = DEFAULT_HOURS_PER_MONTH,
    upgrade_cost_usd: float = 0.0,
) -> PueImprovementRoi:
    """ROI for lowering PUE from current to target.

    monthly_savings = (current_pue - target_pue) * it_load_kw * hours * rate
    payback_months = upgrade_cost / monthly_savings
    roi_pct = (annual_savings - upgrade_cost) / upgrade_cost * 100
    """
    if current_pue < 1.0:
        raise ValueError("current_pue must be >= 1.0")
    if target_pue < 1.0:
        raise ValueError("target_pue must be >= 1.0")
    if target_pue > current_pue:
        raise ValueError("target_pue must be <= current_pue (an improvement)")
    if it_load_kw < 0:
        raise ValueError("it_load_kw must be >= 0")
    if electricity_usd_per_kwh < 0:
        raise ValueError("electricity_usd_per_kwh must be >= 0")
    if hours_per_month <= 0:
        raise ValueError("hours_per_month must be > 0")
    if upgrade_cost_usd < 0:
        raise ValueError("upgrade_cost_usd must be >= 0")

    pue_delta = current_pue - target_pue
    monthly_savings = pue_delta * it_load_kw * hours_per_month * electricity_usd_per_kwh
    annual_savings = monthly_savings * 12.0

    if monthly_savings > 0 and upgrade_cost_usd > 0:
        payback_months = upgrade_cost_usd / monthly_savings
    else:
        payback_months = 0.0

    if upgrade_cost_usd > 0:
        roi_pct = ((annual_savings - upgrade_cost_usd) / upgrade_cost_usd) * 100.0
    else:
        # Free improvement: infinite ROI, report as 100% of annual savings.
        roi_pct = 100.0 if annual_savings > 0 else 0.0

    return PueImprovementRoi(
        current_pue=round(current_pue, 4),
        target_pue=round(target_pue, 4),
        it_load_kw=round(it_load_kw, 4),
        electricity_usd_per_kwh=electricity_usd_per_kwh,
        hours_per_month=hours_per_month,
        upgrade_cost_usd=round(upgrade_cost_usd, 4),
        monthly_savings_usd=round(monthly_savings, 4),
        annual_savings_usd=round(annual_savings, 4),
        payback_months=round(payback_months, 2),
        roi_pct=round(roi_pct, 2),
    )


def analyze_region_migration(
    source_region: str,
    target_region: str,
    power_kw: float,
    hours_per_month: float = DEFAULT_HOURS_PER_MONTH,
    carbon_usd_per_ton: float = DEFAULT_CARBON_USD_PER_TON,
    intensity_map: Optional[Dict[str, float]] = None,
) -> RegionMigrationAnalysis:
    """Carbon/cost analysis for migrating a workload between regions."""
    from .carbon import carbon_intensity_for_region

    if power_kw < 0:
        raise ValueError("power_kw must be >= 0")
    if hours_per_month <= 0:
        raise ValueError("hours_per_month must be > 0")
    if carbon_usd_per_ton < 0:
        raise ValueError("carbon_usd_per_ton must be >= 0")

    source_ci = carbon_intensity_for_region(source_region, intensity_map)
    target_ci = carbon_intensity_for_region(target_region, intensity_map)

    source_carbon_kg = power_kw * hours_per_month * source_ci.carbon_intensity_gco2_per_kwh / 1000.0
    target_carbon_kg = power_kw * hours_per_month * target_ci.carbon_intensity_gco2_per_kwh / 1000.0
    carbon_reduction_kg = source_carbon_kg - target_carbon_kg

    source_carbon_cost = (source_carbon_kg / 1000.0) * carbon_usd_per_ton
    target_carbon_cost = (target_carbon_kg / 1000.0) * carbon_usd_per_ton
    carbon_cost_savings = source_carbon_cost - target_carbon_cost

    carbon_reduction_pct = (
        (carbon_reduction_kg / source_carbon_kg * 100.0) if source_carbon_kg > 0 else 0.0
    )

    return RegionMigrationAnalysis(
        source_region=source_ci.region,
        target_region=target_ci.region,
        power_kw=round(power_kw, 4),
        hours_per_month=hours_per_month,
        source_carbon_intensity_gco2_per_kwh=source_ci.carbon_intensity_gco2_per_kwh,
        target_carbon_intensity_gco2_per_kwh=target_ci.carbon_intensity_gco2_per_kwh,
        source_carbon_kg_per_month=round(source_carbon_kg, 4),
        target_carbon_kg_per_month=round(target_carbon_kg, 4),
        carbon_reduction_kg_per_month=round(carbon_reduction_kg, 4),
        carbon_cost_usd_per_ton=carbon_usd_per_ton,
        source_carbon_cost_usd_per_month=round(source_carbon_cost, 6),
        target_carbon_cost_usd_per_month=round(target_carbon_cost, 6),
        carbon_cost_savings_usd_per_month=round(carbon_cost_savings, 6),
        carbon_reduction_pct=round(carbon_reduction_pct, 2),
    )


def build_optimization_recommendations(
    right_sizing: Optional[List[RightSizingRecommendation]] = None,
    overcommitment: Optional[List[OvercommitmentTradeoff]] = None,
    pue_roi: Optional[List[PueImprovementRoi]] = None,
    region_migration: Optional[List[RegionMigrationAnalysis]] = None,
) -> List[OptimizationRecommendation]:
    """Aggregate domain analyses into prioritized recommendations."""
    recommendations: List[OptimizationRecommendation] = []

    for rs in right_sizing or []:
        if rs.savings_kw > 0:
            priority = "high" if rs.utilization_pct < 50.0 else "medium"
            recommendations.append(
                OptimizationRecommendation(
                    category="right_size",
                    title=f"Right-size {rs.resource_id}",
                    description=rs.reason,
                    estimated_monthly_savings_usd=rs.monthly_savings_usd,
                    priority=priority,
                )
            )

    for oc in overcommitment or []:
        if oc.recommended:
            recommendations.append(
                OptimizationRecommendation(
                    category="overcommitment",
                    title=f"Accept overcommitment on {oc.resource_id}",
                    description=(
                        f"Net benefit ${oc.net_tradeoff_usd_per_month:,.2f}/month "
                        f"at {oc.overcommitment_pct:.1f}% overcommitment"
                    ),
                    estimated_monthly_savings_usd=oc.net_tradeoff_usd_per_month,
                    priority="medium",
                )
            )

    for roi in pue_roi or []:
        if roi.monthly_savings_usd > 0:
            priority = "high" if roi.payback_months <= 12 else "medium"
            recommendations.append(
                OptimizationRecommendation(
                    category="pue",
                    title=f"Improve PUE {roi.current_pue} -> {roi.target_pue}",
                    description=(
                        f"${roi.monthly_savings_usd:,.2f}/month savings, "
                        f"{roi.payback_months:.1f}-month payback"
                    ),
                    estimated_monthly_savings_usd=roi.monthly_savings_usd,
                    priority=priority,
                )
            )

    for mig in region_migration or []:
        if mig.carbon_reduction_kg_per_month > 0:
            recommendations.append(
                OptimizationRecommendation(
                    category="region_migration",
                    title=f"Migrate {mig.source_region} -> {mig.target_region}",
                    description=(
                        f"{mig.carbon_reduction_pct:.1f}% carbon reduction, "
                        f"${mig.carbon_cost_savings_usd_per_month:,.2f}/month "
                        "carbon cost savings"
                    ),
                    estimated_monthly_savings_usd=mig.carbon_cost_savings_usd_per_month,
                    priority="medium",
                )
            )

    recommendations.sort(key=lambda r: (-r.estimated_monthly_savings_usd, r.category, r.title))
    return recommendations


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def _config_hash(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def save_optimizer_result(
    result: dict,
    state_dir: str = DEFAULT_STATE_DIR,
) -> str:
    subdir = os.path.join(state_dir, OPTIMIZER_SUBDIR)
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, LATEST_FILENAME)
    record = {"config_hash": _config_hash(result), "result": result}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
    return path


def load_optimizer_result(state_dir: str = DEFAULT_STATE_DIR) -> Optional[dict]:
    path = os.path.join(state_dir, OPTIMIZER_SUBDIR, LATEST_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
