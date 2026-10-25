"""Energy-to-compute efficiency: PUE, DCiE, compute per watt, carbon intensity,
and efficiency optimization recommendations.

Adapted from Data Center Commander (DCC) energy-to-compute accounting:
PUE = facility_energy / IT_energy for a declared boundary and aligned time
window; carbon = interval energy x location/time-specific emission factor.

All functions are pure and deterministic. Output is advisory only -- no
facility setpoints or actuation are changed by this module.

State persists under ~/.c-uas-platform/datacenter/efficiency/ (outside the repo).

License: AGPL-3.0.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "datacenter")
EFFICIENCY_SUBDIR = "efficiency"
LATEST_FILENAME = "latest_efficiency.json"

# Default grid emission factor (kg CO2e per kWh), illustrative US average.
DEFAULT_EMISSION_FACTOR_KG_CO2E_PER_KWH = 0.45
# PUE bands for efficiency rating.
PUE_EFFICIENT = 1.3
PUE_AVERAGE = 1.6
PUE_INEFFICIENT = 2.0


@dataclass(frozen=True)
class EfficiencyMetrics:
    """Core energy-to-compute efficiency metrics."""

    pue: float
    dcie: float
    compute_per_watt: float
    carbon_intensity_kg_co2e_per_kwh: float
    total_energy_kwh: float
    it_energy_kwh: float
    facility_energy_kwh: float


@dataclass(frozen=True)
class CarbonIntensity:
    """Carbon intensity for an interval, with method and factor provenance."""

    interval_kwh: float
    emission_factor_kg_co2e_per_kwh: float
    carbon_kg_co2e: float
    method: str  # "location-based" | "market-based"
    factor_source: str


@dataclass(frozen=True)
class Recommendation:
    """An efficiency optimization recommendation."""

    recommendation_id: str
    category: str  # "cooling" | "power" | "workload" | "consolidation"
    title: str
    description: str
    estimated_savings_pct: float
    priority: str  # "low" | "medium" | "high"


@dataclass(frozen=True)
class EfficiencyReport:
    """Deterministic efficiency report."""

    report_id: str
    config_hash: str
    metrics: EfficiencyMetrics
    carbon: CarbonIntensity
    recommendations: Tuple[Recommendation, ...]
    efficiency_rating: str  # "A" | "B" | "C" | "D" | "F"


def compute_pue(facility_energy_kwh: float, it_energy_kwh: float) -> float:
    """Power Usage Effectiveness = facility energy / IT energy.

    PUE >= 1.0. A value of 1.0 means all energy reaches IT equipment.
    Boundary, interval, and excluded loads must be declared by the caller.
    """
    if it_energy_kwh <= 0:
        return 0.0
    return facility_energy_kwh / it_energy_kwh


def compute_dcie(pue: float) -> float:
    """Data Center Infrastructure Efficiency = 1 / PUE (as a fraction)."""
    if pue <= 0:
        return 0.0
    return 1.0 / pue


def compute_compute_per_watt(compute_units: int, power_watts: float) -> float:
    """Useful compute units delivered per watt of power draw."""
    if power_watts <= 0:
        return 0.0
    return compute_units / power_watts


def compute_carbon_intensity(
    interval_kwh: float,
    emission_factor_kg_co2e_per_kwh: float = DEFAULT_EMISSION_FACTOR_KG_CO2E_PER_KWH,
    method: str = "location-based",
    factor_source: str = "grid-average-illustrative",
) -> CarbonIntensity:
    """Carbon intensity for an energy interval.

    carbon_kg_co2e = interval_kwh * emission_factor.
    """
    interval_kwh = max(interval_kwh, 0.0)
    emission_factor = max(emission_factor_kg_co2e_per_kwh, 0.0)
    carbon_kg_co2e = interval_kwh * emission_factor
    return CarbonIntensity(
        interval_kwh=round(interval_kwh, 4),
        emission_factor_kg_co2e_per_kwh=round(emission_factor, 6),
        carbon_kg_co2e=round(carbon_kg_co2e, 4),
        method=method,
        factor_source=factor_source,
    )


def _rating(pue: float) -> str:
    if pue <= PUE_EFFICIENT:
        return "A"
    if pue <= PUE_AVERAGE:
        return "B"
    if pue <= PUE_INEFFICIENT:
        return "C"
    if pue <= 2.5:
        return "D"
    return "F"


def efficiency_recommendations(
    metrics: EfficiencyMetrics,
    carbon: CarbonIntensity,
    pue_target: float = 1.3,
) -> Tuple[Recommendation, ...]:
    """Generate efficiency optimization recommendations from current metrics.

    Pure function: same inputs -> same recommendations, ordered by priority.
    """
    recs: List[Recommendation] = []

    if metrics.pue > pue_target:
        recs.append(
            Recommendation(
                recommendation_id="EFF-001",
                category="cooling",
                title="Improve cooling efficiency to lower PUE",
                description=(
                    "Current PUE %.2f exceeds target %.2f. Raising supply "
                    "temperature, improving airflow containment, or adopting "
                    "liquid cooling can reduce facility overhead."
                )
                % (metrics.pue, pue_target),
                estimated_savings_pct=round((metrics.pue - pue_target) / metrics.pue * 100.0, 1),
                priority="high" if metrics.pue >= PUE_INEFFICIENT else "medium",
            )
        )

    if metrics.compute_per_watt < 1.0:
        recs.append(
            Recommendation(
                recommendation_id="EFF-002",
                category="workload",
                title="Increase compute per watt",
                description=(
                    "Compute per watt is %.4f units/W. Consolidate idle "
                    "servers and shift workloads to higher-efficiency "
                    "generations to improve compute per watt."
                )
                % metrics.compute_per_watt,
                estimated_savings_pct=10.0,
                priority="medium",
            )
        )

    if metrics.pue > PUE_AVERAGE:
        recs.append(
            Recommendation(
                recommendation_id="EFF-003",
                category="power",
                title="Reduce facility power overhead",
                description=(
                    "Facility overhead is %.2f kWh vs %.2f kWh IT. UPS, "
                    "distribution losses, and lighting are candidates for "
                    "reduction."
                )
                % (
                    metrics.facility_energy_kwh - metrics.it_energy_kwh,
                    metrics.it_energy_kwh,
                ),
                estimated_savings_pct=5.0,
                priority="medium",
            )
        )

    if carbon.carbon_kg_co2e > 0:
        recs.append(
            Recommendation(
                recommendation_id="EFF-004",
                category="workload",
                title="Shift workloads to lower-carbon intervals",
                description=(
                    "Interval carbon intensity is %.4f kg CO2e/kWh (%s). "
                    "Schedule flexible workloads during low-carbon grid "
                    "periods to reduce emissions."
                )
                % (
                    carbon.carbon_kg_co2e / max(carbon.interval_kwh, 1e-9),
                    carbon.method,
                ),
                estimated_savings_pct=15.0,
                priority="low",
            )
        )

    if not recs:
        recs.append(
            Recommendation(
                recommendation_id="EFF-005",
                category="consolidation",
                title="Maintain current efficiency",
                description=(
                    "PUE %.2f is at or below target %.2f. Continue monitoring "
                    "and revalidate quarterly."
                )
                % (metrics.pue, pue_target),
                estimated_savings_pct=0.0,
                priority="low",
            )
        )

    return tuple(recs)


def _config_hash(metrics: EfficiencyMetrics, carbon: CarbonIntensity) -> str:
    payload = {"metrics": asdict(metrics), "carbon": asdict(carbon)}
    return "EFF-" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def compute_efficiency_report(
    facility_energy_kwh: float,
    it_energy_kwh: float,
    compute_units: int,
    power_watts: float,
    interval_kwh: Optional[float] = None,
    emission_factor_kg_co2e_per_kwh: float = DEFAULT_EMISSION_FACTOR_KG_CO2E_PER_KWH,
    pue_target: float = 1.3,
) -> EfficiencyReport:
    """Full energy-to-compute efficiency report. Pure and deterministic."""
    pue = compute_pue(facility_energy_kwh, it_energy_kwh)
    dcie = compute_dcie(pue)
    compute_per_watt = compute_compute_per_watt(compute_units, power_watts)
    interval = interval_kwh if interval_kwh is not None else facility_energy_kwh
    carbon = compute_carbon_intensity(
        interval_kwh=interval,
        emission_factor_kg_co2e_per_kwh=emission_factor_kg_co2e_per_kwh,
    )
    metrics = EfficiencyMetrics(
        pue=round(pue, 4),
        dcie=round(dcie, 4),
        compute_per_watt=round(compute_per_watt, 4),
        carbon_intensity_kg_co2e_per_kwh=round(carbon.emission_factor_kg_co2e_per_kwh, 6),
        total_energy_kwh=round(facility_energy_kwh, 4),
        it_energy_kwh=round(it_energy_kwh, 4),
        facility_energy_kwh=round(facility_energy_kwh, 4),
    )
    recommendations = efficiency_recommendations(metrics, carbon, pue_target=pue_target)
    config_hash = _config_hash(metrics, carbon)
    report_id = "eff-" + config_hash
    return EfficiencyReport(
        report_id=report_id,
        config_hash=config_hash,
        metrics=metrics,
        carbon=carbon,
        recommendations=recommendations,
        efficiency_rating=_rating(pue),
    )


def save_efficiency_report(report: EfficiencyReport, state_dir: str = DEFAULT_STATE_DIR) -> str:
    """Persist an efficiency report to JSON; return the file path."""
    subdir = os.path.join(state_dir, EFFICIENCY_SUBDIR)
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, LATEST_FILENAME)
    payload = {
        "report_id": report.report_id,
        "config_hash": report.config_hash,
        "metrics": asdict(report.metrics),
        "carbon": asdict(report.carbon),
        "recommendations": [asdict(r) for r in report.recommendations],
        "efficiency_rating": report.efficiency_rating,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return path


def load_efficiency_report(state_dir: str = DEFAULT_STATE_DIR) -> Optional[EfficiencyReport]:
    """Load the latest persisted efficiency report, or None if absent."""
    path = os.path.join(state_dir, EFFICIENCY_SUBDIR, LATEST_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return EfficiencyReport(
        report_id=payload["report_id"],
        config_hash=payload["config_hash"],
        metrics=EfficiencyMetrics(**payload["metrics"]),
        carbon=CarbonIntensity(**payload["carbon"]),
        recommendations=tuple(Recommendation(**r) for r in payload.get("recommendations", [])),
        efficiency_rating=payload["efficiency_rating"],
    )
