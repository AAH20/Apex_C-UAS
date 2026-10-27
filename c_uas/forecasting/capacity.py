"""Capacity forecast: given a demand forecast plus datacenter capacity (from
c_uas/datacenter), compute headroom, overcommitment risk, and recommended rack
additions.

Builds on c_uas/datacenter/capacity.py (RackSpec, compute_headroom,
detect_overcommitment) for the underlying engineering math. All functions are
pure; same inputs produce the same outputs.

License: AGPL-3.0.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, Tuple

from c_uas.datacenter.capacity import (
    DEFAULT_PUE,
    HeadroomAnalysis,
    OvercommitmentResult,
    RackSpec,
)

from .models import ForecastPoint


@dataclass(frozen=True)
class ForecastCapacity:
    """Deterministic capacity assessment derived from a demand forecast."""

    stream_id: str
    horizon: int
    peak_demand: float  # forecast peak (same units as input, e.g. kW or requests/s)
    mean_demand: float
    total_capacity: float  # provisioned capacity in the same units
    headroom: float  # total_capacity - peak_demand
    headroom_pct: float  # headroom / total_capacity * 100
    overcommitment_risk: str  # low | medium | high | critical
    overcommitted: bool  # peak demand exceeds capacity
    recommended_rack_additions: int  # racks to add to restore target headroom
    limiting_factor: str  # "power" | "cooling" | "space" | "balanced"


@dataclass(frozen=True)
class CapacityForecastInputs:
    stream_id: str
    forecast_points: Tuple[ForecastPoint, ...]
    rack_specs: Tuple[RackSpec, ...]
    current_it_loads_kw: Tuple[float, ...]  # per-rack current IT load (aligned to rack_specs)
    headroom_target_pct: float = 20.0


def _risk_label(overcommit_pct: float) -> str:
    if overcommit_pct >= 120.0:
        return "critical"
    if overcommit_pct >= 105.0:
        return "high"
    if overcommit_pct >= 100.0:
        return "medium"
    return "low"


def headroom_from_forecast(
    stream_id: str,
    forecast_points: Sequence[ForecastPoint],
    total_capacity: float,
    headroom_target_pct: float = 20.0,
) -> ForecastCapacity:
    """Assess capacity headroom against a demand forecast.

    peak_demand drives the assessment. headroom = capacity - peak; if peak
    exceeds capacity the system is overcommitted.
    """

    points = tuple(forecast_points)
    values: Tuple[float, ...] = tuple(p.value for p in points) if points else (0.0,)

    peak_demand = max(values)
    mean_demand = sum(values) / len(values)
    total_capacity = max(total_capacity, 0.0)

    headroom = total_capacity - peak_demand
    headroom_pct = (headroom / total_capacity * 100.0) if total_capacity > 0 else 100.0
    overcommitted = peak_demand > total_capacity
    overcommit_pct = (peak_demand / total_capacity * 100.0) if total_capacity > 0 else 0.0
    risk = _risk_label(overcommit_pct)

    # Recommended rack additions: enough rack capacity to close the headroom
    # gap up to the target. Expressed as a whole number of racks; a single
    # "standard rack" is assumed to contribute 10.0 kW of capacity.
    rack_capacity_kw = 10.0
    deficit = max(
        peak_demand + total_capacity * (headroom_target_pct / 100.0) - total_capacity,
        0.0,
    )
    recommended = int(-(-deficit // rack_capacity_kw)) if deficit > 0 else 0  # ceil division

    return ForecastCapacity(
        stream_id=stream_id,
        horizon=len(points),
        peak_demand=round(peak_demand, 4),
        mean_demand=round(mean_demand, 4),
        total_capacity=round(total_capacity, 4),
        headroom=round(headroom, 4),
        headroom_pct=round(headroom_pct, 2),
        overcommitment_risk=risk,
        overcommitted=overcommitted,
        recommended_rack_additions=recommended,
        limiting_factor="balanced",
    )


def headroom_from_forecast_with_racks(
    inputs: CapacityForecastInputs,
) -> Tuple[ForecastCapacity, Tuple[HeadroomAnalysis, ...], Tuple[OvercommitmentResult, ...]]:
    """Full capacity assessment using real datacenter rack specs.

    Computes per-rack headroom and overcommitment via c_uas/datacenter/capacity.py,
    then derives a stream-level ForecastCapacity from the aggregate.
    """

    specs = tuple(inputs.rack_specs)
    loads = tuple(inputs.current_it_loads_kw)
    # Align loads to specs (pad with zeros if fewer loads than racks).
    if len(loads) < len(specs):
        loads = loads + (0.0,) * (len(specs) - len(loads))
    load_map = {s.rack_id: loads[i] for i, s in enumerate(specs)}
    cooling_map = {s.rack_id: loads[i] for i, s in enumerate(specs)}
    units_map = {s.rack_id: 0 for i, s in enumerate(specs)}

    from c_uas.datacenter.capacity import compute_capacity_plan

    plan = compute_capacity_plan(
        specs,
        it_loads_kw=load_map,
        cooling_loads_kw=cooling_map,
        compute_units_map=units_map,
        pue=DEFAULT_PUE,
    )

    points = tuple(inputs.forecast_points)
    values = tuple(p.value for p in points) if len(points) > 0 else (0.0,)
    peak_demand = max(values)
    total_capacity = sum(s.max_power_kw for s in specs)

    headroom = total_capacity - peak_demand
    headroom_pct = (headroom / total_capacity * 100.0) if total_capacity > 0 else 100.0
    overcommitted = peak_demand > total_capacity
    overcommit_pct = (peak_demand / total_capacity * 100.0) if total_capacity > 0 else 0.0
    risk = _risk_label(overcommit_pct)

    deficit = max(
        peak_demand + total_capacity * (inputs.headroom_target_pct / 100.0) - total_capacity,
        0.0,
    )
    rack_capacity_kw = 10.0
    recommended = int(-(-deficit // rack_capacity_kw)) if deficit > 0 else 0

    # Limiting factor: worst headroom across racks.
    limiting = "balanced"
    if plan.headroom:
        worst = min(
            plan.headroom,
            key=lambda h: min(h.headroom_power_pct, h.headroom_cooling_pct, h.headroom_units_pct),
        )
        limiting = worst.limiting_factor

    capacity = ForecastCapacity(
        stream_id=inputs.stream_id,
        horizon=len(points),
        peak_demand=round(peak_demand, 4),
        mean_demand=round(sum(values) / len(values), 4),
        total_capacity=round(total_capacity, 4),
        headroom=round(headroom, 4),
        headroom_pct=round(headroom_pct, 2),
        overcommitment_risk=risk,
        overcommitted=overcommitted,
        recommended_rack_additions=recommended,
        limiting_factor=limiting,
    )
    return capacity, plan.headroom, plan.overcommitment


def recommended_rack_additions(
    peak_demand: float,
    total_capacity: float,
    headroom_target_pct: float = 20.0,
    rack_capacity_kw: float = 10.0,
) -> int:
    """Number of additional racks needed so that peak demand plus target
    headroom fits within total capacity."""

    rack_capacity_kw = max(rack_capacity_kw, 0.001)
    total_capacity = max(total_capacity, 0.0)
    deficit = max(
        peak_demand + total_capacity * (headroom_target_pct / 100.0) - total_capacity,
        0.0,
    )
    if deficit <= 0:
        return 0
    return int(-(-deficit // rack_capacity_kw))  # ceil division
