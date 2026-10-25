"""Data center capacity planning: power draw, cooling load, compute density,
rack utilization, headroom analysis, overcommitment detection.

All functions are pure (same input -> same output) and operate on real
engineering values. Capacity plans are persisted to JSON under
~/.c-uas-platform/datacenter/capacity/ so results survive across sessions.
Nothing in this module actuates facility equipment -- output is advisory only.

License: AGPL-3.0.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "datacenter")
CAPACITY_SUBDIR = "capacity"
LATEST_FILENAME = "latest_capacity.json"

# Engineering reference defaults (illustrative; operators should supply
# site-specific values). PUE of 1.5 is a common industry benchmark.
DEFAULT_PUE = 1.5
# Cooling watts required per kW of IT load (approx. 35% of IT load at PUE 1.5).
DEFAULT_COOLING_WATTS_PER_KW_IT = 350.0
# Recommended maximum continuous rack utilization (headroom for transients).
MAX_RACK_UTILIZATION_PCT = 85.0
# Target headroom margin.
HEADROOM_TARGET_PCT = 20.0

# Overcommitment risk bands (committed-over-physical percent).
RISK_BANDS: List[Tuple[float, str]] = [
    (120.0, "critical"),
    (105.0, "high"),
    (100.0, "medium"),
    (0.0, "low"),
]


@dataclass(frozen=True)
class RackSpec:
    """Physical limits of a single rack."""

    rack_id: str
    max_power_kw: float
    max_cooling_kw: float
    max_rack_units: int


@dataclass(frozen=True)
class PowerDraw:
    """IT and facility power draw for a rack/site."""

    it_load_kw: float
    facility_overhead_kw: float
    total_facility_kw: float
    pue: float


@dataclass(frozen=True)
class CoolingLoad:
    """Cooling demand vs capacity for a rack/site."""

    it_heat_load_kw: float
    cooling_capacity_kw: float
    cooling_utilization_pct: float
    thermal_margin_kw: float


@dataclass(frozen=True)
class ComputeDensity:
    """Compute density: useful compute per unit of power and space."""

    compute_units: int
    power_kw: float
    compute_per_kw: float
    rack_units_used: int
    rack_units_total: int
    rack_density_pct: float


@dataclass(frozen=True)
class RackUtilization:
    """Aggregate utilization of a single rack across power, cooling, space."""

    rack_id: str
    power_utilization_pct: float
    cooling_utilization_pct: float
    compute_utilization_pct: float
    overall_utilization_pct: float
    headroom_pct: float


@dataclass(frozen=True)
class HeadroomAnalysis:
    """Remaining headroom per resource and the limiting factor."""

    rack_id: str
    available_power_kw: float
    available_cooling_kw: float
    available_rack_units: int
    headroom_power_pct: float
    headroom_cooling_pct: float
    headroom_units_pct: float
    limiting_factor: str  # "power" | "cooling" | "space" | "balanced"


@dataclass(frozen=True)
class OvercommitmentResult:
    """Committed vs physical resources and overcommitment risk."""

    rack_id: str
    committed_power_kw: float
    committed_cooling_kw: float
    committed_units: int
    physical_power_kw: float
    physical_cooling_kw: float
    physical_units: int
    power_overcommit_pct: float
    cooling_overcommit_pct: float
    space_overcommit_pct: float
    overcommitted: bool
    risk_level: str  # "low" | "medium" | "high" | "critical"


@dataclass(frozen=True)
class CapacityPlan:
    """Deterministic capacity plan result."""

    plan_id: str
    config_hash: str
    racks: Tuple[RackUtilization, ...]
    headroom: Tuple[HeadroomAnalysis, ...]
    overcommitment: Tuple[OvercommitmentResult, ...]
    total_it_load_kw: float
    total_facility_kw: float
    overall_utilization_pct: float
    overcommitted_racks: int


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def _risk_level(max_overcommit_pct: float) -> str:
    for threshold, label in RISK_BANDS:
        if max_overcommit_pct >= threshold:
            return label
    return "low"


def compute_power_draw(it_load_kw: float, pue: float = DEFAULT_PUE) -> PowerDraw:
    """Total facility power draw from IT load and PUE.

    total_facility_kw = it_load_kw * pue
    facility_overhead_kw = total_facility_kw - it_load_kw
    """
    pue = max(pue, 1.0)
    total_facility_kw = it_load_kw * pue
    facility_overhead_kw = total_facility_kw - it_load_kw
    return PowerDraw(
        it_load_kw=round(it_load_kw, 4),
        facility_overhead_kw=round(facility_overhead_kw, 4),
        total_facility_kw=round(total_facility_kw, 4),
        pue=round(pue, 4),
    )


def compute_cooling_load(
    it_load_kw: float,
    cooling_capacity_kw: float,
    cooling_watts_per_kw_it: float = DEFAULT_COOLING_WATTS_PER_KW_IT,
) -> CoolingLoad:
    """Cooling demand vs capacity.

    IT equipment converts essentially all electrical draw to heat, so the
    IT heat load (kW) is approximately equal to the IT electrical load (kW).
    """
    cooling_capacity_kw = max(cooling_capacity_kw, 0.0)
    it_heat_load_kw = it_load_kw
    if cooling_capacity_kw > 0:
        cooling_utilization_pct = (it_heat_load_kw / cooling_capacity_kw) * 100.0
    else:
        cooling_utilization_pct = 0.0 if it_heat_load_kw == 0 else 100.0
    thermal_margin_kw = cooling_capacity_kw - it_heat_load_kw
    return CoolingLoad(
        it_heat_load_kw=round(it_heat_load_kw, 4),
        cooling_capacity_kw=round(cooling_capacity_kw, 4),
        cooling_utilization_pct=round(_clamp(cooling_utilization_pct), 2),
        thermal_margin_kw=round(thermal_margin_kw, 4),
    )


def compute_compute_density(
    compute_units: int,
    power_kw: float,
    rack_units_used: int,
    rack_units_total: int,
) -> ComputeDensity:
    """Compute per kW and rack space density.

    compute_per_kw = compute_units / power_kw
    rack_density_pct = rack_units_used / rack_units_total * 100
    """
    power_kw = max(power_kw, 0.0)
    rack_units_total = max(rack_units_total, 1)
    compute_per_kw = (compute_units / power_kw) if power_kw > 0 else 0.0
    rack_density_pct = (rack_units_used / rack_units_total) * 100.0
    return ComputeDensity(
        compute_units=compute_units,
        power_kw=round(power_kw, 4),
        compute_per_kw=round(compute_per_kw, 4),
        rack_units_used=rack_units_used,
        rack_units_total=rack_units_total,
        rack_density_pct=round(_clamp(rack_density_pct), 2),
    )


def compute_rack_utilization(
    rack_id: str,
    it_load_kw: float,
    cooling_load_kw: float,
    cooling_capacity_kw: float,
    rack_spec: RackSpec,
    compute_units: int = 0,
) -> RackUtilization:
    """Aggregate rack utilization across power, cooling, and space.

    overall_utilization_pct is the mean of the three resource utilizations;
    headroom_pct = 100 - overall (bounded to [0, 100]).
    """
    power_utilization_pct = (
        (it_load_kw / rack_spec.max_power_kw) * 100.0 if rack_spec.max_power_kw > 0 else 0.0
    )
    cooling_utilization_pct = (
        (cooling_load_kw / rack_spec.max_cooling_kw) * 100.0
        if rack_spec.max_cooling_kw > 0
        else 0.0
    )
    compute_utilization_pct = (
        (compute_units / rack_spec.max_rack_units) * 100.0 if rack_spec.max_rack_units > 0 else 0.0
    )
    overall = (power_utilization_pct + cooling_utilization_pct + compute_utilization_pct) / 3.0
    headroom_pct = 100.0 - overall
    return RackUtilization(
        rack_id=rack_id,
        power_utilization_pct=round(_clamp(power_utilization_pct), 2),
        cooling_utilization_pct=round(_clamp(cooling_utilization_pct), 2),
        compute_utilization_pct=round(_clamp(compute_utilization_pct), 2),
        overall_utilization_pct=round(_clamp(overall), 2),
        headroom_pct=round(_clamp(headroom_pct), 2),
    )


def compute_headroom(
    rack_id: str,
    it_load_kw: float,
    cooling_load_kw: float,
    compute_units: int,
    rack_spec: RackSpec,
) -> HeadroomAnalysis:
    """Remaining headroom per resource and the limiting factor.

    The limiting factor is the resource with the least headroom percentage.
    """
    available_power_kw = rack_spec.max_power_kw - it_load_kw
    available_cooling_kw = rack_spec.max_cooling_kw - cooling_load_kw
    available_units = rack_spec.max_rack_units - compute_units

    headroom_power_pct = (
        (available_power_kw / rack_spec.max_power_kw) * 100.0
        if rack_spec.max_power_kw > 0
        else 100.0
    )
    headroom_cooling_pct = (
        (available_cooling_kw / rack_spec.max_cooling_kw) * 100.0
        if rack_spec.max_cooling_kw > 0
        else 100.0
    )
    headroom_units_pct = (
        (available_units / rack_spec.max_rack_units) * 100.0
        if rack_spec.max_rack_units > 0
        else 100.0
    )

    headrooms = {
        "power": headroom_power_pct,
        "cooling": headroom_cooling_pct,
        "space": headroom_units_pct,
    }
    limiting_factor = min(headrooms, key=headrooms.get)  # type: ignore[arg-type]
    if all(h >= HEADROOM_TARGET_PCT for h in headrooms.values()):
        limiting_factor = "balanced"

    return HeadroomAnalysis(
        rack_id=rack_id,
        available_power_kw=round(available_power_kw, 4),
        available_cooling_kw=round(available_cooling_kw, 4),
        available_rack_units=max(available_units, 0),
        headroom_power_pct=round(_clamp(headroom_power_pct), 2),
        headroom_cooling_pct=round(_clamp(headroom_cooling_pct), 2),
        headroom_units_pct=round(_clamp(headroom_units_pct), 2),
        limiting_factor=limiting_factor,
    )


def detect_overcommitment(
    rack_id: str,
    committed_power_kw: float,
    committed_cooling_kw: float,
    committed_units: int,
    rack_spec: RackSpec,
) -> OvercommitmentResult:
    """Detect overcommitment: committed workload vs physical capacity.

    overcommit_pct = committed / physical * 100. Values > 100 indicate
    overcommitment. Risk level is driven by the worst resource.
    """
    power_overcommit_pct = (
        (committed_power_kw / rack_spec.max_power_kw) * 100.0 if rack_spec.max_power_kw > 0 else 0.0
    )
    cooling_overcommit_pct = (
        (committed_cooling_kw / rack_spec.max_cooling_kw) * 100.0
        if rack_spec.max_cooling_kw > 0
        else 0.0
    )
    space_overcommit_pct = (
        (committed_units / rack_spec.max_rack_units) * 100.0
        if rack_spec.max_rack_units > 0
        else 0.0
    )
    max_overcommit = max(power_overcommit_pct, cooling_overcommit_pct, space_overcommit_pct)
    overcommitted = max_overcommit > 100.0
    return OvercommitmentResult(
        rack_id=rack_id,
        committed_power_kw=round(committed_power_kw, 4),
        committed_cooling_kw=round(committed_cooling_kw, 4),
        committed_units=committed_units,
        physical_power_kw=round(rack_spec.max_power_kw, 4),
        physical_cooling_kw=round(rack_spec.max_cooling_kw, 4),
        physical_units=rack_spec.max_rack_units,
        power_overcommit_pct=round(max(power_overcommit_pct, 0.0), 2),
        cooling_overcommit_pct=round(max(cooling_overcommit_pct, 0.0), 2),
        space_overcommit_pct=round(max(space_overcommit_pct, 0.0), 2),
        overcommitted=overcommitted,
        risk_level=_risk_level(max_overcommit),
    )


def _config_hash(specs: Tuple[RackSpec, ...]) -> str:
    payload = [asdict(s) for s in specs]
    return "CAP-" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def compute_capacity_plan(
    specs: Tuple[RackSpec, ...],
    it_loads_kw: Dict[str, float],
    cooling_loads_kw: Dict[str, float],
    compute_units_map: Optional[Dict[str, int]] = None,
    pue: float = DEFAULT_PUE,
) -> CapacityPlan:
    """Full capacity plan across multiple racks.

    Pure function: given the same specs/loads it always returns the same plan.
    """
    compute_units_map = compute_units_map or {}
    plan_id = "plan-" + _config_hash(specs)
    config_hash = _config_hash(specs)

    rack_utils: List[RackUtilization] = []
    headrooms: List[HeadroomAnalysis] = []
    overcommitments: List[OvercommitmentResult] = []

    total_it_load = 0.0
    total_facility = 0.0
    overcommitted = 0

    for spec in sorted(specs, key=lambda s: s.rack_id):
        it_load = it_loads_kw.get(spec.rack_id, 0.0)
        cooling_load = cooling_loads_kw.get(spec.rack_id, it_load)
        units = compute_units_map.get(spec.rack_id, 0)

        draw = compute_power_draw(it_load, pue=pue)
        total_it_load += draw.it_load_kw
        total_facility += draw.total_facility_kw

        rack_utils.append(
            compute_rack_utilization(
                spec.rack_id, it_load, cooling_load, spec.max_cooling_kw, spec, units
            )
        )
        headrooms.append(compute_headroom(spec.rack_id, it_load, cooling_load, units, spec))
        occ = detect_overcommitment(
            spec.rack_id,
            committed_power_kw=it_load,
            committed_cooling_kw=cooling_load,
            committed_units=units,
            rack_spec=spec,
        )
        overcommitments.append(occ)
        if occ.overcommitted:
            overcommitted += 1

    total_racks = len(specs)
    overall_utilization = (
        sum(r.overall_utilization_pct for r in rack_utils) / total_racks if total_racks else 0.0
    )

    return CapacityPlan(
        plan_id=plan_id,
        config_hash=config_hash,
        racks=tuple(rack_utils),
        headroom=tuple(headrooms),
        overcommitment=tuple(overcommitments),
        total_it_load_kw=round(total_it_load, 4),
        total_facility_kw=round(total_facility, 4),
        overall_utilization_pct=round(_clamp(overall_utilization), 2),
        overcommitted_racks=overcommitted,
    )


def save_capacity_plan(plan: CapacityPlan, state_dir: str = DEFAULT_STATE_DIR) -> str:
    """Persist a capacity plan to JSON; return the file path."""
    subdir = os.path.join(state_dir, CAPACITY_SUBDIR)
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, LATEST_FILENAME)
    payload = {
        "plan_id": plan.plan_id,
        "config_hash": plan.config_hash,
        "racks": [asdict(r) for r in plan.racks],
        "headroom": [asdict(h) for h in plan.headroom],
        "overcommitment": [asdict(o) for o in plan.overcommitment],
        "total_it_load_kw": plan.total_it_load_kw,
        "total_facility_kw": plan.total_facility_kw,
        "overall_utilization_pct": plan.overall_utilization_pct,
        "overcommitted_racks": plan.overcommitted_racks,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return path


def load_capacity_plan(state_dir: str = DEFAULT_STATE_DIR) -> Optional[CapacityPlan]:
    """Load the latest persisted capacity plan, or None if absent."""
    path = os.path.join(state_dir, CAPACITY_SUBDIR, LATEST_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return CapacityPlan(
        plan_id=payload["plan_id"],
        config_hash=payload["config_hash"],
        racks=tuple(RackUtilization(**r) for r in payload["racks"]),
        headroom=tuple(HeadroomAnalysis(**h) for h in payload["headroom"]),
        overcommitment=tuple(OvercommitmentResult(**o) for o in payload["overcommitment"]),
        total_it_load_kw=payload["total_it_load_kw"],
        total_facility_kw=payload["total_facility_kw"],
        overall_utilization_pct=payload["overall_utilization_pct"],
        overcommitted_racks=payload["overcommitted_racks"],
    )
