"""Unit economics: compute-per-dollar, cost-per-compute-unit, cost-per-watt,
rack cost per month, carbon cost per compute unit.

All functions are pure and deterministic. Figures are computed from real
engineering inputs and labeled illustrative where they represent operator
estimates.

State persists under ~/.c-uas-platform/finops/unit_cost/ (outside the repo).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Optional

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "finops")
UNIT_COST_SUBDIR = "unit_cost"
LATEST_FILENAME = "latest_unit_cost.json"

# Default billing hours per month and carbon cost per ton (USD).
DEFAULT_HOURS_PER_MONTH = 730.0
DEFAULT_CARBON_USD_PER_TON = 50.0  # illustrative carbon price


@dataclass(frozen=True)
class UnitCostInputs:
    """Inputs for a unit economics calculation."""

    compute_units: int  # useful compute units delivered (e.g. vCPU-hours)
    power_kw: float  # IT power draw in kW
    monthly_cost_usd: float  # total monthly cost attributable to this compute
    carbon_intensity_gco2_per_kwh: float = 0.0  # gCO2/kWh (0 => unknown)
    carbon_usd_per_ton: float = DEFAULT_CARBON_USD_PER_TON

    def __post_init__(self) -> None:
        if self.compute_units < 0:
            raise ValueError("compute_units must be >= 0")
        if self.power_kw < 0:
            raise ValueError("power_kw must be >= 0")
        if self.monthly_cost_usd < 0:
            raise ValueError("monthly_cost_usd must be >= 0")
        if self.carbon_intensity_gco2_per_kwh < 0:
            raise ValueError("carbon_intensity_gco2_per_kwh must be >= 0")
        if self.carbon_usd_per_ton < 0:
            raise ValueError("carbon_usd_per_ton must be >= 0")


@dataclass(frozen=True)
class UnitCostResult:
    """Result of a unit economics calculation."""

    compute_per_dollar: float  # compute units per USD
    cost_per_compute_unit_usd: float  # USD per compute unit
    cost_per_watt_usd: float  # USD per watt per month
    carbon_cost_per_compute_unit_usd: float  # USD carbon cost per compute unit
    monthly_cost_usd: float


@dataclass(frozen=True)
class RackCost:
    """Monthly cost for a rack at a given power draw and PUE."""

    rack_id: str
    rack_power_kw: float
    pue: float
    electricity_usd_per_kwh: float
    hours_per_month: float
    monthly_rack_cost_usd: float
    cost_per_compute_unit_usd: Optional[float] = None


def compute_unit_cost(inputs: UnitCostInputs) -> UnitCostResult:
    """Derive unit economics from cost, power, and compute inputs.

    - compute_per_dollar = compute_units / monthly_cost_usd
    - cost_per_compute_unit_usd = monthly_cost_usd / compute_units
    - cost_per_watt_usd = monthly_cost_usd / (power_kw * 1000)
    - carbon_cost_per_compute_unit_usd = (power_kw * hours * intensity / 1000 kg
      -> tons) * carbon_usd_per_ton / compute_units
    """
    monthly_cost = inputs.monthly_cost_usd
    compute_units = inputs.compute_units

    compute_per_dollar = compute_units / monthly_cost if monthly_cost > 0 else 0.0
    cost_per_compute_unit = monthly_cost / compute_units if compute_units > 0 else 0.0
    power_watts = inputs.power_kw * 1000.0
    cost_per_watt = monthly_cost / power_watts if power_watts > 0 else 0.0

    # Carbon cost per compute unit.
    energy_kwh = inputs.power_kw * DEFAULT_HOURS_PER_MONTH
    carbon_kg = energy_kwh * inputs.carbon_intensity_gco2_per_kwh / 1000.0
    carbon_tons = carbon_kg / 1000.0
    carbon_cost_total = carbon_tons * inputs.carbon_usd_per_ton
    carbon_cost_per_unit = carbon_cost_total / compute_units if compute_units > 0 else 0.0

    return UnitCostResult(
        compute_per_dollar=round(compute_per_dollar, 6),
        cost_per_compute_unit_usd=round(cost_per_compute_unit, 6),
        cost_per_watt_usd=round(cost_per_watt, 6),
        carbon_cost_per_compute_unit_usd=round(carbon_cost_per_unit, 6),
        monthly_cost_usd=round(monthly_cost, 4),
    )


def compute_rack_cost_per_month(
    rack_id: str,
    rack_power_kw: float,
    pue: float,
    electricity_usd_per_kwh: float,
    hours_per_month: float = DEFAULT_HOURS_PER_MONTH,
    compute_units: Optional[int] = None,
) -> RackCost:
    """Monthly cost for a rack, including facility overhead via PUE.

    monthly_rack_cost_usd = rack_power_kw * pue * hours * rate
    """
    from .cost_model import compute_power_draw

    if rack_power_kw < 0:
        raise ValueError("rack_power_kw must be >= 0")
    if pue < 1.0:
        raise ValueError("pue must be >= 1.0")
    if electricity_usd_per_kwh < 0:
        raise ValueError("electricity_usd_per_kwh must be >= 0")

    draw = compute_power_draw(rack_power_kw, pue)
    monthly_cost = draw.total_facility_kw * hours_per_month * electricity_usd_per_kwh

    cost_per_unit: Optional[float] = None
    if compute_units is not None and compute_units > 0 and monthly_cost > 0:
        cost_per_unit = round(monthly_cost / compute_units, 6)

    return RackCost(
        rack_id=rack_id,
        rack_power_kw=rack_power_kw,
        pue=draw.pue,
        electricity_usd_per_kwh=electricity_usd_per_kwh,
        hours_per_month=hours_per_month,
        monthly_rack_cost_usd=round(monthly_cost, 4),
        cost_per_compute_unit_usd=cost_per_unit,
    )


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def _config_hash(inputs: UnitCostInputs) -> str:
    payload = json.dumps(asdict(inputs), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def save_unit_cost(
    result: UnitCostResult,
    inputs: UnitCostInputs,
    state_dir: str = DEFAULT_STATE_DIR,
) -> str:
    subdir = os.path.join(state_dir, UNIT_COST_SUBDIR)
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, LATEST_FILENAME)
    record = {
        "config_hash": _config_hash(inputs),
        "inputs": asdict(inputs),
        "result": asdict(result),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
    return path


def load_unit_cost(state_dir: str = DEFAULT_STATE_DIR) -> Optional[dict]:
    path = os.path.join(state_dir, UNIT_COST_SUBDIR, LATEST_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
