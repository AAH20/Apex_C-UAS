"""Cost model: IT load kW -> facility overhead -> total facility kW -> monthly
power cost ($/kWh), cooling cost share, PUE-based cost multiplier.

All functions are pure and deterministic. Figures are computed from real
engineering inputs and labeled illustrative where they represent operator
estimates rather than measured site data.

State persists under ~/.c-uas-platform/finops/cost/ (outside the repo).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Optional

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "finops")
COST_SUBDIR = "cost"
LATEST_FILENAME = "latest_cost.json"

# Engineering reference defaults (illustrative; operators should supply
# site-specific values). PUE of 1.5 is a common industry benchmark.
DEFAULT_PUE = 1.5
# Default industrial electricity rate, USD per kWh.
DEFAULT_ELECTRICITY_USD_PER_KWH = 0.12
# Default billing hours per month (365 days * 24 / 12).
DEFAULT_HOURS_PER_MONTH = 730.0
# Cooling share of facility overhead energy (illustrative; typical range 30-50%).
DEFAULT_COOLING_SHARE_OF_OVERHEAD_PCT = 40.0


@dataclass(frozen=True)
class ITLoadConfig:
    """Input configuration for a cost model run."""

    it_load_kw: float
    pue: float = DEFAULT_PUE
    electricity_usd_per_kwh: float = DEFAULT_ELECTRICITY_USD_PER_KWH
    hours_per_month: float = DEFAULT_HOURS_PER_MONTH
    cooling_share_of_overhead_pct: float = DEFAULT_COOLING_SHARE_OF_OVERHEAD_PCT

    def __post_init__(self) -> None:
        if self.it_load_kw < 0:
            raise ValueError("it_load_kw must be >= 0")
        if self.pue < 1.0:
            raise ValueError("pue must be >= 1.0")
        if self.electricity_usd_per_kwh < 0:
            raise ValueError("electricity_usd_per_kwh must be >= 0")
        if self.hours_per_month <= 0:
            raise ValueError("hours_per_month must be > 0")
        if not 0.0 <= self.cooling_share_of_overhead_pct <= 100.0:
            raise ValueError("cooling_share_of_overhead_pct must be in [0, 100]")


@dataclass(frozen=True)
class PowerDraw:
    """IT and facility power draw for a load."""

    it_load_kw: float
    facility_overhead_kw: float
    total_facility_kw: float
    pue: float


@dataclass(frozen=True)
class FacilityCost:
    """Monthly facility cost breakdown derived from IT load and PUE."""

    it_load_kw: float
    total_facility_kw: float
    monthly_power_cost_usd: float
    cooling_cost_usd: float
    cooling_cost_share_pct: float
    pue_cost_multiplier: float
    it_monthly_cost_usd: float
    overhead_monthly_cost_usd: float


def compute_power_draw(it_load_kw: float, pue: float = DEFAULT_PUE) -> PowerDraw:
    """Total facility kW from IT load and PUE.

    total_facility_kw = it_load_kw * pue
    facility_overhead_kw = total_facility_kw - it_load_kw
    PUE is floored at 1.0.
    """
    if it_load_kw < 0:
        raise ValueError("it_load_kw must be >= 0")
    effective_pue = max(pue, 1.0)
    total_facility_kw = it_load_kw * effective_pue
    facility_overhead_kw = total_facility_kw - it_load_kw
    return PowerDraw(
        it_load_kw=it_load_kw,
        facility_overhead_kw=facility_overhead_kw,
        total_facility_kw=total_facility_kw,
        pue=effective_pue,
    )


def compute_monthly_power_cost(
    it_load_kw: float,
    pue: float = DEFAULT_PUE,
    electricity_usd_per_kwh: float = DEFAULT_ELECTRICITY_USD_PER_KWH,
    hours_per_month: float = DEFAULT_HOURS_PER_MONTH,
) -> float:
    """Monthly power cost for total facility energy (kWh x $/kWh)."""
    draw = compute_power_draw(it_load_kw, pue)
    monthly_kwh = draw.total_facility_kw * hours_per_month
    return monthly_kwh * electricity_usd_per_kwh


def compute_facility_cost(
    it_load_kw: float,
    pue: float = DEFAULT_PUE,
    electricity_usd_per_kwh: float = DEFAULT_ELECTRICITY_USD_PER_KWH,
    hours_per_month: float = DEFAULT_HOURS_PER_MONTH,
    cooling_share_of_overhead_pct: float = DEFAULT_COOLING_SHARE_OF_OVERHEAD_PCT,
) -> FacilityCost:
    """Full monthly facility cost breakdown.

    - monthly_power_cost_usd = total_facility_kw * hours * rate
    - cooling_cost_usd = overhead_kw * cooling_share * hours * rate
    - pue_cost_multiplier = total cost / IT-only cost (= pue, since cost scales
      linearly with energy)
    """
    config = ITLoadConfig(
        it_load_kw=it_load_kw,
        pue=pue,
        electricity_usd_per_kwh=electricity_usd_per_kwh,
        hours_per_month=hours_per_month,
        cooling_share_of_overhead_pct=cooling_share_of_overhead_pct,
    )
    draw = compute_power_draw(config.it_load_kw, config.pue)
    monthly_kwh = draw.total_facility_kw * config.hours_per_month
    monthly_power_cost = monthly_kwh * config.electricity_usd_per_kwh

    it_kwh = draw.it_load_kw * config.hours_per_month
    it_monthly_cost = it_kwh * config.electricity_usd_per_kwh
    overhead_monthly_cost = monthly_power_cost - it_monthly_cost

    cooling_fraction = config.cooling_share_of_overhead_pct / 100.0
    cooling_cost = overhead_monthly_cost * cooling_fraction

    pue_multiplier = monthly_power_cost / it_monthly_cost if it_monthly_cost > 0 else 0.0

    return FacilityCost(
        it_load_kw=config.it_load_kw,
        total_facility_kw=draw.total_facility_kw,
        monthly_power_cost_usd=round(monthly_power_cost, 4),
        cooling_cost_usd=round(cooling_cost, 4),
        cooling_cost_share_pct=config.cooling_share_of_overhead_pct,
        pue_cost_multiplier=round(pue_multiplier, 4),
        it_monthly_cost_usd=round(it_monthly_cost, 4),
        overhead_monthly_cost_usd=round(overhead_monthly_cost, 4),
    )


def pue_cost_multiplier(pue: float = DEFAULT_PUE) -> float:
    """Cost multiplier attributable to PUE (equals PUE under linear cost)."""
    effective_pue = max(pue, 1.0)
    return round(effective_pue, 4)


# --------------------------------------------------------------------------- #
# Persistence (load-or-generate, state outside the repo)
# --------------------------------------------------------------------------- #


def _config_hash(config: ITLoadConfig) -> str:
    payload = json.dumps(asdict(config), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def save_facility_cost(
    cost: FacilityCost,
    config: ITLoadConfig,
    state_dir: str = DEFAULT_STATE_DIR,
) -> str:
    """Persist a FacilityCost result to JSON; returns the file path."""
    subdir = os.path.join(state_dir, COST_SUBDIR)
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, LATEST_FILENAME)
    record = {
        "config_hash": _config_hash(config),
        "config": asdict(config),
        "result": asdict(cost),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
    return path


def load_facility_cost(
    state_dir: str = DEFAULT_STATE_DIR,
) -> Optional[dict]:
    """Load the persisted facility cost record, or None if absent."""
    path = os.path.join(state_dir, COST_SUBDIR, LATEST_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
