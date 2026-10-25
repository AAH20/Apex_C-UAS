"""Carbon intensity: gCO2/kWh by region, carbon per compute hour, carbon cost
at $/ton, carbon-efficient region ranking.

All functions are pure and deterministic. Carbon intensity figures are
illustrative grid averages (operators should supply site-specific values).

State persists under ~/.c-uas-platform/finops/carbon/ (outside the repo).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "finops")
CARBON_SUBDIR = "carbon"
LATEST_FILENAME = "latest_carbon.json"

# Default carbon price, USD per metric ton CO2e.
DEFAULT_CARBON_USD_PER_TON = 50.0
# Default billing hours per month.
DEFAULT_HOURS_PER_MONTH = 730.0

# Illustrative grid carbon intensity by region, gCO2/kWh.
# Operators should replace with site-specific / market-based factors.
REGION_CARBON_INTENSITY: Dict[str, float] = {
    "us-east-1": 380.0,
    "us-west-2": 290.0,
    "eu-west-1": 220.0,
    "eu-central-1": 310.0,
    "ap-southeast-1": 520.0,
    "ap-northeast-1": 480.0,
    "sa-east-1": 90.0,  # high hydro share
    "af-south-1": 610.0,
}


@dataclass(frozen=True)
class CarbonIntensity:
    """Carbon intensity for a region with provenance."""

    region: str
    carbon_intensity_gco2_per_kwh: float
    source: str = "grid-average-illustrative"


@dataclass(frozen=True)
class CarbonResult:
    """Carbon result for a compute workload."""

    region: str
    power_kw: float
    hours: float
    energy_kwh: float
    carbon_intensity_gco2_per_kwh: float
    carbon_kg_co2e: float
    carbon_tons_co2e: float
    carbon_cost_usd: float
    carbon_usd_per_ton: float


def carbon_intensity_for_region(
    region: str,
    intensity_map: Optional[Dict[str, float]] = None,
) -> CarbonIntensity:
    """Return the carbon intensity for a region, or a default if unknown."""
    mapping = intensity_map if intensity_map is not None else REGION_CARBON_INTENSITY
    intensity = mapping.get(region)
    if intensity is None:
        # Unknown region: fall back to the median of known intensities as an
        # illustrative placeholder rather than inventing a precise figure.
        known = sorted(mapping.values())
        intensity = known[len(known) // 2] if known else 0.0
        source = "grid-average-illustrative-fallback"
    else:
        source = "grid-average-illustrative"
    return CarbonIntensity(
        region=region,
        carbon_intensity_gco2_per_kwh=intensity,
        source=source,
    )


def carbon_per_compute_hour(
    power_kw: float,
    region: str,
    hours: float = 1.0,
    intensity_map: Optional[Dict[str, float]] = None,
    carbon_usd_per_ton: float = DEFAULT_CARBON_USD_PER_TON,
) -> CarbonResult:
    """Carbon and cost for running a power draw for a given number of hours.

    energy_kwh = power_kw * hours
    carbon_kg = energy_kwh * intensity / 1000  (g -> kg)
    carbon_tons = carbon_kg / 1000
    carbon_cost_usd = carbon_tons * carbon_usd_per_ton
    """
    if power_kw < 0:
        raise ValueError("power_kw must be >= 0")
    if hours < 0:
        raise ValueError("hours must be >= 0")
    if carbon_usd_per_ton < 0:
        raise ValueError("carbon_usd_per_ton must be >= 0")

    ci = carbon_intensity_for_region(region, intensity_map)
    energy_kwh = power_kw * hours
    carbon_kg = energy_kwh * ci.carbon_intensity_gco2_per_kwh / 1000.0
    carbon_tons = carbon_kg / 1000.0
    carbon_cost = carbon_tons * carbon_usd_per_ton

    return CarbonResult(
        region=ci.region,
        power_kw=power_kw,
        hours=hours,
        energy_kwh=round(energy_kwh, 4),
        carbon_intensity_gco2_per_kwh=ci.carbon_intensity_gco2_per_kwh,
        carbon_kg_co2e=round(carbon_kg, 4),
        carbon_tons_co2e=round(carbon_tons, 6),
        carbon_cost_usd=round(carbon_cost, 6),
        carbon_usd_per_ton=carbon_usd_per_ton,
    )


def ranked_regions_by_carbon(
    intensity_map: Optional[Dict[str, float]] = None,
) -> List[Tuple[str, float]]:
    """Regions ranked ascending by carbon intensity (most efficient first)."""
    mapping = intensity_map if intensity_map is not None else REGION_CARBON_INTENSITY
    return sorted(mapping.items(), key=lambda kv: (kv[1], kv[0]))


def carbon_cost_per_ton(
    carbon_kg_co2e: float,
    carbon_usd_per_ton: float = DEFAULT_CARBON_USD_PER_TON,
) -> float:
    """Convert kg CO2e to a USD cost at the given $/ton price."""
    if carbon_kg_co2e < 0:
        raise ValueError("carbon_kg_co2e must be >= 0")
    if carbon_usd_per_ton < 0:
        raise ValueError("carbon_usd_per_ton must be >= 0")
    return round((carbon_kg_co2e / 1000.0) * carbon_usd_per_ton, 6)


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def _config_hash(
    region: str,
    power_kw: float,
    hours: float,
    carbon_usd_per_ton: float,
) -> str:
    payload = json.dumps(
        {
            "region": region,
            "power_kw": power_kw,
            "hours": hours,
            "carbon_usd_per_ton": carbon_usd_per_ton,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def save_carbon_result(
    result: CarbonResult,
    region: str,
    power_kw: float,
    hours: float,
    carbon_usd_per_ton: float,
    state_dir: str = DEFAULT_STATE_DIR,
) -> str:
    subdir = os.path.join(state_dir, CARBON_SUBDIR)
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, LATEST_FILENAME)
    record = {
        "config_hash": _config_hash(region, power_kw, hours, carbon_usd_per_ton),
        "region": region,
        "power_kw": power_kw,
        "hours": hours,
        "carbon_usd_per_ton": carbon_usd_per_ton,
        "result": asdict(result),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
    return path


def load_carbon_result(state_dir: str = DEFAULT_STATE_DIR) -> Optional[dict]:
    path = os.path.join(state_dir, CARBON_SUBDIR, LATEST_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
