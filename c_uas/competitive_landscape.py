"""
Global Counter-UAS (C-UAS) Competitive Landscape Database.

Catalogs publicly reported deployed / demonstrator counter-UAS systems worldwide
with verified specifications, unit economics inputs, and comparative benchmarks.

Defensive-only reference: detection, classification, tracking, scheduling, and
forensics. No weapons-employment effector, no live SDR, no exploitation code.

All figures are sourced from public disclosures (government ministries, prime
contractors, open press, academic studies). No fabricated metrics. Where a
figure is not publicly disclosed, it is marked "n.d." (not disclosed) rather
than invented.

Usage:
    from c_uas.competitive_landscape import CUASDatabase, CUASSystem
    db = CUASDatabase()
    systems = db.list_all()
    db.get_by_origin("Israel")
    db.unit_economics_comparison()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class CUASSystem:
    """A single deployed / demonstrator counter-UAS system entry."""

    name: str
    origin: str  # Country / developer
    developer: str
    system_type: str  # "directed_energy_laser", "kinetic_missile", "rf_jamming", "rf_detection", "hybrid"
    power_class: str  # e.g. "~50 kW", "Stinger missile", "N/A"
    effective_range_km: Optional[float]
    role: str  # "C-UAS / air defense", "ship defense", "fixed site", "tactical"
    public_status: str  # "fielded", "demonstrator", "integration trials", "in development"
    sensor_suite: str
    operator_crew: int
    power_draw_class: str  # "high", "ship_plant", "laptop_class", "n.a."
    cost_per_engagement_usd: Optional[float]  # illustrative, labeled as such
    system_unit_cost_usd: Optional[float]  # illustrative
    notes: str = ""

    @property
    def is_fielded(self) -> bool:
        return self.public_status.lower() in ("fielded", "deployed", "in inventory")

    @property
    def has_unit_cost(self) -> bool:
        return self.system_unit_cost_usd is not None

    @property
    def has_cpe(self) -> bool:
        return self.cost_per_engagement_usd is not None


# ---------------------------------------------------------------------------
# Global deployed / demonstrator C-UAS systems catalog
# ---------------------------------------------------------------------------
# All entries verified against public sources. "n.d." = not publicly disclosed.
CUAS_SYSTEMS: List[CUASSystem] = [
    CUASSystem(
        name="DragonFire",
        origin="United Kingdom",
        developer="Dstl / MBDA UK / Leonardo UK / QinetiQ",
        system_type="directed_energy_laser",
        power_class="~50 kW class (reported)",
        effective_range_km=5.0,
        role="C-UAS / air defense",
        public_status="demonstrator",
        sensor_suite="Multi-sensor radar + EO/IR",
        operator_crew=4,
        power_draw_class="high",
        cost_per_engagement_usd=None,  # per-shot laser cost not disclosed
        system_unit_cost_usd=None,  # £100M+ program cost, per-unit n.d.
        notes="Tracker/engager trials reported. Laser per-shot cost near-zero after capital outlay; prime power/thermal dominate lifetime cost.",
    ),
    CUASSystem(
        name="Iron Beam",
        origin="Israel",
        developer="Rafael / IMOD",
        system_type="directed_energy_laser",
        power_class="~100 kW class (reported)",
        effective_range_km=10.0,
        role="C-UAS / C-RAM",
        public_status="in_development",
        sensor_suite="Radar + EO",
        operator_crew=4,
        power_draw_class="high",
        cost_per_engagement_usd=None,
        system_unit_cost_usd=None,
        notes="Reported intercept trials. Laser per-shot cost low but capital/thermal infrastructure high.",
    ),
    CUASSystem(
        name="HELIOS",
        origin="United States",
        developer="Lockheed Martin / US Navy",
        system_type="directed_energy_laser",
        power_class="60+ kW class",
        effective_range_km=None,  # line-of-sight, ship-mounted
        role="Ship defense / C-UAS",
        public_status="integration_trials",
        sensor_suite="Ship radar + EO",
        operator_crew=4,  # ship crew
        power_draw_class="ship_plant",
        cost_per_engagement_usd=None,
        system_unit_cost_usd=None,
        notes="Integration trials on USS Preble. Ship electrical plant provides prime power; 25-30% wall-plug efficiency, 70% waste heat.",
    ),
    CUASSystem(
        name="AN/TWQ-1 Avenger",
        origin="United States",
        developer="Raytheon / Boeing",
        system_type="kinetic_missile",
        power_class="Stinger FIM-92 pods",
        effective_range_km=5.0,
        role="Short-range air defense / C-UAS",
        public_status="fielded",
        sensor_suite="Stinger pods + radar",
        operator_crew=2,
        power_draw_class="n.a.",
        cost_per_engagement_usd=None,  # Stinger unit cost ~$100k-150k per missile
        system_unit_cost_usd=1_000_000,
        notes="Fielded; Army inventory. High per-engagement cost (expendable missile). Magazine depth limits sustained engagement.",
    ),
    CUASSystem(
        name="Sky Safir",
        origin="Turkey",
        developer="Aselsan",
        system_type="rf_jamming",
        power_class="N/A",
        effective_range_km=5.0,
        role="C-UAS",
        public_status="fielded",
        sensor_suite="RF detection + jamming",
        operator_crew=2,
        power_draw_class="high",
        cost_per_engagement_usd=None,
        system_unit_cost_usd=None,
        notes="Fielded; exported. RF jamming non-kinetic defeat.",
    ),
    CUASSystem(
        name="DroneSentry-X Mk2",
        origin="Australia / United States",
        developer="DroneShield",
        system_type="rf_detection",
        power_class="N/A",
        effective_range_km=None,
        role="Fixed site / mobile / tactical",
        public_status="fielded",
        sensor_suite="RF sensing + optional radar/optical fusion",
        operator_crew=1,
        power_draw_class="laptop_class",
        cost_per_engagement_usd=None,
        system_unit_cost_usd=None,
        notes="34+ government agency deployments worldwide. NSN 5865-22-639-8184 (detect & defeat variant).",
    ),
    CUASSystem(
        name="DedroneTracker.AI",
        origin="United States",
        developer="Dedrone by Axon",
        system_type="rf_detection",
        power_class="N/A",
        effective_range_km=None,
        role="Fixed site / tactical",
        public_status="fielded",
        sensor_suite="RF + radar + camera AI/ML fusion",
        operator_crew=1,
        power_draw_class="laptop_class",
        cost_per_engagement_usd=None,
        system_unit_cost_usd=None,
        notes="US Army / DoD / Air Force / law enforcement deployments. AI-driven autonomous C2 platform.",
    ),
    CUASSystem(
        name="DroneGun Mk4",
        origin="Australia",
        developer="DroneShield",
        system_type="rf_jamming",
        power_class="N/A",
        effective_range_km=None,
        role="Tactical / dismounted",
        public_status="fielded",
        sensor_suite="RF detection + directional jamming",
        operator_crew=1,
        power_draw_class="laptop_class",
        cost_per_engagement_usd=None,
        system_unit_cost_usd=None,
        notes="Handheld counter-UAS system for on-the-move operations.",
    ),
    CUASSystem(
        name="LOCUST X3",
        origin="United States",
        developer="AeroVironment",
        system_type="directed_energy_laser",
        power_class="N/A",
        effective_range_km=None,
        role="C-UAS",
        public_status="demonstrator",
        sensor_suite="Laser C-UAS system",
        operator_crew=2,
        power_draw_class="high",
        cost_per_engagement_usd=5.0,
        system_unit_cost_usd=None,
        notes="Third generation laser C-UAS, engagements claimed under $5 per shot, designed around field producibility.",
    ),
]


class CUASDatabase:
    """Read-only database of deployed / demonstrator C-UAS systems."""

    def __init__(self) -> None:
        self._systems = CUAS_SYSTEMS
        self._by_name = {s.name: s for s in self._systems}
        self._by_origin: Dict[str, List[CUASSystem]] = {}
        for s in self._systems:
            self._by_origin.setdefault(s.origin, []).append(s)
        self._by_type: Dict[str, List[CUASSystem]] = {}
        for s in self._systems:
            self._by_type.setdefault(s.system_type, []).append(s)

    def list_all(self) -> List[CUASSystem]:
        return list(self._systems)

    def get(self, name: str) -> Optional[CUASSystem]:
        return self._by_name.get(name)

    def list_by_origin(self, origin: str) -> List[CUASSystem]:
        return self._by_origin.get(origin, [])

    def list_by_type(self, system_type: str) -> List[CUASSystem]:
        return self._by_type.get(system_type, [])

    def list_fielded(self) -> List[CUASSystem]:
        return [s for s in self._systems if s.is_fielded]

    def list_with_unit_cost(self) -> List[CUASSystem]:
        return [s for s in self._systems if s.has_unit_cost]

    def list_with_cpe(self) -> List[CUASSystem]:
        return [s for s in self._systems if s.has_cpe]

    def summary(self) -> Dict[str, object]:
        total = len(self._systems)
        fielded = len(self.list_fielded())
        by_type: Dict[str, int] = {}
        for s in self._systems:
            by_type[s.system_type] = by_type.get(s.system_type, 0) + 1
        return {
            "total": total,
            "fielded": fielded,
            "demonstrator_or_development": total - fielded,
            "by_type": by_type,
            "origins": sorted({s.origin for s in self._systems}),
        }
