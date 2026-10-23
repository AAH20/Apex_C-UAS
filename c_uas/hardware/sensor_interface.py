"""
Hardware Abstraction Layer - sensor interface contract.

Defensive-only sensor abstraction for C-UAS detection: RF (SDR), radar,
and camera sensors. All adapters degrade to deterministic simulation when
no hardware is present; absence of hardware is logged, never raised as an
error. No live SDR integration, no weapons-employment effector, no facial
recognition, no weapon targeting.

State persists under ~/.c-uas-platform/hardware/ (outside the repo).
"""

from __future__ import annotations

import math
import random
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

logger = __import__("logging").getLogger(__name__)

# Fixed namespace so fused track IDs are deterministic (uuid5 is content-addressed).
FUSION_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "c-uas-hardware-fusion-v1")


class HardwareCapability(Enum):
    """Per-adapter capability flags."""

    RF_SCAN = "rf_scan"
    RADAR_TRACK = "radar_track"
    VISUAL_DETECTION = "visual_detection"


@dataclass(frozen=True)
class SensorStatus:
    """Reported status of a single sensor adapter."""

    sensor_id: str
    online: bool
    simulation_mode: bool
    capability: HardwareCapability
    last_seen: float
    message: str


@dataclass(frozen=True)
class Signal:
    """One narrowband signal observation from an SDR scan."""

    frequency_mhz: float
    rssi_dbm: float
    bandwidth_mhz: float
    detected: bool


@dataclass(frozen=True)
class RadarTrack:
    """One raw radar track observation."""

    track_id: str
    bearing_deg: float
    range_m: float
    altitude_m: float
    velocity_mps: float
    timestamp: float
    snr_db: float


@dataclass(frozen=True)
class Detection:
    """A single raw detection from one sensor."""

    detection_id: str
    sensor_id: str
    timestamp: float
    source: str  # "rf", "radar", "visual"
    x_m: float
    y_m: float
    z_m: float
    confidence: float  # 0.0-1.0
    metadata: Dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class Track:
    """A fused track across one or more sensors."""

    track_id: str
    x_m: float
    y_m: float
    z_m: float
    vx_mps: float
    vy_mps: float
    vz_mps: float
    timestamp: float
    confidence: float
    sensors: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


def distance_m(a: Detection, b: Detection) -> float:
    """Euclidean distance between two detections in meters."""

    return math.sqrt(
        (a.x_m - b.x_m) ** 2 + (a.y_m - b.y_m) ** 2 + (a.z_m - b.z_m) ** 2
    )


def track_distance_m(a: Track, b: Track) -> float:
    """Euclidean distance between two tracks in meters."""

    return math.sqrt(
        (a.x_m - b.x_m) ** 2 + (a.y_m - b.y_m) ** 2 + (a.z_m - b.z_m) ** 2
    )


class SensorInterface(ABC):
    """Abstract base class for hardware sensor adapters.

    Concrete adapters (SDR, radar, camera) implement detect(), get_status(),
    and health_check(). All adapters support a deterministic simulation mode
    used whenever real hardware is absent; hardware absence is logged at INFO
    and never surfaced as an error.
    """

    def __init__(
        self,
        sensor_id: str,
        capability: HardwareCapability,
        seed: int = 42,
        simulation: bool = True,
    ) -> None:
        self.sensor_id = sensor_id
        self.capability = capability
        self.seed = seed
        self.simulation = simulation
        self._rng = random.Random(seed)
        self._online = False
        self._last_seen: Optional[float] = None
        # Real hardware bindings (rtlsdr / hackrf / usrp / radar SDK / camera
        # SDK) are intentionally not imported. Hardware is treated as absent
        # unless a binding is explicitly registered here.
        self._hardware_present = False
        if self.simulation and not self._hardware_present:
            logger.info(
                "no hardware: %s adapter (%s) running in deterministic simulation mode",
                self.sensor_id,
                self.capability.value,
            )

    def register_hardware(self) -> None:
        """Mark this adapter as backed by real hardware (integration hook)."""

        self._hardware_present = True

    @abstractmethod
    def detect(self) -> List[Detection]:
        """Return raw detections from this sensor."""

    @abstractmethod
    def get_status(self) -> SensorStatus:
        """Return current sensor status."""

    @abstractmethod
    def health_check(self) -> bool:
        """Return True if the sensor (real or simulated) responds."""
