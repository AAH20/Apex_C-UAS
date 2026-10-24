"""
Radar adapter for the hardware abstraction layer.

Wraps class radar sensors for track reports (bearing, range, altitude,
velocity) and track correlation. Real radar SDKs are not imported; when no
hardware is present the adapter runs in deterministic simulation mode
(fixed RNG seed) and logs "no hardware" instead of raising an error.

All tracks are synthetic observations of cooperative/non-cooperative aerial
targets in the defended area. Defensive tracking only.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import List, Optional

from .sensor_interface import (
    Detection,
    HardwareCapability,
    RadarTrack,
    SensorInterface,
    SensorStatus,
)


@dataclass(frozen=True)
class Correlation:
    """Association between a new track and a previous track."""

    new_track_id: str
    previous_track_id: Optional[str]
    distance_m: float
    correlated: bool


class RadarAdapter(SensorInterface):
    """Radar sensor adapter producing bearing/range/altitude/velocity tracks."""

    def __init__(
        self,
        sensor_id: str = "radar-0",
        seed: int = 42,
        simulation: bool = True,
        min_range_m: float = 200.0,
        max_range_m: float = 8000.0,
    ) -> None:
        super().__init__(
            sensor_id, HardwareCapability.RADAR_TRACK, seed=seed, simulation=simulation
        )
        self.min_range_m = min_range_m
        self.max_range_m = max_range_m
        self._last_tracks: List[RadarTrack] = []

    def scan_tracks(self) -> List[RadarTrack]:
        """Return one deterministic frame of synthetic radar tracks.

        Track count, geometry, and kinematics are fully determined by seed.
        Velocity vectors point generally toward the defended asset (origin).
        """

        num_tracks = self._rng.randint(3, 6)
        tracks: List[RadarTrack] = []
        for i in range(num_tracks):
            bearing_deg = round(self._rng.uniform(0.0, 360.0), 2)
            range_m = round(self._rng.uniform(self.min_range_m, self.max_range_m), 1)
            altitude_m = round(self._rng.uniform(0.0, 300.0), 1)
            velocity_mps = round(self._rng.uniform(5.0, 40.0), 1)
            snr_db = round(self._rng.uniform(8.0, 25.0), 1)
            tracks.append(
                RadarTrack(
                    track_id=f"raw--radar--{i:03d}",
                    bearing_deg=bearing_deg,
                    range_m=range_m,
                    altitude_m=altitude_m,
                    velocity_mps=velocity_mps,
                    timestamp=time.time(),
                    snr_db=snr_db,
                )
            )
        self._last_tracks = tracks
        return tracks

    def _bearing_to_position(self, bearing_deg: float, range_m: float, altitude_m: float):
        br = math.radians(bearing_deg)
        x_m = range_m * math.sin(br)
        y_m = range_m * math.cos(br)
        return x_m, y_m, altitude_m

    def detect(self) -> List[Detection]:
        """Convert raw radar tracks into Detection objects."""

        detections: List[Detection] = []
        tracks = self._last_tracks or self.scan_tracks()
        _now = time.time()
        for track in tracks:
            x_m, y_m, z_m = self._bearing_to_position(
                track.bearing_deg, track.range_m, track.altitude_m
            )
            confidence = min(1.0, max(0.0, (track.snr_db + 5.0) / 35.0))
            detections.append(
                Detection(
                    detection_id=f"det--radar--{track.track_id.split('--')[-1]}",
                    sensor_id=self.sensor_id,
                    timestamp=track.timestamp,
                    source="radar",
                    x_m=round(x_m, 2),
                    y_m=round(y_m, 2),
                    z_m=round(z_m, 2),
                    confidence=round(confidence, 3),
                    metadata={
                        "bearing_deg": track.bearing_deg,
                        "range_m": track.range_m,
                        "altitude_m": track.altitude_m,
                        "velocity_mps": track.velocity_mps,
                        "snr_db": track.snr_db,
                    },
                )
            )
        return detections

    def correlate_tracks(
        self,
        new_tracks: List[RadarTrack],
        previous_tracks: List[RadarTrack],
        max_distance_m: float = 150.0,
    ) -> List[Correlation]:
        """Correlate new radar tracks with previous tracks by proximity.

        Greedy nearest-neighbor association: each new track matches the
        closest previous track within max_distance_m. Deterministic given
        input order.
        """

        correlations: List[Correlation] = []
        used_previous: List[int] = []
        for new in new_tracks:
            best_idx: Optional[int] = None
            best_dist = float("inf")
            for idx, prev in enumerate(previous_tracks):
                if idx in used_previous:
                    continue
                dist = _radar_distance(new, prev)
                if dist < best_dist:
                    best_dist = dist
                    best_idx = idx
            if best_idx is not None and best_dist <= max_distance_m:
                used_previous.append(best_idx)
                correlations.append(
                    Correlation(
                        new_track_id=new.track_id,
                        previous_track_id=previous_tracks[best_idx].track_id,
                        distance_m=round(best_dist, 2),
                        correlated=True,
                    )
                )
            else:
                correlations.append(
                    Correlation(
                        new_track_id=new.track_id,
                        previous_track_id=None,
                        distance_m=round(best_dist, 2),
                        correlated=False,
                    )
                )
        return correlations

    def get_status(self) -> SensorStatus:
        online = self.health_check()
        self._online = online
        return SensorStatus(
            sensor_id=self.sensor_id,
            online=online,
            simulation_mode=self.simulation and not self._hardware_present,
            capability=self.capability,
            last_seen=self._last_seen or 0.0,
            message=(
                "simulation mode: no hardware" if not self._hardware_present else "hardware present"
            ),
        )

    def health_check(self) -> bool:
        return True


def _radar_distance(a: RadarTrack, b: RadarTrack) -> float:
    xa, ya, za = _polar_to_cartesian(a.bearing_deg, a.range_m, a.altitude_m)
    xb, yb, zb = _polar_to_cartesian(b.bearing_deg, b.range_m, b.altitude_m)
    return math.sqrt((xa - xb) ** 2 + (ya - yb) ** 2 + (za - zb) ** 2)


def _polar_to_cartesian(bearing_deg: float, range_m: float, altitude_m: float):
    br = math.radians(bearing_deg)
    return range_m * math.sin(br), range_m * math.cos(br), altitude_m
