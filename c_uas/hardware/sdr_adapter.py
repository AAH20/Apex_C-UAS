"""
SDR adapter for the hardware abstraction layer.

Wraps RTL-SDR / HackRF / USRP class devices for frequency scanning, signal
detection, and RSSI reporting. Real hardware bindings are not imported;
when no hardware is present the adapter runs in deterministic simulation
mode (fixed RNG seed) and logs "no hardware" instead of raising an error.

Detected signals are synthetic RF observations (frequency, RSSI, bandwidth)
derived from a seeded RNG. SDR alone cannot localize without direction
finding, so positions are RSSI-derived estimates labeled synthetic.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import List, Optional

from .sensor_interface import (
    Detection,
    HardwareCapability,
    SensorStatus,
    Signal,
    SensorInterface,
    logger,
)


@dataclass(frozen=True)
class ScanResult:
    """Result of one SDR frequency scan."""

    sensor_id: str
    start_mhz: float
    stop_mhz: float
    step_mhz: float
    timestamp: float
    signals: List[Signal]


class SDRAdapter(SensorInterface):
    """SDR sensor adapter (RTL-SDR / HackRF / USRP class)."""

    # Common drone / RC bands (MHz), defensive RF monitoring only.
    DEFAULT_FREQUENCIES_MHZ = [2412.0, 2440.0, 2472.0, 5745.0, 5825.0]

    def __init__(
        self,
        sensor_id: str = "sdr-0",
        seed: int = 42,
        simulation: bool = True,
        noise_floor_dbm: float = -95.0,
        detection_threshold_dbm: float = -70.0,
    ) -> None:
        super().__init__(
            sensor_id, HardwareCapability.RF_SCAN, seed=seed, simulation=simulation
        )
        self.noise_floor_dbm = noise_floor_dbm
        self.detection_threshold_dbm = detection_threshold_dbm
        self._last_scan: Optional[ScanResult] = None

    def scan_frequencies(
        self, start_mhz: float = 2400.0, stop_mhz: float = 2500.0, step_mhz: float = 5.0
    ) -> ScanResult:
        """Scan a frequency band and return per-channel signal observations.

        Drone-like signals are placed at deterministic frequencies inside the
        band with strong RSSI; all other channels carry noise-floor jitter.
        Output is fully determined by (seed, start, stop, step).
        """

        signals: List[Signal] = []
        drone_bands = {
            2440.0: ("dji_ocuszyn-like", -50.0),
            2472.0: ("expresslrs-like", -48.0),
        }
        f = start_mhz
        while f <= stop_mhz + 1e-9:
            freq = round(f, 3)
            rssi = self.noise_floor_dbm + self._rng.uniform(-3.0, 3.0)
            label = "noise"
            if any(abs(freq - df) < 3.0 for df in drone_bands):
                label, strong = drone_bands[[df for df in drone_bands if abs(freq - df) < 3.0][0]]
                rssi = max(rssi, self._rng.uniform(strong - 3.0, strong + 3.0))
            detected = rssi > self.detection_threshold_dbm
            signals.append(
                Signal(
                    frequency_mhz=freq,
                    rssi_dbm=round(rssi, 1),
                    bandwidth_mhz=20.0,
                    detected=detected,
                )
            )
            f += step_mhz

        self._last_scan = ScanResult(
            sensor_id=self.sensor_id,
            start_mhz=start_mhz,
            stop_mhz=stop_mhz,
            step_mhz=step_mhz,
            timestamp=time.time(),
            signals=signals,
        )
        return self._last_scan

    def detect(self) -> List[Detection]:
        """Return detections for every signal above the detection threshold.

        Position is a synthetic RSSI-derived estimate (bearing + range from
        the seeded RNG) because SDR alone cannot localize without DF.
        """

        detections: List[Detection] = []
        scan = self._last_scan or self.scan_frequencies()
        for sig in scan.signals:
            if not sig.detected:
                continue
            # Synthetic position estimate: deterministic bearing/range from seed.
            bearing = self._rng.uniform(0.0, 2.0 * math.pi)
            range_m = self._rng.uniform(100.0, 5000.0)
            x_m = range_m * math.sin(bearing)
            y_m = range_m * math.cos(bearing)
            z_m = self._rng.uniform(0.0, 150.0)
            confidence = min(1.0, max(0.0, (sig.rssi_dbm + 100.0) / 40.0))
            detections.append(
                Detection(
                    detection_id=f"det--rf--{sig.frequency_mhz}MHz",
                    sensor_id=self.sensor_id,
                    timestamp=scan.timestamp,
                    source="rf",
                    x_m=round(x_m, 2),
                    y_m=round(y_m, 2),
                    z_m=round(z_m, 2),
                    confidence=round(confidence, 3),
                    metadata={
                        "frequency_mhz": sig.frequency_mhz,
                        "rssi_dbm": sig.rssi_dbm,
                        "bandwidth_mhz": sig.bandwidth_mhz,
                        "position_source": "synthetic_rssi_estimate",
                    },
                )
            )
        return detections

    def get_status(self) -> SensorStatus:
        online = self.health_check()
        self._online = online
        self._last_seen = time.time()
        return SensorStatus(
            sensor_id=self.sensor_id,
            online=online,
            simulation_mode=self.simulation and not self._hardware_present,
            capability=self.capability,
            last_seen=self._last_seen or 0.0,
            message=(
                "simulation mode: no hardware"
                if not self._hardware_present
                else "hardware present"
            ),
        )

    def health_check(self) -> bool:
        """Simulation always responds; real hardware would be probed here."""

        return True
