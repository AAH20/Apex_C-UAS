"""
Camera adapter for the hardware abstraction layer.

Wraps class camera sensors for visual detection: object-detection stub
returning bounding boxes and confidence. Real camera SDKs are not imported;
when no hardware is present the adapter runs in deterministic simulation
mode (fixed RNG seed) and logs "no hardware" instead of raising an error.

Defensive-only constraints, enforced in code:
- No facial recognition (no identity attributes are ever produced).
- No weapon targeting (no targeting, aim-point, or effector fields).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional

from .sensor_interface import (
    Detection,
    HardwareCapability,
    SensorInterface,
    SensorStatus,
)

_FORBIDDEN_METADATA_KEYS = {"face", "identity", "identities", "targeting", "aim_point", "weapon"}


@dataclass(frozen=True)
class FrameResult:
    """Result of one camera frame analysis."""

    sensor_id: str
    timestamp: float
    frame_width: int
    frame_height: int
    detections: List[Detection]


class CameraAdapter(SensorInterface):
    """Camera sensor adapter producing visual object detections."""

    def __init__(
        self,
        sensor_id: str = "camera-0",
        seed: int = 42,
        simulation: bool = True,
        frame_width: int = 1920,
        frame_height: int = 1080,
    ) -> None:
        super().__init__(
            sensor_id, HardwareCapability.VISUAL_DETECTION, seed=seed, simulation=simulation
        )
        self.frame_width = frame_width
        self.frame_height = frame_height
        self._last_frame: Optional[FrameResult] = None

    def analyze_frame(self) -> FrameResult:
        """Run the object-detection stub on one synthetic frame.

        Produces 1-3 quadcopter-like detections with bounding boxes and
        confidence. Deterministic given seed and frame dimensions.
        """

        num = self._rng.randint(1, 3)
        detections: List[Detection] = []
        now = time.time()
        for i in range(num):
            # Bounding box fully inside the frame, deterministic from seed.
            w = self._rng.uniform(40.0, 220.0)
            h = self._rng.uniform(40.0, 180.0)
            x1 = self._rng.uniform(0.0, self.frame_width - w)
            y1 = self._rng.uniform(0.0, self.frame_height - h)
            bbox = [round(x1, 1), round(y1, 1), round(x1 + w, 1), round(y1 + h, 1)]
            confidence = round(self._rng.uniform(0.5, 0.98), 3)
            cx = (bbox[0] + bbox[2]) / 2.0
            cy = (bbox[1] + bbox[3]) / 2.0
            # Project object center to a synthetic ground-plane position.
            x_m = round((cx / self.frame_width - 0.5) * 2000.0, 2)
            y_m = round(100.0 + (cy / self.frame_height) * 1500.0, 2)
            z_m = round(20.0 + self._rng.uniform(0.0, 120.0), 2)
            metadata = {
                "bounding_box": bbox,
                "class": "quadcopter",
                "frame_width": self.frame_width,
                "frame_height": self.frame_height,
                "position_source": "synthetic_perspective_estimate",
            }
            self._assert_defensive(metadata)
            detections.append(
                Detection(
                    detection_id=f"det--visual--{i:03d}",
                    sensor_id=self.sensor_id,
                    timestamp=now,
                    source="visual",
                    x_m=x_m,
                    y_m=y_m,
                    z_m=z_m,
                    confidence=confidence,
                    metadata=metadata,
                )
            )
        self._last_frame = FrameResult(
            sensor_id=self.sensor_id,
            timestamp=now,
            frame_width=self.frame_width,
            frame_height=self.frame_height,
            detections=detections,
        )
        return self._last_frame

    @staticmethod
    def _assert_defensive(metadata: dict) -> None:
        """Enforce defensive-only constraints on camera metadata."""

        for key in _FORBIDDEN_METADATA_KEYS:
            if key in metadata:
                raise ValueError(f"forbidden camera metadata key: {key}")

    def detect(self) -> List[Detection]:
        frame = self._last_frame or self.analyze_frame()
        return list(frame.detections)

    def get_status(self) -> SensorStatus:
        online = self.health_check()
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
