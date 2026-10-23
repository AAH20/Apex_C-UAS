"""
Edge node: local detection and tracking for C-UAS sites.

Runs the SDR / radar / camera adapters in deterministic simulation mode,
fuses detections into local tracks, and persists everything under
~/.c-uas-platform/edge/<node_id>/. Detection and tracking need no cloud
dependency; a site protected by an edge node keeps working fully offline.

All output is determined by (node_id, seed): identical configurations
produce identical detections, track IDs, and reports on any machine.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import List, Optional

from c_uas.hardware import (
    CameraAdapter,
    Detection,
    RadarAdapter,
    SDRAdapter,
    SensorFusion,
    Track,
)

from .config import EdgeConfig
from .state import node_dir, save_json

ADAPTER_BY_SENSOR = {
    "sdr": SDRAdapter,
    "radar": RadarAdapter,
    "camera": CameraAdapter,
}

SENSOR_SOURCE = {
    "sdr": "rf",
    "radar": "radar",
    "camera": "visual",
}


@dataclass(frozen=True)
class DetectionResult:
    """Outcome of one local detection cycle on an edge node."""

    node_id: str
    timestamp: float
    detections: List[Detection]
    tracks: List[Track]
    detection_count: int
    track_count: int


@dataclass(frozen=True)
class DeploymentReport:
    """Report produced when an edge node is deployed."""

    node_id: str
    location: str
    timestamp: float
    state_dir: str
    detection_count: int
    track_count: int
    offline_mode: bool
    within_cpu_target: bool
    within_memory_target: bool


class EdgeNode:
    """Lightweight edge node for Raspberry Pi / NVIDIA Jetson deployment."""

    CPU_TARGET_PERCENT = 5.0
    MEMORY_TARGET_MB = 100.0

    def __init__(self, config: EdgeConfig) -> None:
        self.config = config

    @classmethod
    def footprint_targets(cls) -> dict:
        return {
            "cpu_percent": cls.CPU_TARGET_PERCENT,
            "memory_mb": cls.MEMORY_TARGET_MB,
        }

    @property
    def node_id(self) -> str:
        return self.config.node_id

    def _build_adapter(self, sensor: str):
        adapter_cls = ADAPTER_BY_SENSOR[sensor]
        return adapter_cls(  # type: ignore[abstract]
            sensor_id="{}-{}".format(self.node_id, sensor),
            seed=self.config.seed,
            simulation=True,
        )

    def detect_cycle(self, timestamp: Optional[float] = None) -> DetectionResult:
        """Run one detection + fusion cycle on the enabled sensors."""
        if timestamp is None:
            timestamp = float(self.config.seed)

        detections: List[Detection] = []
        for sensor in self.config.sensors_enabled:
            adapter = self._build_adapter(sensor)
            for detection in adapter.detect():
                detections.append(
                    Detection(
                        detection_id="{}:{}".format(self.node_id, detection.detection_id),
                        sensor_id="{}-{}".format(self.node_id, sensor),
                        timestamp=detection.timestamp,
                        source=SENSOR_SOURCE[sensor],
                        x_m=detection.x_m,
                        y_m=detection.y_m,
                        z_m=detection.z_m,
                        confidence=detection.confidence,
                        metadata=dict(detection.metadata),
                    )
                )

        tracks = SensorFusion(seed=self.config.seed).fuse(detections)
        return DetectionResult(
            node_id=self.node_id,
            timestamp=timestamp,
            detections=detections,
            tracks=tracks,
            detection_count=len(detections),
            track_count=len(tracks),
        )

    def deploy(self) -> DeploymentReport:
        """Deploy the node: run the first cycle and persist all state."""
        from .health import EdgeHealth

        result = self.detect_cycle()
        health = EdgeHealth(self.config).check()

        state_dir = str(node_dir(self.node_id))
        save_json(self.node_id, "config", asdict(self.config))
        save_json(self.node_id, "detections", [asdict(d) for d in result.detections])
        save_json(self.node_id, "tracks", [asdict(t) for t in result.tracks])
        save_json(self.node_id, "last_cycle", asdict(result))

        return DeploymentReport(
            node_id=self.node_id,
            location=self.config.location,
            timestamp=result.timestamp,
            state_dir=state_dir,
            detection_count=result.detection_count,
            track_count=result.track_count,
            offline_mode=self.config.offline_mode,
            within_cpu_target=health.within_cpu_target,
            within_memory_target=health.within_memory_target,
        )
