"""
Edge node configuration for the C-UAS edge computing deployment.

Immutable configuration: node identity, site location, enabled sensors,
cloud sync interval and endpoint, offline mode, and the deterministic RNG
seed. Every edge node runs identically given the same configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

_VALID_SENSORS = {"sdr", "radar", "camera"}


@dataclass(frozen=True)
class EdgeConfig:
    """Configuration for one C-UAS edge node.

    Target footprint for Raspberry Pi 4 / NVIDIA Jetson Nano-class hardware:
    CPU under 5 percent at idle, memory under 100 MB. Detection and tracking
    run fully offline; cloud sync is best-effort and deferred until
    connectivity is restored.
    """

    node_id: str
    location: str
    sensors_enabled: Tuple[str, ...] = ("sdr", "radar", "camera")
    sync_interval_s: float = 300.0
    cloud_endpoint: Optional[str] = None
    offline_mode: bool = False
    seed: int = 42

    def __post_init__(self) -> None:
        if not self.node_id or not str(self.node_id).strip():
            raise ValueError("node_id is required")
        if self.sync_interval_s <= 0:
            raise ValueError("sync_interval_s must be positive")
        unknown = set(self.sensors_enabled) - _VALID_SENSORS
        if unknown:
            raise ValueError("Unknown sensors: {}".format(sorted(unknown)))
        object.__setattr__(self, "sensors_enabled", tuple(sorted(set(self.sensors_enabled))))
