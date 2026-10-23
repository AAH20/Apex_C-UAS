"""
Edge node health monitoring.

Reports CPU, memory, disk, temperature, sensor status, and connectivity for
the edge node. When psutil is unavailable the readings come from a seeded
deterministic RNG, so health checks are reproducible on developer machines
and in CI. When psutil is present the readings are real.
"""

from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .config import EdgeConfig


@dataclass(frozen=True)
class HealthReport:
    node_id: str
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    disk_percent: float
    temperature_c: Optional[float]
    sensors: Dict[str, bool]
    connectivity: bool
    within_cpu_target: bool
    within_memory_target: bool


class EdgeHealth:
    CPU_TARGET_PERCENT = 5.0
    MEMORY_TARGET_MB = 100.0

    def __init__(
        self,
        config: EdgeConfig,
        clock: Optional[Callable[[], float]] = None,
        psutil_module: Optional[Any] = None,
    ) -> None:
        self.config = config
        self._clock = clock or time.time
        self._psutil = psutil_module or self._load_psutil()

    def _load_psutil(self) -> Any:
        try:
            import psutil  # type: ignore[import-untyped]

            return psutil
        except ImportError:
            return None

    def _read_system(self):
        if self._psutil is not None:
            cpu = float(self._psutil.cpu_percent(interval=0.0))
            memory = self._psutil.virtual_memory()
            memory_percent = float(memory.percent)
            memory_mb = float(memory.used) / 1e6
            total, used, _free = shutil.disk_usage("/")
            disk_percent = float(used) / float(total) * 100.0
            temperature_c: Optional[float] = None
            try:
                temps = self._psutil.sensors_temperatures() or {}
                for _name, entries in temps.items():
                    for entry in entries or []:
                        if getattr(entry, "current", None) is not None:
                            temperature_c = float(entry.current)
                            break
                    if temperature_c is not None:
                        break
            except Exception:
                temperature_c = None
        else:
            # Deterministic simulation: idle-class edge hardware readings.
            rng = __import__("random").Random(self.config.seed)
            cpu = round(rng.random() * 3.0, 2)
            memory_mb = round(32.0 + rng.random() * 8.0, 2)
            memory_percent = round(20.0 + rng.random() * 10.0, 2)
            _total, used, _free = shutil.disk_usage("/")
            disk_percent = round(float(used) / float(total) * 100.0, 2)
            temperature_c = round(45.0 + rng.random() * 10.0, 1)
        return cpu, memory_percent, memory_mb, disk_percent, temperature_c

    def check(self, sensors_online: Optional[Dict[str, bool]] = None) -> HealthReport:
        """Produce one health snapshot for the edge node."""
        cpu, memory_percent, memory_mb, disk_percent, temperature_c = self._read_system()
        if sensors_online is None:
            sensors_online = {
                "{}-{}".format(self.config.node_id, sensor): True
                for sensor in self.config.sensors_enabled
            }
        connectivity = (not self.config.offline_mode) and bool(self.config.cloud_endpoint)
        return HealthReport(
            node_id=self.config.node_id,
            timestamp=self._clock(),
            cpu_percent=cpu,
            memory_percent=memory_percent,
            memory_mb=memory_mb,
            disk_percent=disk_percent,
            temperature_c=temperature_c,
            sensors=dict(sensors_online),
            connectivity=connectivity,
            within_cpu_target=cpu <= self.CPU_TARGET_PERCENT,
            within_memory_target=memory_mb <= self.MEMORY_TARGET_MB,
        )
