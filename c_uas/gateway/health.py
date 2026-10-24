"""
Periodic backend health probes. Marks backends healthy / unhealthy.

The default probe performs a GET to {endpoint}/healthz with a short timeout and
measures latency. A callable probe can be injected for tests so no network is
required and results are deterministic.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, List, Optional

from .config import Backend, GatewayConfig
from .router import BackendState


@dataclass
class ProbeResult:
    backend_id: str
    healthy: bool
    latency_ms: Optional[float]
    probed_at: float
    error: Optional[str] = None


class HealthChecker:
    def __init__(
        self,
        config: GatewayConfig,
        states: dict,
        probe: Optional[Callable[[Backend], ProbeResult]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.states = states
        self._probe = probe or self._default_probe
        self.clock = clock

    def _default_probe(self, backend: Backend) -> ProbeResult:
        url = backend.endpoint.rstrip("/") + "/healthz"
        start = self.clock()
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                probed_at = self.clock()
                latency_ms = round((probed_at - start) * 1000.0, 2)
                healthy = 200 <= resp.status < 300
                return ProbeResult(backend.backend_id, healthy, latency_ms, probed_at, None)
        except Exception as exc:  # noqa: BLE001
            probed_at = self.clock()
            latency_ms = round((probed_at - start) * 1000.0, 2)
            return ProbeResult(backend.backend_id, False, latency_ms, probed_at, repr(exc))

    def probe_backend(self, backend: Backend) -> ProbeResult:
        result = self._probe(backend)
        st = self.states.setdefault(
            backend.backend_id, BackendState(backend_id=backend.backend_id)
        )
        st.healthy = result.healthy
        st.last_latency_ms = result.latency_ms
        st.last_probe_ts = result.probed_at
        return result

    def check_all(self) -> List[ProbeResult]:
        return [self.probe_backend(b) for b in self.config.backends]

    def is_due(self, backend_id: str) -> bool:
        st = self.states.get(backend_id)
        if st is None or st.last_probe_ts is None:
            return True
        return (self.clock() - st.last_probe_ts) >= self.config.health_interval_s
