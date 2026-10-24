"""
Health-aware backend router: round_robin / least_latency / failover.

Selects among healthy backends whose circuit admits a request. Decisions are
deterministic for a fixed config, state, and seed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from .circuit import CircuitBreaker
from .config import Backend, GatewayConfig


@dataclass
class BackendState:
    backend_id: str
    healthy: bool = True
    last_latency_ms: Optional[float] = None
    consecutive_failures: int = 0
    last_probe_ts: Optional[float] = None


@dataclass
class RoutingDecision:
    backend: Optional[Backend]
    strategy: str
    reason: str
    candidates: int
    seed: int


class BackendRouter:
    def __init__(
        self,
        config: GatewayConfig,
        states: dict,
        breaker: CircuitBreaker,
        clock: Callable[[], float] = time.time,
        rr_index: int = 0,
    ) -> None:
        self.config = config
        self.states = states
        self.breaker = breaker
        self.clock = clock
        self.rr_index = rr_index

    def _eligible(self, role: Optional[str]) -> List[Backend]:
        """Backends matching role, healthy, and admitted by their circuit."""
        eligible: List[Backend] = []
        for b in self.config.backends:
            if role is not None and b.role != role:
                continue
            st = self.states.get(b.backend_id)
            if st is not None and not st.healthy:
                continue
            if not self.breaker.allow_request(b.backend_id):
                continue
            eligible.append(b)
        return eligible

    def select(self, role: Optional[str] = None) -> RoutingDecision:
        strategy = self.config.strategy
        seed = self.config.seed
        eligible = self._eligible(role)
        if not eligible:
            return RoutingDecision(
                backend=None,
                strategy=strategy,
                reason="no eligible backends",
                candidates=0,
                seed=seed,
            )
        if strategy == "round_robin":
            idx = self.rr_index % len(eligible)
            backend = eligible[idx]
            self.rr_index = idx + 1
            reason = "round_robin index %d of %d" % (idx, len(eligible))
        elif strategy == "least_latency":

            def sort_key(b: Backend):
                st = self.states.get(b.backend_id)
                lat = st.last_latency_ms if st and st.last_latency_ms is not None else float("inf")
                return (lat, b.backend_id)

            eligible_sorted = sorted(eligible, key=sort_key)
            backend = eligible_sorted[0]
            reason = "least_latency"
        else:  # failover
            backend = eligible[0]
            reason = "failover primary"
        return RoutingDecision(
            backend=backend,
            strategy=strategy,
            reason=reason,
            candidates=len(eligible),
            seed=seed,
        )

    def record_success(self, backend_id: str, latency_ms: Optional[float] = None) -> None:
        self.breaker.record_success(backend_id)
        st = self.states.get(backend_id)
        if st is not None:
            if latency_ms is not None:
                st.last_latency_ms = latency_ms
            st.consecutive_failures = 0

    def record_failure(self, backend_id: str) -> None:
        self.breaker.record_failure(backend_id)
        st = self.states.get(backend_id)
        if st is not None:
            st.consecutive_failures += 1
