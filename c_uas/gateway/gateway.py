"""
Gateway facade: config + backends + circuit breaker + router + health checker.

Wires the components together and persists all mutable state under
~/.c-uas-platform/gateway/ so routing decisions remain reproducible across
process restarts.
"""

from __future__ import annotations

import time
from typing import List, Optional, Union

from .circuit import CircuitBreaker
from .config import GatewayConfig
from .health import HealthChecker, ProbeResult
from .router import BackendRouter, BackendState, RoutingDecision
from .state import GatewayStateStore


class Gateway:
    def __init__(self, config: Optional[GatewayConfig] = None, clock=time.time) -> None:
        self.config = config or GatewayConfig()
        self.store = GatewayStateStore(self.config.state_dir)
        persisted = self.store.load_config()
        if persisted is not None:
            self.config = persisted
        # Ensure every configured backend has a state entry.
        self.backend_states: dict = self.store.load_backend_states()
        for b in self.config.backends:
            self.backend_states.setdefault(b.backend_id, BackendState(backend_id=b.backend_id))
        # Circuit breaker hydrated from persisted states.
        self.breaker = CircuitBreaker(
            self.config.failure_threshold, self.config.recovery_timeout_s, clock=clock
        )
        persisted_circuits = self.store.load_circuit_states()
        if persisted_circuits:
            self.breaker.replace_states(persisted_circuits)
        rr_index = self.store.load_rr_index()
        self.router = BackendRouter(
            self.config, self.backend_states, self.breaker, clock=clock, rr_index=rr_index
        )
        self.health = HealthChecker(self.config, self.backend_states, clock=clock)
        self.clock = clock
        # Persist defaults on first construction so state exists on disk.
        self.store.save_config(self.config)

    # ---- status ---------------------------------------------------------
    def status(self) -> dict:
        backends = []
        for b in self.config.backends:
            st = self.backend_states.get(b.backend_id, BackendState(backend_id=b.backend_id))
            cs = self.breaker.state_for(b.backend_id)
            backends.append(
                {
                    "backend_id": b.backend_id,
                    "endpoint": b.endpoint,
                    "role": b.role,
                    "weight": b.weight,
                    "healthy": st.healthy,
                    "circuit": cs.state,
                    "failure_count": cs.failure_count,
                    "consecutive_failures": st.consecutive_failures,
                    "last_latency_ms": st.last_latency_ms,
                    "last_probe_ts": st.last_probe_ts,
                }
            )
        return {
            "strategy": self.config.strategy,
            "seed": self.config.seed,
            "failure_threshold": self.config.failure_threshold,
            "recovery_timeout_s": self.config.recovery_timeout_s,
            "health_interval_s": self.config.health_interval_s,
            "state_dir": self.config.state_dir,
            "backends": backends,
        }

    # ---- routing --------------------------------------------------------
    def route(
        self, role: Optional[str] = None, backend_id: Optional[str] = None
    ) -> RoutingDecision:
        if backend_id is not None:
            # Force a specific backend if it is configured and eligible.
            target = next((b for b in self.config.backends if b.backend_id == backend_id), None)
            if target is None:
                decision = RoutingDecision(
                    backend=None,
                    strategy=self.config.strategy,
                    reason="unknown backend_id %r" % backend_id,
                    candidates=0,
                    seed=self.config.seed,
                )
            else:
                st = self.backend_states.get(backend_id)
                if st is not None and not st.healthy:
                    decision = RoutingDecision(
                        backend=None,
                        strategy=self.config.strategy,
                        reason="backend %s unhealthy" % backend_id,
                        candidates=len(self.config.backends),
                        seed=self.config.seed,
                    )
                elif not self.breaker.allow_request(backend_id):
                    decision = RoutingDecision(
                        backend=None,
                        strategy=self.config.strategy,
                        reason=(
                            "backend %s circuit %s"
                            % (backend_id, self.breaker.state_for(backend_id).state)
                        ),
                        candidates=len(self.config.backends),
                        seed=self.config.seed,
                    )
                else:
                    decision = RoutingDecision(
                        backend=target,
                        strategy=self.config.strategy,
                        reason="forced backend %s" % backend_id,
                        candidates=len(self.config.backends),
                        seed=self.config.seed,
                    )
        else:
            decision = self.router.select(role)
        self.store.save_rr_index(self.router.rr_index)
        self.store.append_routing_log(
            {
                "backend": decision.backend.backend_id if decision.backend else None,
                "strategy": decision.strategy,
                "reason": decision.reason,
                "candidates": decision.candidates,
                "seed": decision.seed,
                "ts": self.clock(),
            }
        )
        return decision

    def record_success(self, backend_id: str, latency_ms: Optional[float] = None) -> None:
        self.router.record_success(backend_id, latency_ms)

    def record_failure(self, backend_id: str) -> None:
        self.router.record_failure(backend_id)

    # ---- health ---------------------------------------------------------
    def probe(self, backend_id: Optional[str] = None) -> Union[ProbeResult, List[ProbeResult]]:
        if backend_id is not None:
            target = next((b for b in self.config.backends if b.backend_id == backend_id), None)
            if target is None:
                raise ValueError("unknown backend_id %r" % backend_id)
            return self.health.probe_backend(target)
        return self.health.check_all()

    def is_healthy(self, backend_id: str) -> bool:
        st = self.backend_states.get(backend_id)
        return bool(st is not None and st.healthy)

    # ---- persistence ----------------------------------------------------
    def save(self) -> None:
        self.store.save_config(self.config)
        self.store.save_backend_states(self.backend_states)
        self.store.save_circuit_states(self.breaker.all_states())
