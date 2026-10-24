"""
Gateway configuration: backends, routing strategy, circuit breaker thresholds,
health check interval. Deterministic with a fixed seed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple

ROLES = ("detection", "tracking", "engagement")
STRATEGIES = ("round_robin", "least_latency", "failover")

DEFAULT_STATE_DIR = os.path.expanduser("~/.c-uas-platform/gateway")


@dataclass(frozen=True)
class Backend:
    backend_id: str
    endpoint: str
    role: str
    weight: float = 1.0

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError("unknown role %r (expected one of %s)" % (self.role, ROLES))
        if self.weight <= 0:
            raise ValueError("weight must be positive")


DEFAULT_BACKENDS: Tuple[Backend, ...] = (
    Backend(
        backend_id="detection-1",
        endpoint="http://127.0.0.1:8000",
        role="detection",
        weight=1.0,
    ),
    Backend(
        backend_id="tracking-1",
        endpoint="http://127.0.0.1:8000",
        role="tracking",
        weight=1.0,
    ),
    Backend(
        backend_id="engagement-1",
        endpoint="http://127.0.0.1:8000",
        role="engagement",
        weight=1.0,
    ),
)


@dataclass(frozen=True)
class GatewayConfig:
    backends: Tuple[Backend, ...] = DEFAULT_BACKENDS
    strategy: str = "round_robin"
    failure_threshold: int = 3
    recovery_timeout_s: float = 30.0
    health_interval_s: float = 10.0
    seed: int = 42
    state_dir: str = DEFAULT_STATE_DIR

    def __post_init__(self) -> None:
        if self.strategy not in STRATEGIES:
            raise ValueError("unknown strategy %r (expected one of %s)" % (self.strategy, STRATEGIES))
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if self.recovery_timeout_s <= 0:
            raise ValueError("recovery_timeout_s must be > 0")
        if self.health_interval_s <= 0:
            raise ValueError("health_interval_s must be > 0")
        object.__setattr__(self, "state_dir", os.path.expanduser(self.state_dir))
