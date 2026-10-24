"""
C-UAS Platform API Gateway.

Multi-backend routing with health checks, circuit breakers, and load balancing
for detection / tracking / engagement backends. Deterministic with a fixed seed;
all state persisted under ~/.c-uas-platform/gateway/ (outside the repo).
"""

from .circuit import CircuitBreaker, CircuitState, CLOSED, HALF_OPEN, OPEN
from .config import Backend, GatewayConfig, DEFAULT_STATE_DIR, ROLES, STRATEGIES
from .gateway import Gateway
from .health import HealthChecker, ProbeResult
from .router import BackendRouter, BackendState, RoutingDecision
from .state import GatewayStateStore

__all__ = [
    "Backend",
    "BackendRouter",
    "BackendState",
    "CLOSED",
    "CircuitBreaker",
    "CircuitState",
    "DEFAULT_STATE_DIR",
    "Gateway",
    "GatewayConfig",
    "GatewayStateStore",
    "HALF_OPEN",
    "HealthChecker",
    "OPEN",
    "ProbeResult",
    "ROLES",
    "RoutingDecision",
    "STRATEGIES",
]
