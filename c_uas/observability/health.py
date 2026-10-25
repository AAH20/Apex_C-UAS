"""
Health aggregation across all platform components.

Components: performance, security, gateway, websockets, chaos, edge.
Each component reports a HealthStatus (healthy/degraded/unhealthy/unknown)
with a score 0-100. The aggregator computes a composite health score and
lists unhealthy components.

State persists under ~/.c-uas-platform/observability/health/ (outside the repo).

License: AGPL-3.0.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

OBS_DIR = Path(
    os.environ.get(
        "C_UAS_OBSERVABILITY_DIR",
        str(Path.home() / ".c-uas-platform" / "observability"),
    )
)
HEALTH_DIR = OBS_DIR / "health"

# Canonical platform components this module aggregates.
DEFAULT_COMPONENTS = (
    "performance",
    "security",
    "gateway",
    "websockets",
    "chaos",
    "edge",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json(path: Path, obj: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj  # type: ignore[call-overload]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return path


def _read_json(path: Path) -> object:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------------- #


class HealthStatus:
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"

    ORDER = {HEALTHY: 0, DEGRADED: 1, UNHEALTHY: 2, UNKNOWN: 3}
    ALL = (HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN)

    @classmethod
    def from_score(cls, score: float) -> str:
        if score >= 90.0:
            return cls.HEALTHY
        if score >= 70.0:
            return cls.DEGRADED
        if score > 0.0:
            return cls.UNHEALTHY
        return cls.UNKNOWN


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ComponentHealth:
    component: str
    status: str  # HealthStatus.*
    score: float  # 0-100
    details: Dict[str, Any]
    checked_at: str
    error: Optional[str] = None


@dataclass(frozen=True)
class CompositeHealth:
    schema_version: str
    overall_status: str  # HealthStatus.*
    composite_score: float  # 0-100
    components: Tuple[ComponentHealth, ...]
    unhealthy: Tuple[str, ...]
    degraded: Tuple[str, ...]
    healthy: Tuple[str, ...]
    checked_at: str

    def to_text(self) -> str:
        lines: List[str] = []
        lines.append(f"[C-UAS] Composite Health: {self.overall_status}")
        lines.append(f"  Composite score: {self.composite_score:.1f}/100")
        lines.append(f"  Components: {len(self.components)}")
        lines.append(f"  Healthy   : {len(self.healthy)}")
        lines.append(f"  Degraded  : {len(self.degraded)}")
        lines.append(f"  Unhealthy : {len(self.unhealthy)}")
        if self.unhealthy:
            lines.append("  Unhealthy components:")
            for c in self.unhealthy:
                lines.append(f"    - {c}")
        lines.append(f"  Checked at: {self.checked_at}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HealthAggregator
# --------------------------------------------------------------------------- #


class HealthAggregator:
    """Aggregates per-component health into a composite score."""

    def __init__(
        self,
        state_dir: Optional[str] = None,
        components: Optional[Tuple[str, ...]] = None,
    ) -> None:
        self.state_dir = Path(state_dir) if state_dir is not None else HEALTH_DIR
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.components = components or DEFAULT_COMPONENTS
        self._checks: Dict[str, ComponentHealth] = {}

    def register_check(self, health: ComponentHealth) -> None:
        self._checks[health.component] = health

    def check_component(
        self,
        component: str,
        status: str,
        score: float,
        details: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> ComponentHealth:
        health = ComponentHealth(
            component=component,
            status=status,
            score=round(float(score), 2),
            details=details or {},
            checked_at=utc_now_iso(),
            error=error,
        )
        self._checks[component] = health
        _write_json(self.state_dir / f"{component}.json", health)
        return health

    def composite(self) -> CompositeHealth:
        checks = [self._checks[c] for c in self.components if c in self._checks]
        if not checks:
            return CompositeHealth(
                schema_version="1.0.0",
                overall_status=HealthStatus.UNKNOWN,
                composite_score=0.0,
                components=(),
                unhealthy=(),
                degraded=(),
                healthy=(),
                checked_at=utc_now_iso(),
            )

        # Weighted average: all components weighted equally.
        total = sum(c.score for c in checks)
        composite_score = round(total / len(checks), 2)

        statuses = [c.status for c in checks]
        if any(s == HealthStatus.UNHEALTHY for s in statuses):
            overall = HealthStatus.UNHEALTHY
        elif any(s == HealthStatus.DEGRADED for s in statuses):
            overall = HealthStatus.DEGRADED
        elif all(s == HealthStatus.HEALTHY for s in statuses):
            overall = HealthStatus.HEALTHY
        else:
            overall = HealthStatus.UNKNOWN

        healthy = tuple(sorted(c.component for c in checks if c.status == HealthStatus.HEALTHY))
        degraded = tuple(sorted(c.component for c in checks if c.status == HealthStatus.DEGRADED))
        unhealthy = tuple(sorted(c.component for c in checks if c.status == HealthStatus.UNHEALTHY))

        result = CompositeHealth(
            schema_version="1.0.0",
            overall_status=overall,
            composite_score=composite_score,
            components=tuple(sorted(checks, key=lambda c: c.component)),
            unhealthy=unhealthy,
            degraded=degraded,
            healthy=healthy,
            checked_at=utc_now_iso(),
        )
        _write_json(self.state_dir / "composite.json", result)
        return result

    def unhealthy_components(self) -> List[str]:
        return list(self.composite().unhealthy)

    def component_health(self, component: str) -> Optional[ComponentHealth]:
        return self._checks.get(component)

    def all_checks(self) -> List[ComponentHealth]:
        return sorted(self._checks.values(), key=lambda c: c.component)


# --------------------------------------------------------------------------- #
# Component adapters: probe real platform modules where available.
# --------------------------------------------------------------------------- #


def _safe_import(dotted: str) -> Any:
    try:
        mod = __import__(dotted, fromlist=["*"])
        return mod
    except Exception:
        return None


def probe_performance(aggregator: HealthAggregator) -> ComponentHealth:
    """Probe c_uas.performance SLA tracker if present, else unknown."""
    try:
        from c_uas.performance.sla_tracker import SLARegistry  # type: ignore

        reg = SLARegistry()
        # No samples -> no_data treated as unknown with 0 score.
        result = reg.compute_result("default")
        if result is None:
            health = aggregator.check_component(
                "performance",
                HealthStatus.UNKNOWN,
                0.0,
                {"reason": "no_sla_samples"},
            )
            return health
        score = 100.0 if result.overall_compliant else 50.0
        status = HealthStatus.HEALTHY if result.overall_compliant else HealthStatus.DEGRADED
        health = aggregator.check_component(
            "performance",
            status,
            score,
            {
                "p99_s": result.latency_p99_s,
                "error_rate": result.error_rate,
                "error_budget_remaining": result.error_budget_remaining,
                "overall_compliant": result.overall_compliant,
            },
        )
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "performance", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


def probe_security(aggregator: HealthAggregator) -> ComponentHealth:
    try:
        from c_uas.security.compliance_matrix import PlatformConfig  # type: ignore
        from c_uas.security.hardening import run_audit  # type: ignore

        config = PlatformConfig()
        audit = run_audit(config)
        score = float(audit.overall_score)
        status = HealthStatus.from_score(score)
        health = aggregator.check_component(
            "security",
            status,
            score,
            {
                "overall_score": audit.overall_score,
                "grade": audit.grade,
                "checks_passed": sum(1 for c in audit.checks if c.passed),
                "checks_total": len(audit.checks),
            },
        )
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "security", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


def probe_gateway(aggregator: HealthAggregator) -> ComponentHealth:
    try:
        from c_uas.gateway.health import GatewayHealthChecker  # type: ignore

        checker = GatewayHealthChecker()
        status_map = checker.check_all()  # type: ignore[attr-defined]
        healthy = sum(1 for s in status_map.values() if s == "healthy")
        total = len(status_map) or 1
        score = round(100.0 * healthy / total, 2)
        status = HealthStatus.HEALTHY if healthy == total else HealthStatus.DEGRADED
        health = aggregator.check_component(
            "gateway",
            status,
            score,
            {"backends_healthy": healthy, "backends_total": total, "status": dict(status_map)},
        )
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "gateway", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


def probe_websockets(aggregator: HealthAggregator) -> ComponentHealth:
    try:
        from c_uas.api.websockets import WebSocketManager  # type: ignore

        mgr = WebSocketManager()
        # connection_count() is async; read the sync registry dict length instead.
        connected = len(getattr(mgr._registry, "_connections", {}))  # type: ignore[attr-defined]
        health = aggregator.check_component(
            "websockets",
            HealthStatus.HEALTHY,
            100.0,
            {"connected_clients": connected},
        )
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "websockets", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


def probe_chaos(aggregator: HealthAggregator) -> ComponentHealth:
    try:
        from c_uas.chaos.scenarios import ALL_SCENARIOS  # type: ignore

        n = len(ALL_SCENARIOS)
        health = aggregator.check_component(
            "chaos",
            HealthStatus.HEALTHY,
            100.0,
            {"scenarios_loaded": n},
        )
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "chaos", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


def probe_edge(aggregator: HealthAggregator) -> ComponentHealth:
    try:
        from c_uas.edge.state import EdgeNodeState  # type: ignore

        state = EdgeNodeState()
        online = getattr(state, "is_online", lambda: False)()  # type: ignore[attr-defined]
        score = 100.0 if online else 0.0
        status = HealthStatus.HEALTHY if online else HealthStatus.UNHEALTHY
        health = aggregator.check_component("edge", status, score, {"online": online})
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "edge", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


_PROBE_REGISTRY = {
    "performance": probe_performance,
    "security": probe_security,
    "gateway": probe_gateway,
    "websockets": probe_websockets,
    "chaos": probe_chaos,
    "edge": probe_edge,
}


def run_all_probes(aggregator: HealthAggregator) -> List[ComponentHealth]:
    """Run every component probe and register results with the aggregator."""
    results: List[ComponentHealth] = []
    for component in aggregator.components:
        probe = _PROBE_REGISTRY.get(component)
        if probe is None:
            health = aggregator.check_component(
                component, HealthStatus.UNKNOWN, 0.0, {"reason": "no_probe"}
            )
            results.append(health)
            continue
        results.append(probe(aggregator))
    return results


def new_aggregator(
    state_dir: Optional[str] = None,
    components: Optional[Tuple[str, ...]] = None,
) -> HealthAggregator:
    return HealthAggregator(state_dir=state_dir, components=components)
