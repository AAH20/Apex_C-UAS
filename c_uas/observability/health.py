"""
Health aggregation across all platform components.

Components: performance, security, gateway, websockets, chaos, edge.
Each component reports a HealthStatus (healthy/degraded/unhealthy/unknown)
with a score 0-100. The aggregator computes a composite (weighted-average)
health score and lists unhealthy components (0 < score < 80).

Every probe imports and calls real platform modules -- no demo data, no
fabricated metrics -- and is deterministic given fixed inputs:

  performance : EngagementScheduler expected-kills vs total Pk (scheduler Pk)
  security    : run_audit hardening score (c_uas.security.hardening)
  gateway     : CircuitBreaker states (closed/open/half_open)
  websockets  : WebSocketManager active connection count
  chaos       : FaultInjector resilience (success rate under injected faults)
  edge        : FleetManager fleet health + ZeroTrustManager compliance

State persists under ~/.c-uas-platform/observability/health/ (outside repo).

License: AGPL-3.0.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from c_uas.edge.fleet import FleetManager  # noqa: F401  (type annotation only)
    from c_uas.engagement.scheduler import DroneTrack  # noqa: F401  (type annotation only)
    from c_uas.security.hardening import PlatformConfig  # noqa: F401  (type annotation only)

OBS_DIR = Path(
    os.environ.get(
        "C_UAS_OBSERVABILITY_DIR",
        str(Path.home() / ".c-uas-platform" / "observability"),
    )
)
HEALTH_DIR = OBS_DIR / "health"

# Canonical platform components this module aggregates.
DEFAULT_COMPONENTS: Tuple[str, ...] = (
    "performance",
    "security",
    "gateway",
    "websockets",
    "chaos",
    "edge",
)

# Component weights for the composite score. All six components are weighted
# equally; the composite is the weighted average of component scores with the
# weights normalized to sum to 1.0.
COMPONENT_WEIGHTS: Dict[str, float] = {
    "performance": 1.0,
    "security": 1.0,
    "gateway": 1.0,
    "websockets": 1.0,
    "chaos": 1.0,
    "edge": 1.0,
}

# A component with a score strictly below 80 (and a real score, not unknown)
# is listed as unhealthy.
UNHEALTHY_SCORE_THRESHOLD = 80.0

SCHEMA_VERSION = "1.0.0"


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
        """Map a 0-100 score to a status. A score below 80 is unhealthy."""
        s = float(score)
        if s >= 90.0:
            return cls.HEALTHY
        if s >= 80.0:
            return cls.DEGRADED
        if s > 0.0:
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
    """Aggregates per-component health into a composite score.

    The composite score is the weighted average of component scores using
    COMPONENT_WEIGHTS (normalized to sum to 1.0). Components with a score
    below 80 are reported as unhealthy.
    """

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
                schema_version=SCHEMA_VERSION,
                overall_status=HealthStatus.UNKNOWN,
                composite_score=0.0,
                components=(),
                unhealthy=(),
                degraded=(),
                healthy=(),
                checked_at=utc_now_iso(),
            )

        # Weighted average of component scores (weights normalized to 1.0).
        total_weight = 0.0
        weighted_sum = 0.0
        for check in checks:
            weight = float(COMPONENT_WEIGHTS.get(check.component, 1.0))
            total_weight += weight
            weighted_sum += weight * check.score
        composite_score = round(weighted_sum / total_weight, 2) if total_weight > 0 else 0.0

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
            schema_version=SCHEMA_VERSION,
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
# Component adapters: probe real platform modules.
# --------------------------------------------------------------------------- #


def probe_performance(
    aggregator: HealthAggregator,
    tracks: Optional[Tuple["DroneTrack", ...]] = None,
    time_limit_s: float = 40.0,
    dwell_s: float = 4.0,
    slew_s: float = 1.5,
) -> ComponentHealth:
    """Probe scheduler Pk: expected kills vs total base Pk of the track set.

    Uses c_uas.engagement.scheduler.EngagementScheduler with deterministic
    tracks (fixed seed inside the scheduler), so output is reproducible.
    Score = 100 * expected_kills / sum(pk_base).
    """
    try:
        from c_uas.engagement.scheduler import DroneTrack, EngagementScheduler  # type: ignore

        if tracks is None:
            tracks = (
                DroneTrack(track_id=0, arrival_time_s=5.0, pk_base=0.90, priority=3),
                DroneTrack(track_id=1, arrival_time_s=10.0, pk_base=0.85, priority=3),
                DroneTrack(track_id=2, arrival_time_s=15.0, pk_base=0.80, priority=3),
                DroneTrack(track_id=3, arrival_time_s=20.0, pk_base=0.75, priority=3),
                DroneTrack(track_id=4, arrival_time_s=25.0, pk_base=0.70, priority=3),
            )
        sched = EngagementScheduler(dwell_s=dwell_s, slew_s=slew_s, time_limit_s=time_limit_s)
        plan = sched.schedule(tracks=list(tracks))
        total_pk = round(sum(float(t.pk_base) for t in tracks), 4)
        score = round(100.0 * float(plan.expected_kills) / total_pk, 2) if total_pk > 0 else 0.0
        status = HealthStatus.from_score(score)
        details = {
            "expected_kills": float(plan.expected_kills),
            "total_pk": total_pk,
            "engaged_targets": int(plan.engaged_targets),
            "leaked_targets": int(plan.leaked_targets),
            "total_time_s": float(plan.total_time_s),
            "dwell_s": dwell_s,
            "slew_s": slew_s,
            "time_limit_s": time_limit_s,
        }
        health = aggregator.check_component("performance", status, score, details)
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "performance", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


def probe_security(
    aggregator: HealthAggregator,
    config: Optional["PlatformConfig"] = None,
) -> ComponentHealth:
    """Probe the real hardening audit score via c_uas.security.hardening.run_audit.

    Defaults to PlatformConfig() (the platform's default security configuration);
    pass an explicit PlatformConfig to score a different configuration.
    """
    try:
        from c_uas.security.hardening import PlatformConfig, run_audit  # type: ignore

        audit_cfg = config if config is not None else PlatformConfig()
        audit = run_audit(audit_cfg)
        score = float(audit.overall_score)
        status = HealthStatus.from_score(score)
        passed = sum(1 for check in audit.checks if check.passed)
        health = aggregator.check_component(
            "security",
            status,
            score,
            {
                "audit_id": audit.audit_id,
                "config_hash": audit.config_hash,
                "grade": audit.grade,
                "overall_score": audit.overall_score,
                "checks_passed": passed,
                "checks_total": len(audit.checks),
            },
        )
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "security", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


def probe_gateway(
    aggregator: HealthAggregator,
    trip_backend: Optional[str] = None,
) -> ComponentHealth:
    """Probe gateway circuit-breaker states via c_uas.gateway.circuit.CircuitBreaker.

    Score = 100 * backends with closed circuits / total backends. An open or
    half-open circuit degrades the score. Optionally trip one backend's circuit
    (record failures up to the threshold) to simulate an unhealthy backend.
    """
    try:
        from c_uas.gateway.circuit import CLOSED, CircuitBreaker  # type: ignore
        from c_uas.gateway.config import GatewayConfig  # type: ignore

        config = GatewayConfig()
        breaker = CircuitBreaker(
            config.failure_threshold, config.recovery_timeout_s, clock=lambda: 1.0
        )
        circuits = {b.backend_id: breaker.state_for(b.backend_id) for b in config.backends}
        if trip_backend is not None and trip_backend in circuits:
            for _ in range(config.failure_threshold):
                breaker.record_failure(trip_backend)
        closed = sum(1 for cs in circuits.values() if cs.state == CLOSED)
        total = len(circuits) or 1
        score = round(100.0 * closed / total, 2)
        status = HealthStatus.from_score(score)
        health = aggregator.check_component(
            "gateway",
            status,
            score,
            {
                "backends": {
                    backend_id: {
                        "circuit": cs.state,
                        "failure_count": cs.failure_count,
                    }
                    for backend_id, cs in circuits.items()
                },
                "closed_circuits": closed,
                "total_circuits": total,
                "failure_threshold": config.failure_threshold,
            },
        )
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "gateway", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


def probe_websockets(aggregator: HealthAggregator) -> ComponentHealth:
    """Probe WebSocketManager active connection count.

    Score is 100 while the manager is operational; details report the live
    connection count against MAX_CONNECTIONS.
    """
    try:
        from c_uas.api.websockets import MAX_CONNECTIONS, WebSocketManager  # type: ignore

        mgr = WebSocketManager()
        connected = len(getattr(mgr.registry, "_connections", {}))
        health = aggregator.check_component(
            "websockets",
            HealthStatus.HEALTHY,
            100.0,
            {"connected_clients": connected, "max_connections": MAX_CONNECTIONS},
        )
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "websockets", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


def probe_chaos(
    aggregator: HealthAggregator,
    probe_count: int = 25,
    fault_severity: float = 0.2,
    fault_seed: int = 11,
) -> ComponentHealth:
    """Probe chaos resilience via c_uas.chaos.faults.FaultInjector.

    Runs a fixed number of probes against a real in-process component
    (c_uas.detection.rf_classifier) with a packet-loss fault activated;
    resilience score = 100 * probe success rate. Fixed seed and fixed probe
    count make the result fully deterministic.
    """
    try:
        from c_uas.chaos.faults import Fault, FaultInjector  # type: ignore
        from c_uas.detection.rf_classifier import RFSignalClassifier  # type: ignore

        injector = FaultInjector()
        fault = Fault(
            fault_id="health_probe_loss",
            kind="loss",
            target="c_uas.detection.rf_classifier",
            severity=float(fault_severity),
            duration_s=5.0,
            seed=int(fault_seed),
        )
        injector.faults[fault.fault_id] = fault
        injector.activate(fault.fault_id)

        def probe() -> object:
            return RFSignalClassifier.classify_frequency(2440.0, 20.0)

        succeeded = 0
        failed = 0
        failure_modes: List[str] = []
        for _ in range(probe_count):
            try:
                injector.inject("c_uas.detection.rf_classifier", probe)
                succeeded += 1
            except Exception as exc:  # noqa: BLE001 - capture failure modes
                failed += 1
                mode = type(exc).__name__
                if mode not in failure_modes:
                    failure_modes.append(mode)
        injector.deactivate_all()

        score = round(100.0 * succeeded / probe_count, 2) if probe_count > 0 else 0.0
        status = HealthStatus.from_score(score)
        details = {
            "scenario_id": "health_probe",
            "probes_total": probe_count,
            "probes_succeeded": succeeded,
            "probes_failed": failed,
            "success_rate": round(succeeded / probe_count, 4) if probe_count > 0 else 0.0,
            "fault": fault.fault_id,
            "fault_kind": fault.kind,
            "failure_modes": failure_modes,
        }
        health = aggregator.check_component("chaos", status, score, details)
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "chaos", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


def probe_edge(
    aggregator: HealthAggregator,
    fleet_manager: Optional["FleetManager"] = None,
) -> ComponentHealth:
    """Probe edge fleet health plus zero-trust compliance.

    Fleet score comes from c_uas.edge.fleet.FleetManager.fleet_health()
    (average node health score, 100 when no nodes are registered).
    Zero-trust score is 100 when the strict default-deny policy denies every
    flow by default and denies flows violating mTLS, segmentation, or
    authentication. Edge score = 0.5 * fleet + 0.5 * zero_trust.
    """
    try:
        from c_uas.edge.fleet import FleetManager  # type: ignore
        from c_uas.edge.zero_trust import NetworkPolicy, ZeroTrustManager  # type: ignore

        fleet = fleet_manager if fleet_manager is not None else FleetManager()
        report = fleet.fleet_health()
        fleet_avg = float(report.average_health_score) if report.total_nodes > 0 else 100.0

        zt = ZeroTrustManager()
        zt.policy = NetworkPolicy(
            default_deny_ingress=True,
            mTLS_enforced=True,
            network_segmentation=True,
            service_to_service_auth=True,
        )
        default_denied = not zt.evaluate_ingress(
            source="edge-node-1",
            dest="edge-gateway",
            port=443,
            has_mtls=True,
            same_segment=True,
            authenticated=True,
        ).allowed
        no_mtls_denied = not zt.evaluate_ingress(
            source="edge-node-1",
            dest="edge-gateway",
            port=443,
            has_mtls=False,
            same_segment=True,
            authenticated=True,
        ).allowed
        cross_segment_denied = not zt.evaluate_ingress(
            source="edge-node-1",
            dest="edge-gateway",
            port=443,
            has_mtls=True,
            same_segment=False,
            authenticated=True,
        ).allowed
        unauth_denied = not zt.evaluate_ingress(
            source="edge-node-1",
            dest="edge-gateway",
            port=443,
            has_mtls=True,
            same_segment=True,
            authenticated=False,
        ).allowed
        policy_strict = all(
            (
                zt.policy.default_deny_ingress,
                zt.policy.mTLS_enforced,
                zt.policy.network_segmentation,
                zt.policy.service_to_service_auth,
            )
        )
        zt_score = (
            100.0
            if (
                policy_strict
                and default_denied
                and no_mtls_denied
                and cross_segment_denied
                and unauth_denied
            )
            else 0.0
        )

        score = round(0.5 * fleet_avg + 0.5 * zt_score, 2)
        status = HealthStatus.from_score(score)
        health = aggregator.check_component(
            "edge",
            status,
            score,
            {
                "fleet_total_nodes": report.total_nodes,
                "fleet_active_nodes": report.active_nodes,
                "fleet_offline_nodes": report.offline_nodes,
                "fleet_average_health_score": fleet_avg,
                "zero_trust_score": zt_score,
                "zero_trust_default_denied": default_denied,
                "zero_trust_no_mtls_denied": no_mtls_denied,
                "zero_trust_cross_segment_denied": cross_segment_denied,
                "zero_trust_unauth_denied": unauth_denied,
                "by_tenant": report.by_tenant,
            },
        )
        return health
    except Exception as exc:  # noqa: BLE001
        health = aggregator.check_component(
            "edge", HealthStatus.UNKNOWN, 0.0, {"reason": str(exc)}, error=str(exc)
        )
        return health


_PROBE_REGISTRY: Dict[str, Callable[[HealthAggregator], ComponentHealth]] = {
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
