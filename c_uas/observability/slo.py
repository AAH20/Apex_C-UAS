"""
SLO tracking: availability, latency p95, error budget burn rate.

Each SLO target defines a service, a metric, a target value, and an
evaluation window. The tracker computes the actual value, remaining error
budget, and burn rate, and emits burn alerts when the budget is being
consumed too fast.

State persists under ~/.c-uas-platform/observability/slo/ (outside the repo).

License: AGPL-3.0.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

OBS_DIR = Path(
    os.environ.get(
        "C_UAS_OBSERVABILITY_DIR",
        str(Path.home() / ".c-uas-platform" / "observability"),
    )
)
SLO_DIR = OBS_DIR / "slo"


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
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SLOTarget:
    """A service-level objective target."""

    service: str
    metric: str  # "availability" | "latency_p95" | "error_rate"
    target: float  # e.g. 0.999 (99.9% availability) or 0.5 (500ms p95)
    window_seconds: float  # evaluation window
    # For availability/error_rate: target is the minimum acceptable ratio.
    # For latency_p95: target is the maximum acceptable latency (lower is better).
    is_latency: bool = False


@dataclass(frozen=True)
class ErrorBudget:
    service: str
    metric: str
    target: float
    actual: float
    budget_consumed: float  # fraction of budget used (0-1+)
    budget_remaining: float  # fraction remaining (0-1+)
    exhausted: bool
    updated_at: str


@dataclass(frozen=True)
class SLOResult:
    service: str
    metric: str
    target: float
    actual: float
    compliant: bool
    error_budget_remaining: float
    burn_rate: float  # budget consumed per unit time (per window)
    window_seconds: float
    evaluated_at: str
    is_latency: bool = False


@dataclass(frozen=True)
class BurnAlert:
    service: str
    metric: str
    severity: str  # "warning" | "critical"
    burn_rate: float
    budget_remaining: float
    time_to_exhaustion_seconds: Optional[float]
    triggered_at: str


# --------------------------------------------------------------------------- #
# SLOTracker
# --------------------------------------------------------------------------- #


class SLOTracker:
    """Tracks SLOs, error budgets, and burn rates."""

    def __init__(
        self,
        state_dir: Optional[str] = None,
    ) -> None:
        self.state_dir = Path(state_dir) if state_dir is not None else SLO_DIR
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._targets: Dict[str, SLOTarget] = {}
        # service|metric -> list of (timestamp, value)
        self._observations: Dict[str, List[Tuple[str, float]]] = {}

    # -- target registration ---------------------------------------------- #

    def add_target(self, target: SLOTarget) -> None:
        key = f"{target.service}|{target.metric}"
        self._targets[key] = target

    def list_targets(self) -> Tuple[SLOTarget, ...]:
        return tuple(sorted(self._targets.values(), key=lambda t: (t.service, t.metric)))

    # -- observations ----------------------------------------------------- #

    def observe(
        self, service: str, metric: str, value: float, timestamp: Optional[str] = None
    ) -> None:
        key = f"{service}|{metric}"
        ts = timestamp or utc_now_iso()
        self._observations.setdefault(key, []).append((ts, float(value)))

    def _values_for(self, service: str, metric: str) -> List[float]:
        key = f"{service}|{metric}"
        return [v for _, v in self._observations.get(key, [])]

    # -- evaluation ------------------------------------------------------- #

    def evaluate(self, service: str, metric: str) -> Optional[SLOResult]:
        target_key = f"{service}|{metric}"
        target = self._targets.get(target_key)
        if target is None:
            return None
        values = self._values_for(service, metric)
        if not values:
            return None

        actual = values[-1]  # latest observation
        if target.is_latency:
            # Lower is better: compliant if actual <= target.
            compliant = actual <= target.target
            # Error budget: how much headroom remains below the target.
            if target.target > 0:
                budget_remaining = max(0.0, (target.target - actual) / target.target)
            else:
                budget_remaining = 1.0 if compliant else 0.0
        else:
            # Higher is better (availability, success rate): compliant if actual >= target.
            compliant = actual >= target.target
            if target.target > 0:
                budget_remaining = max(0.0, (actual - target.target) / target.target)
            else:
                budget_remaining = 1.0 if compliant else 0.0

        # Burn rate: fraction of budget consumed per evaluation window.
        budget_consumed = 1.0 - budget_remaining
        burn_rate = budget_consumed  # per window

        result = SLOResult(
            service=service,
            metric=metric,
            target=target.target,
            actual=round(actual, 6),
            compliant=compliant,
            error_budget_remaining=round(budget_remaining, 6),
            burn_rate=round(burn_rate, 6),
            window_seconds=target.window_seconds,
            evaluated_at=utc_now_iso(),
            is_latency=target.is_latency,
        )
        _write_json(self.state_dir / f"{service}_{metric}.json", result)
        return result

    def evaluate_all(self) -> List[SLOResult]:
        results: List[SLOResult] = []
        for target in self.list_targets():
            result = self.evaluate(target.service, target.metric)
            if result is not None:
                results.append(result)
        return results

    def error_budget(self, service: str, metric: str) -> Optional[ErrorBudget]:
        target_key = f"{service}|{metric}"
        target = self._targets.get(target_key)
        if target is None:
            return None
        values = self._values_for(service, metric)
        if not values:
            return None
        actual = values[-1]
        if target.is_latency:
            if target.target > 0:
                budget_remaining = max(0.0, (target.target - actual) / target.target)
            else:
                budget_remaining = 1.0 if actual <= target.target else 0.0
        else:
            if target.target > 0:
                budget_remaining = max(0.0, (actual - target.target) / target.target)
            else:
                budget_remaining = 1.0 if actual >= target.target else 0.0
        budget_consumed = 1.0 - budget_remaining
        return ErrorBudget(
            service=service,
            metric=metric,
            target=target.target,
            actual=round(actual, 6),
            budget_consumed=round(budget_consumed, 6),
            budget_remaining=round(budget_remaining, 6),
            exhausted=budget_remaining <= 0.0,
            updated_at=utc_now_iso(),
        )

    # -- burn alerts ------------------------------------------------------- #

    def burn_alerts(
        self,
        warning_threshold: float = 0.05,  # 5% of budget per window
        critical_threshold: float = 0.2,  # 20% of budget per window
    ) -> List[BurnAlert]:
        alerts: List[BurnAlert] = []
        now = utc_now_iso()
        for target in self.list_targets():
            result = self.evaluate(target.service, target.metric)
            if result is None:
                continue
            burn_rate = result.burn_rate
            remaining = result.error_budget_remaining
            tte: Optional[float] = None
            if burn_rate > 0 and remaining > 0:
                tte = remaining / burn_rate * target.window_seconds
            severity: Optional[str] = None
            if burn_rate >= critical_threshold:
                severity = "critical"
            elif burn_rate >= warning_threshold:
                severity = "warning"
            if severity is not None:
                alerts.append(
                    BurnAlert(
                        service=target.service,
                        metric=target.metric,
                        severity=severity,
                        burn_rate=burn_rate,
                        budget_remaining=remaining,
                        time_to_exhaustion_seconds=tte,
                        triggered_at=now,
                    )
                )
        return sorted(
            alerts,
            key=lambda a: (0 if a.severity == "critical" else 1, a.service, a.metric),
        )


# --------------------------------------------------------------------------- #
# Module-level pure helpers
# --------------------------------------------------------------------------- #


def error_budget_remaining(actual: float, target: float, is_latency: bool = False) -> float:
    if is_latency:
        if target > 0:
            return round(max(0.0, (target - actual) / target), 6)
        return 1.0 if actual <= target else 0.0
    if target > 0:
        return round(max(0.0, (actual - target) / target), 6)
    return 1.0 if actual >= target else 0.0


def burn_rate(budget_remaining: float) -> float:
    return round(1.0 - budget_remaining, 6)


def new_tracker(state_dir: Optional[str] = None) -> SLOTracker:
    return SLOTracker(state_dir=state_dir)
