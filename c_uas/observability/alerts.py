"""
Alerting rules engine: threshold-based, rate-of-change, absence-of-signal.

Alerts carry severity levels (info/warning/critical/emergency) and lifecycle
states (active/firing/resolved). Duplicate alerts for the same rule + label
set are collapsed (deduplication). State persists under
~/.c-uas-platform/observability/alerts/ (outside the repo).

License: AGPL-3.0.
"""

from __future__ import annotations

import hashlib
import json
import math
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
ALERTS_DIR = OBS_DIR / "alerts"


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
# Severity & state
# --------------------------------------------------------------------------- #


class AlertSeverity:
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

    ORDER = {INFO: 0, WARNING: 1, CRITICAL: 2, EMERGENCY: 3}
    ALL = (INFO, WARNING, CRITICAL, EMERGENCY)


class AlertState:
    ACTIVE = "active"
    FIRING = "firing"
    RESOLVED = "resolved"

    ALL = (ACTIVE, FIRING, RESOLVED)


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AlertRule:
    """A declarative alerting rule."""

    rule_id: str
    name: str
    metric: str  # metric name to evaluate
    condition: str  # "threshold" | "rate_of_change" | "absence_of_signal"
    threshold: float  # comparison value
    severity: str  # AlertSeverity.*
    for_seconds: float = 60.0  # evaluation window
    labels: Tuple[Tuple[str, str], ...] = ()  # rule-scoped label filter
    comparison: str = "gt"  # "gt" | "lt" | "eq" (threshold rules)


@dataclass(frozen=True)
class ThresholdRule:
    rule_id: str
    name: str
    metric: str
    threshold: float
    severity: str
    comparison: str = "gt"
    for_seconds: float = 60.0
    labels: Tuple[Tuple[str, str], ...] = ()

    def to_alert_rule(self) -> AlertRule:
        return AlertRule(
            rule_id=self.rule_id,
            name=self.name,
            metric=self.metric,
            condition="threshold",
            threshold=self.threshold,
            severity=self.severity,
            for_seconds=self.for_seconds,
            labels=self.labels,
            comparison=self.comparison,
        )


@dataclass(frozen=True)
class RateOfChangeRule:
    rule_id: str
    name: str
    metric: str
    threshold: float  # absolute rate of change per second
    severity: str
    for_seconds: float = 60.0
    labels: Tuple[Tuple[str, str], ...] = ()

    def to_alert_rule(self) -> AlertRule:
        return AlertRule(
            rule_id=self.rule_id,
            name=self.name,
            metric=self.metric,
            condition="rate_of_change",
            threshold=self.threshold,
            severity=self.severity,
            for_seconds=self.for_seconds,
            labels=self.labels,
        )


@dataclass(frozen=True)
class AbsenceSignalRule:
    rule_id: str
    name: str
    metric: str
    severity: str
    for_seconds: float = 60.0
    labels: Tuple[Tuple[str, str], ...] = ()

    def to_alert_rule(self) -> AlertRule:
        return AlertRule(
            rule_id=self.rule_id,
            name=self.name,
            metric=self.metric,
            condition="absence_of_signal",
            threshold=0.0,
            severity=self.severity,
            for_seconds=self.for_seconds,
            labels=self.labels,
        )


@dataclass(frozen=True)
class Alert:
    """A fired (or resolved) alert instance."""

    alert_id: str
    rule_id: str
    name: str
    metric: str
    severity: str
    state: str  # AlertState.*
    value: float
    threshold: float
    labels: Tuple[Tuple[str, str], ...]
    fired_at: str
    resolved_at: Optional[str] = None
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# AlertingEngine
# --------------------------------------------------------------------------- #


class AlertingEngine:
    """Evaluates alert rules against a metrics registry."""

    def __init__(
        self,
        registry: Any,
        state_dir: Optional[str] = None,
    ) -> None:
        self.registry = registry
        self.state_dir = Path(state_dir) if state_dir is not None else ALERTS_DIR
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._rules: Dict[str, AlertRule] = {}
        # alert_id -> Alert (current lifecycle state)
        self._alerts: Dict[str, Alert] = {}
        # rule_id+labels_key -> last fired value & timestamp (for rate_of_change)
        self._last_value: Dict[str, Tuple[float, str]] = {}

    # -- rule registration ------------------------------------------------ #

    def add_rule(self, rule: AlertRule) -> None:
        self._rules[rule.rule_id] = rule

    def add_threshold_rule(self, rule: ThresholdRule) -> None:
        self.add_rule(rule.to_alert_rule())

    def add_rate_of_change_rule(self, rule: RateOfChangeRule) -> None:
        self.add_rule(rule.to_alert_rule())

    def add_absence_signal_rule(self, rule: AbsenceSignalRule) -> None:
        self.add_rule(rule.to_alert_rule())

    # -- evaluation -------------------------------------------------------- #

    def _series_for(
        self, metric: str, labels_key: Tuple[Tuple[str, str], ...]
    ) -> List[Tuple[str, float]]:
        """Return timestamped samples for a metric + label set."""
        counters = getattr(self.registry, "_counter_samples", {})
        gauges = getattr(self.registry, "_gauge_samples", {})
        histograms = getattr(self.registry, "_histogram_observations", {})
        summaries = getattr(self.registry, "_summary_observations", {})
        for store in (counters, gauges, histograms, summaries):
            by_label = store.get(metric)
            if by_label is None:
                continue
            series = by_label.get(labels_key)
            if series:
                return series
        return []

    def _latest(
        self, metric: str, labels_key: Tuple[Tuple[str, str], ...]
    ) -> Optional[Tuple[str, float]]:
        series = self._series_for(metric, labels_key)
        if not series:
            return None
        return series[-1]

    def _compare(self, value: float, threshold: float, comparison: str) -> bool:
        if comparison == "gt":
            return value > threshold
        if comparison == "lt":
            return value < threshold
        if comparison == "eq":
            return math.isclose(value, threshold, abs_tol=1e-12)
        return value > threshold

    def _alert_key(self, rule_id: str, labels_key: Tuple[Tuple[str, str], ...]) -> str:
        raw = f"{rule_id}|{labels_key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _message(self, rule: AlertRule, value: float, triggered: bool) -> str:
        if rule.condition == "absence_of_signal":
            return f"No signal on metric '{rule.metric}' for {rule.for_seconds}s"
        op = {">": "gt", "<": "lt", "==": "eq"}.get(rule.comparison, rule.comparison)
        if triggered:
            return (
                f"Metric '{rule.metric}' {op} {rule.threshold} "
                f"(current {value:.6f}) — {rule.severity}"
            )
        return f"Metric '{rule.metric}' recovered (current {value:.6f}, threshold {rule.threshold})"

    def evaluate(self, now_iso: Optional[str] = None) -> List[Alert]:
        """Evaluate all rules against current registry state.

        Returns the list of alerts that changed state in this evaluation.
        Fully deterministic given the same registry contents.
        """
        now_iso = now_iso or utc_now_iso()
        changed: List[Alert] = []

        for rule in sorted(self._rules.values(), key=lambda r: r.rule_id):
            labels_key = rule.labels
            latest = self._latest(rule.metric, labels_key)

            if rule.condition == "absence_of_signal":
                # Absence: alert when no samples within the window.
                if latest is None:
                    triggered = True
                    value = 0.0
                else:
                    try:
                        ts = datetime.fromisoformat(latest[0].replace("Z", "+00:00"))
                        age_s = (datetime.now(timezone.utc) - ts).total_seconds()
                        triggered = age_s > rule.for_seconds
                        value = latest[1]
                    except ValueError:
                        triggered = True
                        value = latest[1]
            elif rule.condition == "rate_of_change":
                key = f"{rule.rule_id}|{labels_key}"
                prev = self._last_value.get(key)
                if latest is None:
                    triggered = False
                    value = 0.0
                elif prev is None:
                    # First sample: establish baseline, no alert yet.
                    self._last_value[key] = (latest[1], latest[0])
                    triggered = False
                    value = latest[1]
                else:
                    try:
                        t0 = datetime.fromisoformat(prev[1].replace("Z", "+00:00"))
                        t1 = datetime.fromisoformat(latest[0].replace("Z", "+00:00"))
                        dt = max((t1 - t0).total_seconds(), 1e-6)
                        rate = abs((latest[1] - prev[0]) / dt)
                        triggered = rate > rule.threshold
                        value = rate
                    except ValueError:
                        triggered = False
                        value = latest[1]
                    self._last_value[key] = (latest[1], latest[0])
            else:  # threshold
                if latest is None:
                    triggered = False
                    value = 0.0
                else:
                    value = latest[1]
                    triggered = self._compare(value, rule.threshold, rule.comparison)

            alert_id = self._alert_key(rule.rule_id, labels_key)
            existing = self._alerts.get(alert_id)

            if triggered:
                if existing is None or existing.state == AlertState.RESOLVED:
                    alert = Alert(
                        alert_id=alert_id,
                        rule_id=rule.rule_id,
                        name=rule.name,
                        metric=rule.metric,
                        severity=rule.severity,
                        state=AlertState.FIRING,
                        value=value,
                        threshold=rule.threshold,
                        labels=labels_key,
                        fired_at=now_iso,
                        resolved_at=None,
                        message=self._message(rule, value, True),
                    )
                    self._alerts[alert_id] = alert
                    changed.append(alert)
                    _write_json(self.state_dir / f"{alert_id}.json", alert)
                elif existing.state == AlertState.ACTIVE:
                    # Re-fire: update value/message, keep firing.
                    alert = Alert(
                        alert_id=alert_id,
                        rule_id=rule.rule_id,
                        name=rule.name,
                        metric=rule.metric,
                        severity=rule.severity,
                        state=AlertState.FIRING,
                        value=value,
                        threshold=rule.threshold,
                        labels=labels_key,
                        fired_at=existing.fired_at,
                        resolved_at=None,
                        message=self._message(rule, value, True),
                    )
                    self._alerts[alert_id] = alert
                    changed.append(alert)
                    _write_json(self.state_dir / f"{alert_id}.json", alert)
                # Already FIRING: no change (deduplication).
            else:
                if existing is not None and existing.state in (
                    AlertState.ACTIVE,
                    AlertState.FIRING,
                ):
                    alert = Alert(
                        alert_id=alert_id,
                        rule_id=rule.rule_id,
                        name=rule.name,
                        metric=rule.metric,
                        severity=rule.severity,
                        state=AlertState.RESOLVED,
                        value=value,
                        threshold=rule.threshold,
                        labels=labels_key,
                        fired_at=existing.fired_at,
                        resolved_at=now_iso,
                        message=self._message(rule, value, False),
                    )
                    self._alerts[alert_id] = alert
                    changed.append(alert)
                    _write_json(self.state_dir / f"{alert_id}.json", alert)

        return changed

    def active_alerts(self) -> List[Alert]:
        return sorted(
            (a for a in self._alerts.values() if a.state != AlertState.RESOLVED),
            key=lambda a: (AlertSeverity.ORDER.get(a.severity, 99), a.rule_id),
        )

    def firing_alerts(self) -> List[Alert]:
        return sorted(
            (a for a in self._alerts.values() if a.state == AlertState.FIRING),
            key=lambda a: (AlertSeverity.ORDER.get(a.severity, 99), a.rule_id),
        )

    def resolved_alerts(self) -> List[Alert]:
        return sorted(
            (a for a in self._alerts.values() if a.state == AlertState.RESOLVED),
            key=lambda a: a.resolved_at or "",
        )

    def all_alerts(self) -> List[Alert]:
        return sorted(self._alerts.values(), key=lambda a: a.fired_at)

    def summary(self) -> Dict[str, Any]:
        return {
            "total": len(self._alerts),
            "firing": len(self.firing_alerts()),
            "active": len([a for a in self._alerts.values() if a.state == AlertState.ACTIVE]),
            "resolved": len(self.resolved_alerts()),
            "by_severity": {
                sev: len(
                    [
                        a
                        for a in self._alerts.values()
                        if a.severity == sev and a.state != AlertState.RESOLVED
                    ]
                )
                for sev in AlertSeverity.ALL
            },
        }


def new_engine(registry: Any, state_dir: Optional[str] = None) -> AlertingEngine:
    return AlertingEngine(registry=registry, state_dir=state_dir)
