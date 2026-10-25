"""Observability & Alerting for the C-UAS platform.

Production-grade visibility into platform health, performance, and SLOs:
Prometheus-style metrics registry, alerting rules engine, health aggregation,
and SLO / error-budget tracking.

State persists under ~/.c-uas-platform/observability/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from .alerts import (
    AbsenceSignalRule,
    Alert,
    AlertingEngine,
    AlertRule,
    AlertSeverity,
    AlertState,
    RateOfChangeRule,
    ThresholdRule,
    new_engine,
)
from .health import (
    ComponentHealth,
    CompositeHealth,
    HealthAggregator,
    HealthStatus,
)
from .metrics import (
    Counter,
    Gauge,
    Histogram,
    Metric,
    MetricFamily,
    MetricRegistry,
    MetricType,
    Summary,
    new_registry,
)
from .slo import (
    BurnAlert,
    ErrorBudget,
    SLOResult,
    SLOTarget,
    SLOTracker,
    new_tracker,
)

__all__ = [
    # metrics
    "MetricType",
    "Metric",
    "MetricFamily",
    "Counter",
    "Gauge",
    "Histogram",
    "Summary",
    "MetricRegistry",
    # alerts
    "AlertSeverity",
    "AlertState",
    "AlertRule",
    "ThresholdRule",
    "RateOfChangeRule",
    "AbsenceSignalRule",
    "Alert",
    "AlertingEngine",
    # health
    "HealthStatus",
    "ComponentHealth",
    "CompositeHealth",
    "HealthAggregator",
    # slo
    "SLOTarget",
    "SLOResult",
    "ErrorBudget",
    "BurnAlert",
    "SLOTracker",
    "new_engine",
    "new_registry",
    "new_tracker",
]
