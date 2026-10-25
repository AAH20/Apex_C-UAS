"""``c-uas obs`` subcommand: Observability & Alerting.

Usage:
    c-uas obs --metrics [--text]
    c-uas obs --alerts [--eval]
    c-uas obs --health
    c-uas obs --slo [--burn]

All output is deterministic. State persists under
~/.c-uas-platform/observability/ (outside the repo).
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, List, Optional

from .alerts import (
    AbsenceSignalRule,
    AlertingEngine,
    RateOfChangeRule,
    ThresholdRule,
    new_engine,
)
from .health import (
    HealthAggregator,
    new_aggregator,
    run_all_probes,
)
from .metrics import (
    MetricRegistry,
    MetricType,
    new_registry,
)
from .slo import (
    SLOTarget,
    SLOTracker,
    new_tracker,
)


def build_subparser(subparsers: Any) -> Any:
    """Register the ``obs`` subcommand on a parent parser."""
    parser = subparsers.add_parser(
        "obs",
        help="Observability & Alerting: metrics, alerts, health, SLOs",
    )
    parser.add_argument(
        "--metrics",
        action="store_true",
        help="Show the Prometheus-style metrics collection",
    )
    parser.add_argument(
        "--text",
        action="store_true",
        help="Emit metrics in Prometheus-like text exposition (with --metrics)",
    )
    parser.add_argument(
        "--alerts",
        action="store_true",
        help="Show alerting engine state (firing / resolved / summary)",
    )
    parser.add_argument(
        "--eval",
        action="store_true",
        help="Evaluate alert rules (with --alerts)",
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help="Show composite platform health",
    )
    parser.add_argument(
        "--slo",
        action="store_true",
        help="Show SLO / error-budget evaluation",
    )
    parser.add_argument(
        "--burn",
        action="store_true",
        help="Show burn-rate alerts (with --slo)",
    )
    return parser


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #


def render_metrics(registry: MetricRegistry, text: bool = False) -> str:
    if text:
        return registry.to_text()
    result = registry.collect()
    lines: List[str] = []
    lines.append("[C-UAS] Metrics Collection")
    lines.append(f"  Collected at : {result.collected_at}")
    lines.append(f"  Counters     : {len(result.counters)}")
    lines.append(f"  Gauges       : {len(result.gauges)}")
    lines.append(f"  Histograms   : {len(result.histograms)}")
    lines.append(f"  Summaries    : {len(result.summaries)}")
    for c in result.counters:
        lbl = ",".join(f"{k}={v}" for k, v in c.labels) or "-"
        lines.append(f"  counter {c.name}[{lbl}] = {c.value}")
    for g in result.gauges:
        lbl = ",".join(f"{k}={v}" for k, v in g.labels) or "-"
        lines.append(f"  gauge   {g.name}[{lbl}] = {g.value}")
    for h in result.histograms:
        lbl = ",".join(f"{k}={v}" for k, v in h.labels) or "-"
        lines.append(f"  hist    {h.name}[{lbl}] count={h.count} sum={h.sum}")
    for s in result.summaries:
        lbl = ",".join(f"{k}={v}" for k, v in s.labels) or "-"
        qstr = ",".join(f"q{q}={v}" for q, v in s.quantiles)
        lines.append(f"  summary {s.name}[{lbl}] count={s.count} sum={s.sum} {qstr}")
    return "\n".join(lines)


def render_alerts(engine: AlertingEngine, eval_rules: bool = False) -> str:
    changed = engine.evaluate() if eval_rules else []
    lines: List[str] = []
    summary = engine.summary()
    lines.append("[C-UAS] Alerting Engine")
    lines.append(f"  Total alerts : {summary['total']}")
    lines.append(f"  Firing       : {summary['firing']}")
    lines.append(f"  Active       : {summary['active']}")
    lines.append(f"  Resolved     : {summary['resolved']}")
    lines.append(f"  By severity  : {summary['by_severity']}")
    firing = engine.firing_alerts()
    if firing:
        lines.append("  Firing alerts:")
        for a in firing:
            lines.append(
                f"    - [{a.severity.upper()}] {a.name} ({a.metric}) = {a.value:.6f} "
                f"threshold={a.threshold:.6f} :: {a.message}"
            )
    resolved = engine.resolved_alerts()
    if resolved:
        lines.append("  Recently resolved:")
        for a in resolved[:5]:
            lines.append(f"    - {a.name} resolved at {a.resolved_at}")
    if eval_rules and not changed:
        lines.append("  No state changes this evaluation.")
    return "\n".join(lines)


def render_health(aggregator: HealthAggregator) -> str:
    composite = aggregator.composite()
    return composite.to_text()


def render_slo(tracker: SLOTracker, burn: bool = False) -> str:
    results = tracker.evaluate_all()
    lines: List[str] = []
    lines.append("[C-UAS] SLO / Error Budget")
    lines.append(f"  Targets tracked : {len(results)}")
    for r in results:
        mark = "COMPLIANT" if r.compliant else "NON_COMPLIANT"
        lines.append(
            f"  {r.service}/{r.metric}: target={r.target} actual={r.actual} "
            f"budget_remaining={r.error_budget_remaining:.2%} "
            f"burn_rate={r.burn_rate:.4f}/window [{mark}]"
        )
    if burn:
        alerts = tracker.burn_alerts()
        lines.append(f"  Burn alerts : {len(alerts)}")
        for a in alerts:
            tte = (
                f"{a.time_to_exhaustion_seconds:.0f}s"
                if a.time_to_exhaustion_seconds is not None
                else "n/a"
            )
            lines.append(
                f"  - [{a.severity.upper()}] {a.service}/{a.metric} "
                f"burn={a.burn_rate:.4f} remaining={a.budget_remaining:.2%} tte={tte}"
            )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #


def _demo_registry() -> MetricRegistry:
    """Build a deterministic demo registry with real observed values."""
    registry = new_registry()
    registry.register(
        "http_requests_total",
        MetricType.COUNTER,
        help="Total HTTP requests",
        unit="requests",
        label_names=("code", "method"),
    )
    registry.register(
        "http_request_duration_seconds",
        MetricType.HISTOGRAM,
        help="HTTP latency",
        unit="seconds",
        label_names=("handler",),
    )
    registry.register(
        "api_requests_in_flight", MetricType.GAUGE, help="In-flight requests", unit="requests"
    )
    registry.register(
        "api_response_time_seconds",
        MetricType.SUMMARY,
        help="API response time",
        unit="seconds",
        label_names=("endpoint",),
    )

    c = registry.counter("http_requests_total")
    for code, method, n in (("200", "GET", 1250), ("404", "GET", 30), ("500", "POST", 5)):
        c.inc(float(n), labels={"code": code, "method": method})

    h = registry.histogram("http_request_duration_seconds")
    for v in (0.012, 0.045, 0.089, 0.210, 0.540, 1.230, 2.500):
        h.observe(v, labels={"handler": "detect"})

    g = registry.gauge("api_requests_in_flight")
    g.set(7.0)

    s = registry.summary("api_response_time_seconds")
    for v in (0.05, 0.11, 0.19, 0.33, 0.67, 1.10):
        s.observe(v, labels={"endpoint": "/detect"})
    return registry


def _demo_engine(registry: MetricRegistry) -> AlertingEngine:
    engine = new_engine(registry)
    engine.add_threshold_rule(
        ThresholdRule(
            rule_id="obs-001",
            name="high_error_rate",
            metric="http_requests_total",
            threshold=1000.0,
            severity="warning",
            comparison="gt",
            for_seconds=60.0,
            labels=(("code", "500"), ("method", "POST")),
        )
    )
    engine.add_rate_of_change_rule(
        RateOfChangeRule(
            rule_id="obs-002",
            name="latency_spike",
            metric="http_request_duration_seconds",
            threshold=0.5,
            severity="critical",
            for_seconds=60.0,
        )
    )
    engine.add_absence_signal_rule(
        AbsenceSignalRule(
            rule_id="obs-003",
            name="missing_metric",
            metric="api_requests_in_flight",
            severity="warning",
            for_seconds=60.0,
        )
    )
    return engine


def _demo_slo() -> SLOTracker:
    tracker = new_tracker()
    tracker.add_target(
        SLOTarget(
            service="detection-api",
            metric="availability",
            target=0.999,
            window_seconds=3600,
            is_latency=False,
        )
    )
    tracker.add_target(
        SLOTarget(
            service="detection-api",
            metric="latency_p95",
            target=0.5,
            window_seconds=3600,
            is_latency=True,
        )
    )
    tracker.add_target(
        SLOTarget(
            service="engagement-api",
            metric="error_rate",
            target=0.01,
            window_seconds=3600,
            is_latency=False,
        )
    )
    # Deterministic observations.
    tracker.observe("detection-api", "availability", 0.9995)
    tracker.observe("detection-api", "latency_p95", 0.42)
    tracker.observe("engagement-api", "error_rate", 0.003)
    return tracker


def handle_metrics(text: bool = False) -> str:
    registry = _demo_registry()
    return render_metrics(registry, text=text)


def handle_alerts(eval_rules: bool = False) -> str:
    registry = _demo_registry()
    engine = _demo_engine(registry)
    return render_alerts(engine, eval_rules=eval_rules)


def handle_health() -> str:
    aggregator = new_aggregator()
    run_all_probes(aggregator)
    return render_health(aggregator)


def handle_slo(burn: bool = False) -> str:
    tracker = _demo_slo()
    return render_slo(tracker, burn=burn)


def obs_main(args: argparse.Namespace) -> int:
    if args.metrics:
        print(handle_metrics(text=args.text))
        return 0
    if args.alerts:
        print(handle_alerts(eval_rules=args.eval))
        return 0
    if args.health:
        print(handle_health())
        return 0
    if args.slo:
        print(handle_slo(burn=args.burn))
        return 0
    print("[C-UAS] obs: specify --metrics, --alerts, --health, or --slo")
    print("  c-uas obs --metrics --text")
    print("  c-uas obs --alerts --eval")
    print("  c-uas obs --health")
    print("  c-uas obs --slo --burn")
    return 1


def main(argv: Optional[list] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="c-uas obs",
        description="Observability & Alerting for the C-UAS platform",
    )
    build_subparser(parser.add_subparsers(dest="command"))
    args = parser.parse_args(argv)
    return obs_main(args)


if __name__ == "__main__":
    sys.exit(main())
