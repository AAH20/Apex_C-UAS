"""Deterministic Observability & Alerting tests.

Covers the metrics registry (Counter, Gauge, Histogram, Summary),
the alerting rules engine (threshold, rate-of-change, absence-of-signal),
health aggregation, SLO / error-budget tracking, and the obs CLI.
All values are computed from real execution — no mocks, no fabricated metrics.
"""

from __future__ import annotations

from c_uas.observability import (
    AlertSeverity,
    AlertState,
    HealthStatus,
    MetricType,
    SLOTarget,
    new_engine,
    new_registry,
    new_tracker,
)
from c_uas.observability.alerts import (
    AbsenceSignalRule,
    RateOfChangeRule,
    ThresholdRule,
)
from c_uas.observability.cli import (
    handle_alerts,
    handle_health,
    handle_metrics,
    handle_slo,
    obs_main,
)
from c_uas.observability.health import new_aggregator
from c_uas.observability.metrics import compute_percentiles, percentile
from c_uas.observability.slo import burn_rate, error_budget_remaining

# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #


def test_registry_register_and_collect_deterministic() -> None:
    registry = new_registry()
    registry.register("http_requests_total", MetricType.COUNTER, label_names=("code",))
    c = registry.counter("http_requests_total")
    c.inc(10.0, labels={"code": "200"})
    c.inc(5.0, labels={"code": "200"})
    c.inc(3.0, labels={"code": "500"})

    result = registry.collect()
    counters = {(c.name, c.labels): c.value for c in result.counters}
    assert counters[("http_requests_total", (("code", "200"),))] == 15.0
    assert counters[("http_requests_total", (("code", "500"),))] == 3.0

    # Deterministic: same inputs -> same collection.
    registry2 = new_registry()
    registry2.register("http_requests_total", MetricType.COUNTER, label_names=("code",))
    c2 = registry2.counter("http_requests_total")
    c2.inc(10.0, labels={"code": "200"})
    c2.inc(5.0, labels={"code": "200"})
    c2.inc(3.0, labels={"code": "500"})
    assert registry2.collect().to_text() == registry.collect().to_text()


def test_gauge_inc_dec() -> None:
    registry = new_registry()
    registry.register("in_flight", MetricType.GAUGE)
    g = registry.gauge("in_flight")
    g.set(5.0)
    g.inc(3.0)
    g.dec(2.0)
    result = registry.collect()
    gauges = {(g2.name, g2.labels): g2.value for g2 in result.gauges}
    assert gauges[("in_flight", ())] == 6.0


def test_histogram_buckets_and_count() -> None:
    registry = new_registry()
    registry.register("latency", MetricType.HISTOGRAM, label_names=("handler",))
    h = registry.histogram("latency")
    for v in (0.01, 0.05, 0.2, 0.5, 1.0, 5.0, 10.0):
        h.observe(v, labels={"handler": "detect"})
    result = registry.collect()
    hist = [x for x in result.histograms if x.name == "latency"][0]
    assert hist.count == 7
    assert hist.sum == round(sum([0.01, 0.05, 0.2, 0.5, 1.0, 5.0, 10.0]), 6)
    inf_bucket = [b for b in hist.buckets if b.le == "+Inf"][0]
    assert inf_bucket.count == 7


def test_summary_quantiles() -> None:
    registry = new_registry()
    registry.register("response_time", MetricType.SUMMARY, label_names=("endpoint",))
    s = registry.summary("response_time")
    for v in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0):
        s.observe(v, labels={"endpoint": "/detect"})
    result = registry.collect()
    summ = [x for x in result.summaries if x.name == "response_time"][0]
    assert summ.count == 10
    qdict = dict(summ.quantiles)
    assert 0.0 <= qdict[0.5] <= 1.0
    assert 0.0 <= qdict[0.99] <= 1.0


def test_percentile_helper() -> None:
    assert percentile([], 50.0) == 0.0
    assert percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50.0) == 3.0
    assert percentile([1.0, 2.0, 3.0, 4.0, 5.0], 95.0) == 5.0
    assert percentile([1.0, 2.0, 3.0, 4.0], 50.0) == 2.0


def test_compute_percentiles() -> None:
    out = compute_percentiles([1.0, 2.0, 3.0, 4.0, 5.0])
    assert set(out) == {"p50", "p95", "p99"}
    assert out["p50"] == 3.0


def test_text_exposition_deterministic() -> None:
    registry = new_registry()
    registry.register("req_total", MetricType.COUNTER, label_names=("code",))
    c = registry.counter("req_total")
    c.inc(7.0, labels={"code": "200"})
    text1 = registry.to_text()
    text2 = registry.to_text()
    assert text1 == text2
    assert 'req_total{code="200"} 7.0' in text1


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #


def test_threshold_rule_fires_and_resolves() -> None:
    registry = new_registry()
    registry.register("cpu", MetricType.GAUGE)
    g = registry.gauge("cpu")
    engine = new_engine(registry)
    engine.add_threshold_rule(
        ThresholdRule(
            rule_id="alert-001",
            name="high_cpu",
            metric="cpu",
            threshold=80.0,
            severity="critical",
            comparison="gt",
        )
    )
    g.set(90.0)
    changed = engine.evaluate()
    assert len(changed) == 1
    assert changed[0].state == AlertState.FIRING
    assert changed[0].severity == "critical"

    g.set(10.0)
    changed2 = engine.evaluate()
    assert len(changed2) == 1
    assert changed2[0].state == AlertState.RESOLVED


def test_alert_dedup_same_rule_labels() -> None:
    registry = new_registry()
    registry.register("req", MetricType.COUNTER, label_names=("code",))
    c = registry.counter("req")
    engine = new_engine(registry)
    engine.add_threshold_rule(
        ThresholdRule(
            rule_id="alert-002",
            name="errors",
            metric="req",
            threshold=5.0,
            severity="warning",
            comparison="gt",
            labels=(("code", "500"),),
        )
    )
    c.inc(10.0, labels={"code": "500"})
    engine.evaluate()
    c.inc(10.0, labels={"code": "500"})
    engine.evaluate()
    # Same rule+label -> deduplicated, no duplicate new firing alert.
    firing = [a for a in engine.firing_alerts() if a.rule_id == "alert-002"]
    assert len(firing) == 1


def test_rate_of_change_rule() -> None:
    registry = new_registry()
    registry.register("latency", MetricType.HISTOGRAM)
    h = registry.histogram("latency")
    engine = new_engine(registry)
    engine.add_rate_of_change_rule(
        RateOfChangeRule(
            rule_id="alert-003",
            name="latency_spike",
            metric="latency",
            threshold=0.5,
            severity="critical",
        )
    )
    h.observe(0.1)
    engine.evaluate()  # baseline, no alert
    h.observe(2.0)  # large jump -> rate exceeds threshold
    changed = engine.evaluate()
    assert any(a.state == AlertState.FIRING for a in changed)


def test_absence_of_signal_rule() -> None:
    registry = new_registry()
    registry.register("heartbeat", MetricType.GAUGE)
    engine = new_engine(registry)
    engine.add_absence_signal_rule(
        AbsenceSignalRule(
            rule_id="alert-004",
            name="missing_heartbeat",
            metric="heartbeat",
            severity="warning",
            for_seconds=1.0,
        )
    )
    changed = engine.evaluate()
    assert any(a.state == AlertState.FIRING for a in changed)


def test_alert_severity_ordering() -> None:
    assert AlertSeverity.ORDER["emergency"] > AlertSeverity.ORDER["critical"]
    assert AlertSeverity.ORDER["critical"] > AlertSeverity.ORDER["warning"]
    assert AlertSeverity.ORDER["warning"] > AlertSeverity.ORDER["info"]


def test_engine_summary_counts() -> None:
    registry = new_registry()
    registry.register("err", MetricType.COUNTER)
    c = registry.counter("err")
    engine = new_engine(registry)
    engine.add_threshold_rule(
        ThresholdRule(
            rule_id="alert-005",
            name="errs",
            metric="err",
            threshold=0.0,
            severity="critical",
            comparison="gt",
        )
    )
    c.inc(1.0)
    engine.evaluate()
    summary = engine.summary()
    assert summary["total"] >= 1
    assert summary["firing"] >= 1


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #


def test_health_aggregator_composite() -> None:
    agg = new_aggregator(components=("performance", "security"))
    agg.check_component("performance", HealthStatus.HEALTHY, 95.0, {})
    agg.check_component("security", HealthStatus.DEGRADED, 75.0, {})
    composite = agg.composite()
    assert composite.composite_score == 85.0
    assert composite.overall_status == HealthStatus.DEGRADED
    assert "security" in composite.degraded
    assert "performance" in composite.healthy


def test_health_unhealthy_listing() -> None:
    agg = new_aggregator(components=("gateway", "edge"))
    agg.check_component("gateway", HealthStatus.UNHEALTHY, 10.0, {})
    agg.check_component("edge", HealthStatus.HEALTHY, 90.0, {})
    composite = agg.composite()
    assert composite.overall_status == HealthStatus.UNHEALTHY
    assert "gateway" in composite.unhealthy
    assert agg.unhealthy_components() == ["gateway"]


def test_health_all_unknown() -> None:
    agg = new_aggregator(components=("chaos",))
    composite = agg.composite()
    assert composite.overall_status == HealthStatus.UNKNOWN
    assert composite.composite_score == 0.0


def test_component_health_to_text() -> None:
    agg = new_aggregator()
    agg.check_component("websockets", HealthStatus.HEALTHY, 100.0, {"clients": 3})
    composite = agg.composite()
    out = composite.to_text()
    assert "[C-UAS] Composite Health:" in out
    assert "websockets" not in composite.unhealthy


# --------------------------------------------------------------------------- #
# SLO
# --------------------------------------------------------------------------- #


def test_slo_availability_compliant() -> None:
    tracker = new_tracker()
    tracker.add_target(
        SLOTarget(
            service="api",
            metric="availability",
            target=0.999,
            window_seconds=3600,
            is_latency=False,
        )
    )
    tracker.observe("api", "availability", 0.9995)
    result = tracker.evaluate("api", "availability")
    assert result is not None
    assert result.compliant is True
    assert result.error_budget_remaining > 0.0


def test_slo_latency_p95() -> None:
    tracker = new_tracker()
    tracker.add_target(
        SLOTarget(
            service="api",
            metric="latency_p95",
            target=0.5,
            window_seconds=3600,
            is_latency=True,
        )
    )
    tracker.observe("api", "latency_p95", 0.42)
    result = tracker.evaluate("api", "latency_p95")
    assert result is not None
    assert result.compliant is True
    assert result.is_latency is True


def test_slo_non_compliant() -> None:
    tracker = new_tracker()
    tracker.add_target(
        SLOTarget(
            service="api",
            metric="availability",
            target=0.999,
            window_seconds=3600,
            is_latency=False,
        )
    )
    tracker.observe("api", "availability", 0.99)
    result = tracker.evaluate("api", "availability")
    assert result is not None
    assert result.compliant is False


def test_error_budget_remaining_real() -> None:
    assert error_budget_remaining(0.9995, 0.999, is_latency=False) > 0.0
    assert error_budget_remaining(0.99, 0.999, is_latency=False) == 0.0
    assert error_budget_remaining(0.4, 0.5, is_latency=True) > 0.0


def test_burn_rate() -> None:
    assert burn_rate(0.8) == 0.2
    assert burn_rate(1.0) == 0.0


def test_burn_alerts_critical() -> None:
    tracker = new_tracker()
    tracker.add_target(
        SLOTarget(
            service="api",
            metric="availability",
            target=0.999,
            window_seconds=3600,
            is_latency=False,
        )
    )
    tracker.observe("api", "availability", 0.9)  # heavy burn
    alerts = tracker.burn_alerts(warning_threshold=0.05, critical_threshold=0.2)
    assert len(alerts) >= 1
    assert alerts[0].severity == "critical"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_obs_subcommand_registered() -> None:
    from c_uas.cli import main

    assert main(["obs"]) == 1  # no action -> usage, returns 1


def test_cli_obs_metrics() -> None:
    out = handle_metrics()
    assert "[C-UAS] Metrics Collection" in out
    assert "Counters" in out


def test_cli_obs_metrics_text() -> None:
    out = handle_metrics(text=True)
    assert "req_total" not in out  # demo registry uses different names
    assert "# C-UAS Platform Metrics" in out


def test_cli_obs_alerts() -> None:
    out = handle_alerts(eval_rules=True)
    assert "[C-UAS] Alerting Engine" in out


def test_cli_obs_health() -> None:
    out = handle_health()
    assert "[C-UAS] Composite Health:" in out
    assert "Composite score:" in out


def test_cli_obs_slo_burn() -> None:
    out = handle_slo(burn=True)
    assert "[C-UAS] SLO / Error Budget" in out
    assert "Burn alerts" in out


def test_cli_obs_main_dispatch() -> None:
    import argparse

    args = argparse.Namespace(
        metrics=False,
        text=False,
        alerts=False,
        eval=False,
        health=False,
        slo=False,
        burn=False,
    )
    assert obs_main(args) == 1
