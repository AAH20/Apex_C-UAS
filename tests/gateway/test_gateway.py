"""Deterministic tests for the C-UAS API Gateway.

Covers the circuit breaker, health-aware router, health checker, persistence,
and the Gateway facade. All scenarios use a fixed clock and an in-memory or
temporary state directory so every test is reproducible.
"""

from c_uas.gateway.circuit import CLOSED, HALF_OPEN, OPEN, CircuitBreaker
from c_uas.gateway.config import Backend, GatewayConfig
from c_uas.gateway.gateway import Gateway
from c_uas.gateway.health import HealthChecker, ProbeResult
from c_uas.gateway.router import BackendRouter, BackendState
from c_uas.gateway.state import GatewayStateStore


def make_backends():
    return (
        Backend(backend_id="b-det", endpoint="http://det:1", role="detection"),
        Backend(backend_id="b-trk", endpoint="http://trk:1", role="tracking"),
        Backend(backend_id="b-eng", endpoint="http://eng:1", role="engagement"),
    )


def make_states(backends):
    return {b.backend_id: BackendState(backend_id=b.backend_id) for b in backends}


def _clock() -> float:
    return 0.0


def make_breaker(threshold=3, recovery=30.0, clock=None):
    if clock is None:
        clock = _clock
    return CircuitBreaker(failure_threshold=threshold, recovery_timeout_s=recovery, clock=clock)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_defaults():
    config = GatewayConfig()
    assert config.strategy == "round_robin"
    assert config.seed == 42
    assert config.failure_threshold == 3
    assert config.recovery_timeout_s == 30.0
    assert config.health_interval_s == 10.0
    assert tuple(b.backend_id for b in config.backends) == (
        "detection-1",
        "tracking-1",
        "engagement-1",
    )


def test_config_validation_bad_strategy():
    try:
        GatewayConfig(strategy="not-a-strategy")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown strategy")


def test_config_validation_bad_role():
    try:
        Backend(backend_id="x", endpoint="http://x", role="not-a-role")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown role")


def test_config_validation_non_positive_weight():
    try:
        Backend(backend_id="x", endpoint="http://x", role="detection", weight=0.0)
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-positive weight")


def test_config_persist_roundtrip(tmp_path):
    backends = make_backends()
    config = GatewayConfig(
        backends=backends,
        strategy="least_latency",
        seed=9,
        state_dir=str(tmp_path),
    )
    store = GatewayStateStore(str(tmp_path))
    store.save_config(config)
    loaded = store.load_config()
    assert loaded is not None
    assert loaded.strategy == "least_latency"
    assert loaded.seed == 9
    assert tuple(b.backend_id for b in loaded.backends) == tuple(b.backend_id for b in backends)


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


def test_circuit_closed_allows_requests():
    t = [0.0]
    cb = make_breaker(clock=lambda: t[0])
    assert cb.allow_request("b1") is True
    assert cb.state_for("b1").state == CLOSED


def test_circuit_opens_after_threshold():
    t = [0.0]
    cb = make_breaker(threshold=3, clock=lambda: t[0])
    cb.record_failure("b1")
    cb.record_failure("b1")
    assert cb.state_for("b1").state == CLOSED
    cb.record_failure("b1")
    st = cb.state_for("b1")
    assert st.state == OPEN
    assert st.opened_at == 0.0
    assert cb.allow_request("b1") is False


def test_circuit_open_rejects_until_recovery():
    t = [0.0]
    cb = make_breaker(threshold=2, recovery=30.0, clock=lambda: t[0])
    cb.record_failure("b1")
    cb.record_failure("b1")
    assert cb.allow_request("b1") is False
    t[0] = 29.0
    assert cb.allow_request("b1") is False
    t[0] = 30.0
    assert cb.allow_request("b1") is True  # transitions to half_open
    assert cb.state_for("b1").state == HALF_OPEN


def test_circuit_half_open_success_closes():
    t = [0.0]
    cb = make_breaker(threshold=2, recovery=30.0, clock=lambda: t[0])
    cb.record_failure("b1")
    cb.record_failure("b1")
    t[0] = 30.0
    cb.allow_request("b1")  # half_open trial
    cb.record_success("b1")
    assert cb.state_for("b1").state == CLOSED
    assert cb.state_for("b1").failure_count == 0


def test_circuit_half_open_failure_reopens():
    t = [0.0]
    cb = make_breaker(threshold=2, recovery=30.0, clock=lambda: t[0])
    cb.record_failure("b1")
    cb.record_failure("b1")
    t[0] = 30.0
    cb.allow_request("b1")  # half_open trial
    cb.record_failure("b1")
    assert cb.state_for("b1").state == OPEN
    assert cb.allow_request("b1") is False


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


def test_router_round_robin_distributes():
    backends = make_backends()
    config = GatewayConfig(backends=backends, strategy="round_robin", seed=11)
    states = make_states(backends)
    breaker = make_breaker(clock=lambda: 0.0)
    router = BackendRouter(config, states, breaker, clock=lambda: 0.0, rr_index=0)
    seq = [router.select().backend.backend_id for _ in range(6)]
    assert seq == ["b-det", "b-trk", "b-eng", "b-det", "b-trk", "b-eng"]


def test_router_round_robin_deterministic_same_seed():
    backends = make_backends()
    config = GatewayConfig(backends=backends, strategy="round_robin", seed=7)

    def build():
        states = make_states(backends)
        breaker = make_breaker(clock=lambda: 0.0)
        return BackendRouter(config, states, breaker, clock=lambda: 0.0, rr_index=0)

    seq1 = [build().select().backend.backend_id for _ in range(5)]
    seq2 = [build().select().backend.backend_id for _ in range(5)]
    assert seq1 == seq2


def test_router_least_latency_picks_minimum():
    backends = make_backends()
    states = make_states(backends)
    states["b-det"].last_latency_ms = 100.0
    states["b-trk"].last_latency_ms = 50.0
    states["b-eng"].last_latency_ms = 20.0
    config = GatewayConfig(backends=backends, strategy="least_latency", seed=11)
    breaker = make_breaker(clock=lambda: 0.0)
    router = BackendRouter(config, states, breaker, clock=lambda: 0.0)
    decision = router.select()
    assert decision.backend.backend_id == "b-eng"
    assert decision.reason == "least_latency"


def test_router_failover_picks_first_eligible():
    backends = make_backends()
    config = GatewayConfig(backends=backends, strategy="failover", seed=11)
    states = make_states(backends)
    breaker = make_breaker(clock=lambda: 0.0)
    router = BackendRouter(config, states, breaker, clock=lambda: 0.0)
    decision = router.select()
    assert decision.backend.backend_id == "b-det"
    assert decision.reason == "failover primary"


def test_router_excludes_unhealthy_backend():
    backends = make_backends()
    states = make_states(backends)
    states["b-det"].healthy = False
    config = GatewayConfig(backends=backends, strategy="round_robin", seed=11)
    breaker = make_breaker(clock=lambda: 0.0)
    router = BackendRouter(config, states, breaker, clock=lambda: 0.0, rr_index=0)
    decision = router.select()
    assert decision.backend.backend_id == "b-trk"
    assert decision.candidates == 2


def test_router_excludes_open_circuit_backend():
    backends = make_backends()
    states = make_states(backends)
    breaker = make_breaker(threshold=2, clock=lambda: 0.0)
    breaker.record_failure("b-det")
    breaker.record_failure("b-det")
    config = GatewayConfig(backends=backends, strategy="round_robin", seed=11)
    router = BackendRouter(config, states, breaker, clock=lambda: 0.0, rr_index=0)
    decision = router.select()
    assert decision.backend.backend_id == "b-trk"
    assert decision.candidates == 2


def test_router_no_eligible_backends():
    backends = make_backends()
    states = make_states(backends)
    for st in states.values():
        st.healthy = False
    config = GatewayConfig(backends=backends, strategy="round_robin", seed=11)
    breaker = make_breaker(clock=lambda: 0.0)
    router = BackendRouter(config, states, breaker, clock=lambda: 0.0)
    decision = router.select()
    assert decision.backend is None
    assert decision.candidates == 0
    assert decision.reason == "no eligible backends"


def test_router_record_success_and_failure():
    backends = make_backends()
    states = make_states(backends)
    breaker = make_breaker(clock=lambda: 0.0)
    config = GatewayConfig(backends=backends, strategy="round_robin", seed=11)
    router = BackendRouter(config, states, breaker, clock=lambda: 0.0)
    router.record_success("b-det", latency_ms=12.5)
    assert states["b-det"].last_latency_ms == 12.5
    assert states["b-det"].consecutive_failures == 0
    router.record_failure("b-trk")
    assert states["b-trk"].consecutive_failures == 1


# ---------------------------------------------------------------------------
# Health checker
# ---------------------------------------------------------------------------


def test_health_checker_marks_healthy_and_unhealthy():
    backends = make_backends()
    states = make_states(backends)

    def fake_probe(backend):
        healthy = backend.backend_id != "b-bad"
        return ProbeResult(backend.backend_id, healthy, 10.0, 1000.0, None)

    config = GatewayConfig(backends=backends, seed=11)
    checker = HealthChecker(config, states, probe=fake_probe, clock=lambda: 1000.0)
    results = checker.check_all()
    assert len(results) == 3
    by_id = {r.backend_id: r for r in results}
    assert by_id["b-det"].healthy is True
    assert by_id["b-det"].latency_ms == 10.0
    # mark unhealthy via dedicated probe
    bad = Backend(backend_id="b-bad", endpoint="http://bad", role="detection")
    res = checker.probe_backend(bad)
    assert res.healthy is False
    assert states["b-bad"].healthy is False
    assert states["b-det"].last_latency_ms == 10.0
    assert states["b-det"].last_probe_ts == 1000.0


def test_health_checker_is_due():
    backends = make_backends()
    states = make_states(backends)
    config = GatewayConfig(backends=backends, health_interval_s=10.0, seed=11)
    checker = HealthChecker(config, states, clock=lambda: 0.0)
    assert checker.is_due("b-det") is True  # never probed
    checker.probe_backend(backends[0])
    assert checker.is_due("b-det") is False  # just probed
    checker.clock = lambda: 10.0
    assert checker.is_due("b-det") is True  # interval elapsed


# ---------------------------------------------------------------------------
# Gateway facade
# ---------------------------------------------------------------------------


def test_gateway_status_shape(tmp_path):
    backends = make_backends()
    config = GatewayConfig(backends=backends, state_dir=str(tmp_path), seed=5)
    gw = Gateway(config=config, clock=_clock)
    status = gw.status()
    assert status["strategy"] == "round_robin"
    assert status["seed"] == 5
    assert len(status["backends"]) == 3
    first = status["backends"][0]
    assert first["backend_id"] == "b-det"
    assert first["circuit"] == "closed"
    assert first["failure_count"] == 0
    assert first["healthy"] is True


def test_gateway_route_forces_and_records(tmp_path):
    backends = make_backends()
    config = GatewayConfig(backends=backends, state_dir=str(tmp_path), seed=5)
    gw = Gateway(config=config, clock=_clock)
    decision = gw.route(role="detection")
    assert decision.backend.backend_id == "b-det"
    assert decision.candidates == 1
    gw.record_success("b-det", latency_ms=7.0)
    gw.record_failure("b-trk")
    assert gw.backend_states["b-det"].last_latency_ms == 7.0
    assert gw.backend_states["b-trk"].consecutive_failures == 1


def test_gateway_persist_and_reload_round_robin(tmp_path):
    backends = make_backends()
    config = GatewayConfig(
        backends=backends,
        state_dir=str(tmp_path),
        seed=5,
        strategy="round_robin",
    )
    gw = Gateway(config=config, clock=_clock)
    d1 = gw.route(role=None)  # rr index 0 -> b-det, persists rr_index=1
    d2 = gw.route(role=None)  # rr index 1 -> b-trk, persists rr_index=2
    gw.save()
    assert d1.backend.backend_id == "b-det"
    assert d2.backend.backend_id == "b-trk"
    # Reload: router resumes at persisted rr_index=2 -> b-eng
    gw2 = Gateway(config=config, clock=lambda: 0.0)
    d3 = gw2.route(role=None)
    assert d3.backend.backend_id == "b-eng"


def test_gateway_persist_config_on_init(tmp_path):
    backends = make_backends()
    config = GatewayConfig(backends=backends, state_dir=str(tmp_path), strategy="failover")
    Gateway(config=config, clock=lambda: 0.0)
    store = GatewayStateStore(str(tmp_path))
    loaded = store.load_config()
    assert loaded is not None
    assert loaded.strategy == "failover"
    assert len(loaded.backends) == 3


def test_gateway_probe_and_health(tmp_path):
    backends = make_backends()
    config = GatewayConfig(backends=backends, state_dir=str(tmp_path), seed=5)

    def fake_probe(backend):
        return ProbeResult(backend.backend_id, True, 5.0, 1234.0, None)

    gw = Gateway(config=config, clock=lambda: 1234.0)
    gw.health._probe = fake_probe
    result = gw.probe("b-det")
    assert result.backend_id == "b-det"
    assert result.healthy is True
    assert result.latency_ms == 5.0
    assert gw.is_healthy("b-det") is True


def test_cli_status_returns_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("C_UAS_GATEWAY_STATE_DIR", str(tmp_path))
    from c_uas.cli import main

    assert main(["gateway", "--status"]) == 0


def test_cli_route_returns_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("C_UAS_GATEWAY_STATE_DIR", str(tmp_path))
    from c_uas.cli import main

    assert main(["gateway", "--route", "--backend", "detection"]) == 0
