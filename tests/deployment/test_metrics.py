"""Deterministic tests for the Prometheus metrics endpoint."""

import re

from fastapi.testclient import TestClient

from c_uas.deployment.server import create_app

_COUNTER_RE = re.compile(
    r'http_requests_total\{method="GET",path="([^"]+)",status="([^"]+)"\} ([0-9.]+)'
)


def _counter_value(text: str, path: str, status: str) -> float:
    match = _COUNTER_RE.search(text)
    while match is not None:
        if match.group(1) == path and match.group(2) == status:
            return float(match.group(3))
        match = _COUNTER_RE.search(text, match.end())
    raise AssertionError(f"no counter for path={path!r} status={status!r} in:\n{text}")


def test_metrics_endpoint_shape():
    app = create_app()
    client = TestClient(app)
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    text = resp.text
    for name in (
        "http_requests_total",
        "http_errors_total",
        "http_active_connections",
        "http_request_duration_seconds",
    ):
        assert name in text, f"missing metric {name}"
    assert "# TYPE http_requests_total counter" in text
    assert "# TYPE http_request_duration_seconds histogram" in text
    assert "# TYPE http_active_connections gauge" in text


def test_metrics_counts_requests_and_errors():
    app = create_app()
    client = TestClient(app)
    client.get("/healthz")  # warm up the registry
    before = client.get("/metrics").text
    before_healthz = _counter_value(before, "/healthz", "200")

    client.get("/healthz")
    after = client.get("/metrics").text
    after_healthz = _counter_value(after, "/healthz", "200")
    assert after_healthz == before_healthz + 1

    assert 'http_request_duration_seconds_bucket{method="GET",path="/healthz",le=' in after
    assert "http_request_duration_seconds_sum" in after
