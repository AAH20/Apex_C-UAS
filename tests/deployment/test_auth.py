"""Deterministic tests for API key authentication and per-client rate limiting."""

from fastapi.testclient import TestClient

import c_uas.deployment.config as config_module
from c_uas.deployment.server import create_app


def _app_with_keys(monkeypatch, keys):
    monkeypatch.setenv("CUAS_API_KEYS", ",".join(keys))
    return create_app()


def test_auth_missing_key_rejected(monkeypatch):
    app = _app_with_keys(monkeypatch, ["prod-key-0001"])
    client = TestClient(app)
    resp = client.get("/healthz")
    # /healthz is public even with auth enabled
    assert resp.status_code == 200
    resp = client.get("/systems")
    assert resp.status_code == 401
    assert resp.json() == {"detail": "unauthorized"}


def test_auth_valid_key_accepted(monkeypatch):
    app = _app_with_keys(monkeypatch, ["prod-key-0001"])
    client = TestClient(app)
    resp = client.get("/systems", headers={"X-API-Key": "prod-key-0001"})
    assert resp.status_code == 200


def test_auth_invalid_key_rejected(monkeypatch):
    app = _app_with_keys(monkeypatch, ["prod-key-0001"])
    client = TestClient(app)
    resp = client.get("/systems", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401


def test_auth_pass_through_when_no_keys(monkeypatch):
    monkeypatch.setattr(config_module, "load_api_keys", lambda: ())
    app = create_app()
    client = TestClient(app)
    resp = client.get("/systems")
    assert resp.status_code == 200


def test_rate_limit_blocks_excess_requests(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("time.monotonic", lambda: now[0])
    app = _app_with_keys(monkeypatch, ["rl-key"])
    client = TestClient(app)
    headers = {"X-API-Key": "rl-key"}
    # burst = 20, no time passes, so the first 20 requests are allowed
    for _ in range(20):
        assert client.get("/systems", headers=headers).status_code == 200
    resp = client.get("/systems", headers=headers)
    assert resp.status_code == 429
    assert resp.json() == {"detail": "rate limited"}
    assert resp.headers["retry-after"] == "1"


def test_rate_limit_refills_with_time(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("time.monotonic", lambda: now[0])
    app = _app_with_keys(monkeypatch, ["rl-key-2"])
    client = TestClient(app)
    headers = {"X-API-Key": "rl-key-2"}
    for _ in range(20):
        assert client.get("/systems", headers=headers).status_code == 200
    assert client.get("/systems", headers=headers).status_code == 429
    # 1 second later at 10 rps: 10 tokens refill -> 10 more requests allowed
    now[0] += 1.0
    for _ in range(10):
        assert client.get("/systems", headers=headers).status_code == 200
    assert client.get("/systems", headers=headers).status_code == 429


def test_rate_limit_is_per_client(monkeypatch):
    now = [0.0]
    monkeypatch.setattr("time.monotonic", lambda: now[0])
    app = _app_with_keys(monkeypatch, ["key-a", "key-b"])
    client = TestClient(app)
    for _ in range(20):
        assert client.get("/systems", headers={"X-API-Key": "key-a"}).status_code == 200
    assert client.get("/systems", headers={"X-API-Key": "key-a"}).status_code == 429
    # key-b has its own bucket and is unaffected
    assert client.get("/systems", headers={"X-API-Key": "key-b"}).status_code == 200
