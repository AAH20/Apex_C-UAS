"""Deterministic tests for the C-UAS WebSocket real-time streaming module.

Covers MessageEnvelope framing, ConnectionRegistry, BroadcastEngine,
WebSocketManager, TrackEventStream, and the /ws FastAPI route.
"""

import asyncio

from fastapi.testclient import TestClient
from fastapi.websockets import WebSocketState

import c_uas.api.websockets as ws_mod
from c_uas.api.server import app
from c_uas.api.websockets import (
    DEFAULT_TIMESTAMP,
    MAX_CONNECTIONS,
    MessageEnvelope,
    TrackEventStream,
    WebSocketManager,
    make_alert,
    make_detection_event,
    make_engagement_scheduled,
    make_health_status,
    make_track_update,
    websocket_route,
)


class _FakeWebSocket:
    """Minimal WebSocket stand-in for registry/broadcast unit tests."""

    def __init__(self) -> None:
        self.application_state = WebSocketState.CONNECTED
        self.sent: list = []

    async def accept(self) -> None:
        return None

    async def send_text(self, data: str) -> None:
        self.sent.append(data)

    async def close(self) -> None:
        return None


def _fresh_manager(tmp_path, monkeypatch) -> WebSocketManager:
    """Build a WebSocketManager whose state lives under tmp_path."""
    monkeypatch.setattr(ws_mod, "WEBSOCKETS_DIR", tmp_path / "websockets")
    monkeypatch.setattr(
        ws_mod,
        "CONNECTIONS_FILE",
        tmp_path / "websockets" / "connections.json",
    )
    monkeypatch.setattr(
        ws_mod,
        "EVENTS_FILE",
        tmp_path / "websockets" / "events.json",
    )
    return WebSocketManager()


# --------------------------------------------------------------------------- #
# MessageEnvelope / factory helpers
# --------------------------------------------------------------------------- #


def test_envelope_deterministic_message_id():
    ts = DEFAULT_TIMESTAMP
    a = make_track_update("T1", 1.0, 2.0, 3.0, 10.0, 45.0, 0.9, timestamp=ts)
    b = make_track_update("T1", 1.0, 2.0, 3.0, 10.0, 45.0, 0.9, timestamp=ts)
    assert a.message_id == b.message_id
    assert a.message_id.startswith("msg-")
    assert len(a.message_id) == len("msg-") + 16


def test_envelope_json_round_trip():
    env = make_alert("A1", "HIGH", "test alert", "unit", timestamp=DEFAULT_TIMESTAMP)
    env2 = MessageEnvelope(**env.to_dict())
    assert env2.message_id == env.message_id
    assert env2.type == env.type
    assert env2.payload == env.payload
    assert env2.timestamp == env.timestamp
    assert env.to_json() == env2.to_json()


def test_track_update_envelope():
    env = make_track_update("T1", 10.0, 20.0, 30.0, 15.0, 90.0, 0.85, timestamp=DEFAULT_TIMESTAMP)
    assert env.type == "track_update"
    assert env.payload["track_id"] == "T1"
    assert env.payload["x"] == 10.0
    assert env.payload["confidence"] == 0.85
    assert env.timestamp == DEFAULT_TIMESTAMP


def test_detection_event_envelope():
    env = make_detection_event(
        "D1",
        "rf_classifier",
        "UAV-1",
        "CRITICAL",
        "DJI_OCUSYNC_4",
        0.94,
        latitude=34.05,
        longitude=-118.2,
        anomalies=["SPOOFED_BROADCAST_ID"],
        timestamp=DEFAULT_TIMESTAMP,
    )
    assert env.type == "detection_event"
    assert env.payload["threat_level"] == "CRITICAL"
    assert env.payload["anomalies"] == ["SPOOFED_BROADCAST_ID"]
    assert env.payload["latitude"] == 34.05


def test_detection_event_optional_fields_omitted():
    env = make_detection_event(
        "D2",
        "spoof",
        "UAV-2",
        "HIGH",
        "GPS_L1_CA",
        0.5,
        timestamp=DEFAULT_TIMESTAMP,
    )
    assert "latitude" not in env.payload
    assert "longitude" not in env.payload
    assert "anomalies" not in env.payload


def test_engagement_scheduled_envelope():
    env = make_engagement_scheduled("T1", 5.0, 9.0, 0.75, 3, timestamp=DEFAULT_TIMESTAMP)
    assert env.type == "engagement_scheduled"
    assert env.payload["pk_base"] == 0.75
    assert env.payload["priority"] == 3
    assert env.payload["engage_start_s"] == 5.0


def test_alert_envelope_with_and_without_target():
    env = make_alert(
        "A1",
        "CRITICAL",
        "rogue drone",
        "rf",
        target_id="UAV-1",
        timestamp=DEFAULT_TIMESTAMP,
    )
    assert env.type == "alert"
    assert env.payload["severity"] == "CRITICAL"
    assert env.payload["target_id"] == "UAV-1"

    env2 = make_alert("A2", "MEDIUM", "notice", "rf", timestamp=DEFAULT_TIMESTAMP)
    assert "target_id" not in env2.payload


def test_health_status_envelope():
    env = make_health_status("ok", {"api": "ok", "scheduler": "ok"}, timestamp=DEFAULT_TIMESTAMP)
    assert env.type == "health_status"
    assert env.payload["status"] == "ok"
    assert env.payload["checks"]["scheduler"] == "ok"


# --------------------------------------------------------------------------- #
# ConnectionRegistry
# --------------------------------------------------------------------------- #


def test_registry_connection_count_empty(tmp_path, monkeypatch):
    m = _fresh_manager(tmp_path, monkeypatch)
    assert asyncio.run(m.connection_count()) == 0


def test_registry_register_and_subscribe(tmp_path, monkeypatch):
    m = _fresh_manager(tmp_path, monkeypatch)

    async def _run() -> None:
        ws1 = _FakeWebSocket()
        sub1 = await m.registry.register("client-1", ws1)
        assert sub1.client_id == "client-1"
        assert await m.registry.connection_count() == 1

        assert await m.registry.subscribe("client-1", "tracks") is True
        assert await m.registry.subscribe("client-1", "detections") is True
        subs = await m.registry.get_subscriptions("client-1")
        assert subs == {"tracks", "detections"}

        # unknown client cannot subscribe
        assert await m.registry.subscribe("ghost", "tracks") is False

        # heartbeat refreshes
        assert await m.registry.heartbeat("client-1") is True
        assert await m.registry.heartbeat("ghost") is False

        await m.registry.unsubscribe("client-1", "tracks")
        subs = await m.registry.get_subscriptions("client-1")
        assert subs == {"detections"}

        await m.registry.disconnect if False else None
        await m.registry.unregister("client-1")
        assert await m.registry.connection_count() == 0

    asyncio.run(_run())


def test_registry_max_connections(tmp_path, monkeypatch):
    m = _fresh_manager(tmp_path, monkeypatch)

    async def _run() -> None:
        for i in range(MAX_CONNECTIONS):
            await m.registry.register(f"c{i}", _FakeWebSocket())
        try:
            await m.registry.register("overflow", _FakeWebSocket())
        except RuntimeError:
            return  # expected
        raise AssertionError("expected RuntimeError when over connection limit")

    asyncio.run(_run())


def test_registry_is_stale(tmp_path, monkeypatch):
    m = _fresh_manager(tmp_path, monkeypatch)

    async def _run() -> None:
        await m.registry.register("c1", _FakeWebSocket())
        assert await m.registry.is_stale("c1", 30.0) is False  # just connected
        assert await m.registry.is_stale("ghost", 30.0) is True  # unknown -> stale

    asyncio.run(_run())


# --------------------------------------------------------------------------- #
# BroadcastEngine
# --------------------------------------------------------------------------- #


def test_broadcast_delivers_to_subscribed_clients_only(tmp_path, monkeypatch):
    m = _fresh_manager(tmp_path, monkeypatch)

    async def _run() -> None:
        ws1, ws2, ws3 = _FakeWebSocket(), _FakeWebSocket(), _FakeWebSocket()
        await m.registry.register("c1", ws1)
        await m.registry.register("c2", ws2)
        await m.registry.register("c3", ws3)
        await m.registry.subscribe("c1", "tracks")
        await m.registry.subscribe("c2", "tracks")
        # c3 subscribes to detections only -> should NOT receive track updates
        await m.registry.subscribe("c3", "detections")

        from c_uas.api.websockets import make_track_update

        env = make_track_update("T1", 1.0, 2.0, 3.0, 10.0, 45.0, 0.9)

        results = await m.broadcast_engine.broadcast(env, topic="tracks")
        assert results["c1"] is True
        assert results["c2"] is True
        assert "c3" not in results  # not subscribed, not enqueued

        # dequeue: c1 and c2 have the envelope; c3 has none
        got1 = await m.broadcast_engine.dequeue("c1")
        got2 = await m.broadcast_engine.dequeue("c2")
        assert got1.message_id == env.message_id
        assert got2.message_id == env.message_id

    asyncio.run(_run())


def test_broadcast_backpressure_queue_full(tmp_path, monkeypatch):
    m = _fresh_manager(tmp_path, monkeypatch)

    async def _run() -> None:
        await m.registry.register("c1", _FakeWebSocket())
        await m.registry.subscribe("c1", "tracks")
        # fill the queue (maxsize 1000)
        for _ in range(1000):
            assert (
                await m.broadcast_engine.enqueue("c1", make_track_update("T", 0, 0, 0, 0, 0, 0))
                is True
            )
        # now full
        assert (
            await m.broadcast_engine.enqueue("c1", make_track_update("T", 0, 0, 0, 0, 0, 0))
            is False
        )

    asyncio.run(_run())


# --------------------------------------------------------------------------- #
# WebSocketManager publish + persistence
# --------------------------------------------------------------------------- #


def test_manager_publish_persists_to_history(tmp_path, monkeypatch):
    m = _fresh_manager(tmp_path, monkeypatch)
    env = m.publish_track_update("T1", 1.0, 2.0, 3.0, 10.0, 45.0, 0.9)
    history = m.get_event_history()
    assert len(history) == 1
    assert history[0].message_id == env.message_id
    assert history[0].type == "track_update"


def test_manager_publish_all_event_types(tmp_path, monkeypatch):
    m = _fresh_manager(tmp_path, monkeypatch)
    m.publish_track_update("T1", 1.0, 2.0, 3.0, 10.0, 45.0, 0.9)
    m.publish_detection_event("D1", "rf", "UAV-1", "HIGH", "DJI_OCUSYNC_4", 0.9)
    m.publish_engagement_scheduled("T1", 5.0, 9.0, 0.75, 3)
    m.publish_alert("A1", "HIGH", "notice", "rf")
    m.publish_health_status("ok", {"api": "ok"})
    history = m.get_event_history()
    assert [e.type for e in history] == [
        "track_update",
        "detection_event",
        "engagement_scheduled",
        "alert",
        "health_status",
    ]


def test_manager_publish_is_deterministic(tmp_path, monkeypatch):
    monkeypatch.setattr(ws_mod, "_now", lambda: DEFAULT_TIMESTAMP)
    m = _fresh_manager(tmp_path, monkeypatch)
    e1 = m.publish_track_update("T1", 1.0, 2.0, 3.0, 10.0, 45.0, 0.9)
    m2 = _fresh_manager(tmp_path, monkeypatch)
    e2 = m2.publish_track_update("T1", 1.0, 2.0, 3.0, 10.0, 45.0, 0.9)
    assert e1.message_id == e2.message_id
    assert e1.timestamp == DEFAULT_TIMESTAMP


# --------------------------------------------------------------------------- #
# TrackEventStream
# --------------------------------------------------------------------------- #


def test_track_event_stream_emit_methods(tmp_path, monkeypatch):
    m = _fresh_manager(tmp_path, monkeypatch)
    stream = TrackEventStream(manager=m)
    te = stream.emit_track("T1", 1.0, 2.0, 3.0, 10.0, 45.0, 0.9)
    assert te.type == "track_update"

    de = stream.emit_detection("D1", "rf", "UAV-1", "CRITICAL", "DJI_OCUSYNC_4", 0.94)
    assert de.type == "detection_event"

    ee = stream.emit_engagement("T1", 5.0, 9.0, 0.75, 3)
    assert ee.type == "engagement_scheduled"

    ae = stream.emit_alert("A1", "HIGH", "notice", "rf")
    assert ae.type == "alert"

    history = stream.history()
    assert [e.type for e in history] == [
        "track_update",
        "detection_event",
        "engagement_scheduled",
        "alert",
    ]


# --------------------------------------------------------------------------- #
# FastAPI /ws route
# --------------------------------------------------------------------------- #


def test_ws_route_is_mounted():
    paths = [getattr(r, "path", "") for r in app.routes]
    assert "/ws" in paths


def test_ws_connect_subscribe_and_ack():
    client = TestClient(app)
    with client.websocket_connect("/ws") as ws:
        # connection ack arrives immediately
        ack = ws.receive_json()
        assert ack["type"] == "subscription_ack"
        assert "client_id" in ack

        # subscribe to tracks + detections
        ws.send_json({"action": "subscribe", "topics": ["tracks", "detections"]})
        ack2 = ws.receive_json()
        assert ack2["type"] == "subscription_ack"
        assert set(ack2["payload"]["topics"]) == {"tracks", "detections"}

        # heartbeat round-trip
        ws.send_json({"action": "heartbeat"})
        hb = ws.receive_json()
        assert hb["type"] == "health_status"
        assert hb["payload"]["status"] == "ok"


def test_ws_unknown_action_returns_error():
    client = TestClient(app)
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()  # consume subscription_ack
        ws.send_json({"action": "bogus"})
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["payload"]["error"] == "unknown_action"


def test_websocket_route_callable():
    import asyncio

    async def _run() -> None:
        # the route factory returns a coroutine function
        assert asyncio.iscoroutinefunction(websocket_route)

    asyncio.run(_run())
