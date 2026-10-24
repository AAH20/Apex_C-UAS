"""WebSocket real-time streaming for the C-UAS platform dashboard.

Provides live track updates, detection events, engagement schedules, alerts,
and health status to subscribed dashboard clients over a single WebSocket
connection per client.

Components
----------
- MessageEnvelope : typed WebSocket message framing (track_update,
  detection_event, engagement_scheduled, alert, health_status)
- ConnectionRegistry : track active connections, client subscriptions,
  heartbeat monitoring
- WebSocketManager : subscribe/unsubscribe/broadcast/connection lifecycle
- TrackEventStream : stream detection events, tracking updates, engagement
  schedules to subscribed clients
- BroadcastEngine : fan-out events to all subscribed connections with
  backpressure handling

All state is persisted to ~/.c-uas-platform/websockets/ (outside the repo)
for connection history. Deterministic: fixed message IDs, reproducible event
ordering.

Defensive only: live streaming of detection/tracking/engagement telemetry.
No weapons-employment effector, no live SDR integration.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState

# Persistent storage outside the repo — connection history survives repo rebuilds.
WEBSOCKETS_DIR = Path.home() / ".c-uas-platform" / "websockets"
CONNECTIONS_FILE = WEBSOCKETS_DIR / "connections.json"
EVENTS_FILE = WEBSOCKETS_DIR / "events.json"

DEFAULT_HEARTBEAT_INTERVAL_S = 30.0
MAX_CONNECTIONS = 1024
MAX_EVENT_HISTORY = 10_000

MESSAGE_TYPE_TRACK_UPDATE = "track_update"
MESSAGE_TYPE_DETECTION_EVENT = "detection_event"
MESSAGE_TYPE_ENGAGEMENT_SCHEDULED = "engagement_scheduled"
MESSAGE_TYPE_ALERT = "alert"
MESSAGE_TYPE_HEALTH_STATUS = "health_status"
MESSAGE_TYPE_SUBSCRIPTION_ACK = "subscription_ack"
MESSAGE_TYPE_ERROR = "error"

SUBSCRIPTION_TRACKS = "tracks"
SUBSCRIPTION_DETECTIONS = "detections"
SUBSCRIPTION_ENGAGEMENTS = "engagements"
SUBSCRIPTION_ALERTS = "alerts"
SUBSCRIPTION_HEALTH = "health"


class MessageType(str, Enum):
    TRACK_UPDATE = MESSAGE_TYPE_TRACK_UPDATE
    DETECTION_EVENT = MESSAGE_TYPE_DETECTION_EVENT
    ENGAGEMENT_SCHEDULED = MESSAGE_TYPE_ENGAGEMENT_SCHEDULED
    ALERT = MESSAGE_TYPE_ALERT
    HEALTH_STATUS = MESSAGE_TYPE_HEALTH_STATUS
    SUBSCRIPTION_ACK = MESSAGE_TYPE_SUBSCRIPTION_ACK
    ERROR = MESSAGE_TYPE_ERROR


@dataclass(frozen=True)
class MessageEnvelope:
    """Typed WebSocket message envelope.

    message_id is fixed per message for deterministic replay and deduplication.
    timestamp is a deterministic float so the same input yields the same envelope.
    """

    message_id: str
    type: str
    timestamp: float
    payload: Dict[str, Any]
    client_id: Optional[str] = None
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _now() -> float:
    return time.time()


def _message_id(message_type: str, payload: Dict[str, Any], timestamp: float) -> str:
    """Deterministic message ID: sha256(type + canonical payload + timestamp)."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    data = f"{message_type}|{canonical}|{timestamp}"
    return f"msg-{hashlib.sha256(data.encode('utf-8')).hexdigest()[:16]}"


def make_envelope(
    message_type: str,
    payload: Dict[str, Any],
    timestamp: Optional[float] = None,
    client_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> MessageEnvelope:
    """Build a deterministic MessageEnvelope."""
    if timestamp is None:
        timestamp = _now()
    return MessageEnvelope(
        message_id=_message_id(message_type, payload, timestamp),
        type=message_type,
        timestamp=timestamp,
        payload=payload,
        client_id=client_id,
        correlation_id=correlation_id,
    )


def make_track_update(
    track_id: str,
    x: float,
    y: float,
    z: float,
    speed_mps: float,
    heading_deg: float,
    confidence: float,
    timestamp: Optional[float] = None,
    client_id: Optional[str] = None,
) -> MessageEnvelope:
    payload = {
        "track_id": track_id,
        "x": x,
        "y": y,
        "z": z,
        "speed_mps": speed_mps,
        "heading_deg": heading_deg,
        "confidence": confidence,
    }
    return make_envelope(MESSAGE_TYPE_TRACK_UPDATE, payload, timestamp, client_id)


def make_detection_event(
    event_id: str,
    source: str,
    target_id: str,
    threat_level: str,
    protocol: str,
    confidence: float,
    latitude: Optional[float] = None,
    longitude: Optional[float] = None,
    anomalies: Optional[List[str]] = None,
    timestamp: Optional[float] = None,
    client_id: Optional[str] = None,
) -> MessageEnvelope:
    payload: Dict[str, Any] = {
        "event_id": event_id,
        "source": source,
        "target_id": target_id,
        "threat_level": threat_level,
        "protocol": protocol,
        "confidence": confidence,
    }
    if latitude is not None:
        payload["latitude"] = latitude
    if longitude is not None:
        payload["longitude"] = longitude
    if anomalies:
        payload["anomalies"] = anomalies
    return make_envelope(MESSAGE_TYPE_DETECTION_EVENT, payload, timestamp, client_id)


def make_engagement_scheduled(
    track_id: str,
    engage_start_s: float,
    engage_end_s: float,
    pk_base: float,
    priority: int,
    timestamp: Optional[float] = None,
    client_id: Optional[str] = None,
) -> MessageEnvelope:
    payload = {
        "track_id": track_id,
        "engage_start_s": engage_start_s,
        "engage_end_s": engage_end_s,
        "pk_base": pk_base,
        "priority": priority,
    }
    return make_envelope(MESSAGE_TYPE_ENGAGEMENT_SCHEDULED, payload, timestamp, client_id)


def make_alert(
    alert_id: str,
    severity: str,
    message: str,
    source: str,
    target_id: Optional[str] = None,
    timestamp: Optional[float] = None,
    client_id: Optional[str] = None,
) -> MessageEnvelope:
    payload: Dict[str, Any] = {
        "alert_id": alert_id,
        "severity": severity,
        "message": message,
        "source": source,
    }
    if target_id is not None:
        payload["target_id"] = target_id
    return make_envelope(MESSAGE_TYPE_ALERT, payload, timestamp, client_id)


def make_health_status(
    status: str,
    checks: Dict[str, str],
    timestamp: Optional[float] = None,
    client_id: Optional[str] = None,
) -> MessageEnvelope:
    payload = {"status": status, "checks": checks}
    return make_envelope(MESSAGE_TYPE_HEALTH_STATUS, payload, timestamp, client_id)


@dataclass(frozen=True)
class ClientSubscription:
    client_id: str
    subscriptions: Set[str] = field(default_factory=set)
    connected_at: float = field(default_factory=_now)
    last_heartbeat: float = field(default_factory=_now)
    messages_sent: int = 0


@dataclass(frozen=True)
class ConnectionRecord:
    client_id: str
    connected_at: float
    disconnected_at: Optional[float]
    subscriptions: List[str]
    messages_sent: int
    messages_received: int


def _ensure_dir() -> None:
    WEBSOCKETS_DIR.mkdir(parents=True, exist_ok=True)


def _load_json(path: Path) -> list:
    _ensure_dir()
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save_json(path: Path, data: list) -> None:
    _ensure_dir()
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


class ConnectionRegistry:
    """Track active WebSocket connections, client subscriptions, heartbeat."""

    def __init__(self) -> None:
        self._connections: Dict[str, ClientSubscription] = {}
        self._websockets: Dict[str, WebSocket] = {}
        # Lock created lazily on first async use so it binds to the running
        # event loop (Python 3.9 binds asyncio.Lock() to the loop at creation).
        self._lock: Optional[asyncio.Lock] = None
        self._history: List[ConnectionRecord] = []
        for row in _load_json(CONNECTIONS_FILE):
            if isinstance(row, dict):
                self._history.append(
                    ConnectionRecord(
                        client_id=str(row["client_id"]),
                        connected_at=float(row["connected_at"]),
                        disconnected_at=(
                            float(row["disconnected_at"])
                            if row.get("disconnected_at") is not None
                            else None
                        ),
                        subscriptions=list(row.get("subscriptions", [])),
                        messages_sent=int(row.get("messages_sent", 0)),
                        messages_received=int(row.get("messages_received", 0)),
                    )
                )

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def register(self, client_id: str, websocket: WebSocket) -> ClientSubscription:
        """Register a new connection. Returns the subscription record."""
        async with self._get_lock():
            if len(self._connections) >= MAX_CONNECTIONS:
                raise RuntimeError("maximum connection limit reached")
            if client_id in self._connections:
                # Reuse existing client id but update the websocket reference.
                existing = self._connections[client_id]
                subscription = ClientSubscription(
                    client_id=client_id,
                    subscriptions=set(existing.subscriptions),
                    connected_at=_now(),
                    last_heartbeat=_now(),
                    messages_sent=existing.messages_sent,
                )
            else:
                subscription = ClientSubscription(client_id=client_id)
            self._connections[client_id] = subscription
            self._websockets[client_id] = websocket
            return subscription

    async def unregister(self, client_id: str) -> Optional[ClientSubscription]:
        """Remove a connection and record it in history."""
        async with self._get_lock():
            subscription = self._connections.pop(client_id, None)
            self._websockets.pop(client_id, None)
            if subscription is None:
                return None
            record = ConnectionRecord(
                client_id=client_id,
                connected_at=subscription.connected_at,
                disconnected_at=_now(),
                subscriptions=sorted(subscription.subscriptions),
                messages_sent=subscription.messages_sent,
                messages_received=0,
            )
            self._history.append(record)
            _save_json(
                CONNECTIONS_FILE,
                [asdict(r) for r in self._history],
            )
            return subscription

    async def subscribe(self, client_id: str, topic: str) -> bool:
        """Add a topic subscription for a client."""
        async with self._get_lock():
            subscription = self._connections.get(client_id)
            if subscription is None:
                return False
            new_subs = set(subscription.subscriptions)
            new_subs.add(topic)
            self._connections[client_id] = ClientSubscription(
                client_id=client_id,
                subscriptions=new_subs,
                connected_at=subscription.connected_at,
                last_heartbeat=_now(),
                messages_sent=subscription.messages_sent,
            )
            return True

    async def unsubscribe(self, client_id: str, topic: str) -> bool:
        """Remove a topic subscription for a client."""
        async with self._get_lock():
            subscription = self._connections.get(client_id)
            if subscription is None:
                return False
            new_subs = set(subscription.subscriptions)
            new_subs.discard(topic)
            self._connections[client_id] = ClientSubscription(
                client_id=client_id,
                subscriptions=new_subs,
                connected_at=subscription.connected_at,
                last_heartbeat=_now(),
                messages_sent=subscription.messages_sent,
            )
            return True

    async def heartbeat(self, client_id: str) -> bool:
        """Refresh the last_heartbeat for a client. Returns False if unknown."""
        async with self._get_lock():
            subscription = self._connections.get(client_id)
            if subscription is None:
                return False
            self._connections[client_id] = ClientSubscription(
                client_id=client_id,
                subscriptions=set(subscription.subscriptions),
                connected_at=subscription.connected_at,
                last_heartbeat=_now(),
                messages_sent=subscription.messages_sent,
            )
            return True

    async def increment_messages_sent(self, client_id: str) -> None:
        async with self._get_lock():
            subscription = self._connections.get(client_id)
            if subscription is None:
                return
            self._connections[client_id] = ClientSubscription(
                client_id=client_id,
                subscriptions=set(subscription.subscriptions),
                connected_at=subscription.connected_at,
                last_heartbeat=subscription.last_heartbeat,
                messages_sent=subscription.messages_sent + 1,
            )

    async def get_subscriptions(self, client_id: str) -> Set[str]:
        async with self._get_lock():
            subscription = self._connections.get(client_id)
            if subscription is None:
                return set()
            return set(subscription.subscriptions)

    async def get_websocket(self, client_id: str) -> Optional[WebSocket]:
        async with self._get_lock():
            return self._websockets.get(client_id)

    async def list_connections(self) -> List[ClientSubscription]:
        async with self._get_lock():
            return list(self._connections.values())

    async def connection_count(self) -> int:
        async with self._get_lock():
            return len(self._connections)

    async def is_stale(self, client_id: str, interval: float) -> bool:
        async with self._get_lock():
            subscription = self._connections.get(client_id)
            if subscription is None:
                return True
            return (_now() - subscription.last_heartbeat) > interval

    def list_history(self) -> List[ConnectionRecord]:
        return list(self._history)


class BroadcastEngine:
    """Fan-out events to all subscribed connections with backpressure."""

    def __init__(self, registry: ConnectionRegistry) -> None:
        self._registry = registry
        self._queues: Dict[str, asyncio.Queue[Optional[MessageEnvelope]]] = {}
        # Lock created lazily on first async use so it binds to the running
        # event loop (Python 3.9 binds asyncio.Lock() to the loop at creation).
        self._lock: Optional[asyncio.Lock] = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    # ---- internal queue management ----
    async def _ensure_queue(self, client_id: str) -> asyncio.Queue[Optional[MessageEnvelope]]:
        async with self._get_lock():
            queue = self._queues.get(client_id)
            if queue is None:
                queue = asyncio.Queue(maxsize=1000)
                self._queues[client_id] = queue
            return queue

    async def _remove_queue(self, client_id: str) -> None:
        async with self._get_lock():
            self._queues.pop(client_id, None)

    async def enqueue(self, client_id: str, envelope: MessageEnvelope) -> bool:
        """Enqueue an envelope for a client. Returns False if queue full (backpressure)."""
        queue = await self._ensure_queue(client_id)
        try:
            queue.put_nowait(envelope)
            return True
        except asyncio.QueueFull:
            return False

    async def dequeue(self, client_id: str) -> Optional[MessageEnvelope]:
        """Dequeue the next envelope for a client, or None if the queue is closed."""
        queue = await self._ensure_queue(client_id)
        envelope = await queue.get()
        return envelope

    async def close_queue(self, client_id: str) -> None:
        """Signal a client queue to close (sentinel None)."""
        queue = await self._ensure_queue(client_id)
        try:
            queue.put_nowait(None)  # type: ignore[arg-type]
        except asyncio.QueueFull:
            pass
        await self._remove_queue(client_id)

    async def broadcast(
        self, envelope: MessageEnvelope, topic: Optional[str] = None
    ) -> Dict[str, bool]:
        """Broadcast an envelope to all matching connections.

        If topic is None, send to all connections. Otherwise only to connections
        subscribed to the topic. Returns a map of client_id -> delivered.
        """
        connections = await self._registry.list_connections()
        results: Dict[str, bool] = {}
        for sub in connections:
            if topic is not None and topic not in sub.subscriptions:
                continue
            ok = await self.enqueue(sub.client_id, envelope)
            results[sub.client_id] = ok
        return results


class WebSocketManager:
    """Manage WebSocket connections: subscribe/unsubscribe, broadcast, lifecycle."""

    def __init__(self) -> None:
        self._registry = ConnectionRegistry()
        self._broadcast = BroadcastEngine(self._registry)
        self._tasks: Dict[str, asyncio.Task[None]] = {}
        self._handlers: Dict[str, Callable[[MessageEnvelope], None]] = {}
        self._event_history: List[MessageEnvelope] = []
        for row in _load_json(EVENTS_FILE):
            if isinstance(row, dict):
                self._event_history.append(
                    MessageEnvelope(
                        message_id=str(row["message_id"]),
                        type=str(row["type"]),
                        timestamp=float(row["timestamp"]),
                        payload=dict(row.get("payload", {})),
                        client_id=row.get("client_id"),
                        correlation_id=row.get("correlation_id"),
                    )
                )

    # -- registry accessors -------------------------------------------------
    @property
    def registry(self) -> ConnectionRegistry:
        return self._registry

    @property
    def broadcast_engine(self) -> BroadcastEngine:
        return self._broadcast

    async def connection_count(self) -> int:
        return await self._registry.connection_count()

    async def list_connections(self) -> List[ClientSubscription]:
        return await self._registry.list_connections()

    # -- event stream persistence ------------------------------------------
    def _persist_event(self, envelope: MessageEnvelope) -> None:
        self._event_history.append(envelope)
        if len(self._event_history) > MAX_EVENT_HISTORY:
            self._event_history = self._event_history[-MAX_EVENT_HISTORY:]
        _save_json(EVENTS_FILE, [e.to_dict() for e in self._event_history])

    def get_event_history(self) -> List[MessageEnvelope]:
        return list(self._event_history)

    def _schedule_broadcast(self, envelope: MessageEnvelope, topic: Optional[str]) -> None:
        """Schedule a broadcast if an event loop is running; otherwise skip.

        The event is always persisted deterministically. Broadcast only happens
        when the manager is running inside an event loop (e.g. via the FastAPI
        route or an async test).
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no running loop — broadcast deferred until the manager runs
        loop.create_task(self._broadcast.broadcast(envelope, topic=topic))

    # -- publish helpers ----------------------------------------------------
    def publish_track_update(
        self,
        track_id: str,
        x: float,
        y: float,
        z: float,
        speed_mps: float,
        heading_deg: float,
        confidence: float,
        client_id: Optional[str] = None,
    ) -> MessageEnvelope:
        envelope = make_track_update(
            track_id,
            x,
            y,
            z,
            speed_mps,
            heading_deg,
            confidence,
            client_id=client_id,
        )
        self._persist_event(envelope)
        self._schedule_broadcast(envelope, topic=SUBSCRIPTION_TRACKS)
        return envelope

    def publish_detection_event(
        self,
        event_id: str,
        source: str,
        target_id: str,
        threat_level: str,
        protocol: str,
        confidence: float,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        anomalies: Optional[List[str]] = None,
        client_id: Optional[str] = None,
    ) -> MessageEnvelope:
        envelope = make_detection_event(
            event_id,
            source,
            target_id,
            threat_level,
            protocol,
            confidence,
            latitude=latitude,
            longitude=longitude,
            anomalies=anomalies,
            client_id=client_id,
        )
        self._persist_event(envelope)
        self._schedule_broadcast(envelope, topic=SUBSCRIPTION_DETECTIONS)
        return envelope

    def publish_engagement_scheduled(
        self,
        track_id: str,
        engage_start_s: float,
        engage_end_s: float,
        pk_base: float,
        priority: int,
        client_id: Optional[str] = None,
    ) -> MessageEnvelope:
        envelope = make_engagement_scheduled(
            track_id,
            engage_start_s,
            engage_end_s,
            pk_base,
            priority,
            client_id=client_id,
        )
        self._persist_event(envelope)
        self._schedule_broadcast(envelope, topic=SUBSCRIPTION_ENGAGEMENTS)
        return envelope

    def publish_alert(
        self,
        alert_id: str,
        severity: str,
        message: str,
        source: str,
        target_id: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> MessageEnvelope:
        envelope = make_alert(
            alert_id,
            severity,
            message,
            source,
            target_id=target_id,
            client_id=client_id,
        )
        self._persist_event(envelope)
        self._schedule_broadcast(envelope, topic=SUBSCRIPTION_ALERTS)
        return envelope

    def publish_health_status(
        self,
        status: str,
        checks: Dict[str, str],
        client_id: Optional[str] = None,
    ) -> MessageEnvelope:
        envelope = make_health_status(status, checks, client_id=client_id)
        self._persist_event(envelope)
        self._schedule_broadcast(envelope, topic=SUBSCRIPTION_HEALTH)
        return envelope

    # -- connection lifecycle ----------------------------------------------
    async def connect(self, websocket: WebSocket, client_id: Optional[str] = None) -> str:
        """Accept a WebSocket and register the client."""
        if client_id is None:
            client_id = f"client-{uuid.uuid4().hex[:8]}"
        await websocket.accept()
        await self._registry.register(client_id, websocket)
        # Start the send pump for this client.
        task = asyncio.create_task(self._send_pump(client_id))
        self._tasks[client_id] = task
        # Send a subscription ack so the client knows the connection is live.
        ack = make_envelope(
            MESSAGE_TYPE_SUBSCRIPTION_ACK,
            {"client_id": client_id, "topics": []},
            client_id=client_id,
        )
        await self._safe_send(client_id, ack)
        return client_id

    async def disconnect(self, client_id: str) -> None:
        """Close a client connection and clean up."""
        task = self._tasks.pop(client_id, None)
        if task is not None:
            task.cancel()
        await self._registry.unregister(client_id)
        await self._broadcast.close_queue(client_id)
        websocket = await self._registry.get_websocket(client_id)
        if websocket is not None:
            try:
                if websocket.application_state == WebSocketState.CONNECTED:
                    await websocket.close()
            except Exception:  # noqa: BLE001 — best effort close
                pass

    async def handle(self, websocket: WebSocket, client_id: Optional[str] = None) -> None:
        """Handle a WebSocket connection end-to-end (FastAPI route entry point)."""
        actual_client_id = await self.connect(websocket, client_id)
        try:
            while True:
                raw = await websocket.receive_text()
                await self._on_client_message(actual_client_id, raw)
        except WebSocketDisconnect:
            pass
        finally:
            await self.disconnect(actual_client_id)

    # -- message handling ---------------------------------------------------
    async def _on_client_message(self, client_id: str, raw: str) -> None:
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            await self._safe_send(
                client_id,
                make_envelope(
                    MESSAGE_TYPE_ERROR,
                    {"error": "invalid_json", "detail": "message body must be JSON"},
                    client_id=client_id,
                ),
            )
            return
        if not isinstance(message, dict):
            await self._safe_send(
                client_id,
                make_envelope(
                    MESSAGE_TYPE_ERROR,
                    {"error": "invalid_message", "detail": "message must be a JSON object"},
                    client_id=client_id,
                ),
            )
            return
        action = str(message.get("action", "")).lower()
        if action == "subscribe":
            topics = message.get("topics", [])
            if isinstance(topics, list):
                for topic in topics:
                    await self._registry.subscribe(client_id, str(topic))
            ack = make_envelope(
                MESSAGE_TYPE_SUBSCRIPTION_ACK,
                {
                    "client_id": client_id,
                    "topics": sorted(await self._registry.get_subscriptions(client_id)),
                },
                client_id=client_id,
                correlation_id=message.get("correlation_id"),
            )
            await self._safe_send(client_id, ack)
        elif action == "unsubscribe":
            topics = message.get("topics", [])
            if isinstance(topics, list):
                for topic in topics:
                    await self._registry.unsubscribe(client_id, str(topic))
            ack = make_envelope(
                MESSAGE_TYPE_SUBSCRIPTION_ACK,
                {
                    "client_id": client_id,
                    "topics": sorted(await self._registry.get_subscriptions(client_id)),
                },
                client_id=client_id,
                correlation_id=message.get("correlation_id"),
            )
            await self._safe_send(client_id, ack)
        elif action == "heartbeat":
            await self._registry.heartbeat(client_id)
            await self._safe_send(
                client_id,
                make_envelope(
                    MESSAGE_TYPE_HEALTH_STATUS,
                    {"status": "ok", "client_id": client_id},
                    client_id=client_id,
                    correlation_id=message.get("correlation_id"),
                ),
            )
        elif action == "status":
            await self._safe_send(
                client_id,
                make_envelope(
                    MESSAGE_TYPE_HEALTH_STATUS,
                    {
                        "status": "ok",
                        "client_id": client_id,
                        "topics": sorted(await self._registry.get_subscriptions(client_id)),
                    },
                    client_id=client_id,
                ),
            )
        else:
            await self._safe_send(
                client_id,
                make_envelope(
                    MESSAGE_TYPE_ERROR,
                    {"error": "unknown_action", "action": action},
                    client_id=client_id,
                ),
            )

    # -- send pump ----------------------------------------------------------
    async def _send_pump(self, client_id: str) -> None:
        """Continuously dequeue envelopes and send them to one client."""
        while True:
            envelope = await self._broadcast.dequeue(client_id)
            if envelope is None:
                return  # closed
            await self._safe_send(client_id, envelope)
            await self._registry.increment_messages_sent(client_id)

    async def _safe_send(self, client_id: str, envelope: MessageEnvelope) -> bool:
        websocket = await self._registry.get_websocket(client_id)
        if websocket is None:
            return False
        try:
            await websocket.send_text(envelope.to_json())
            return True
        except Exception:  # noqa: BLE001 — send failures are handled by disconnect
            return False

    # -- FastAPI route factory ----------------------------------------------
    def route(self):
        """Return an async route handler for FastAPI `app.websocket(...)`.

        The returned coroutine accepts a WebSocket and an optional client_id
        and runs the full connection lifecycle (connect, message loop, disconnect).
        """

        async def _handler(websocket: WebSocket, client_id: Optional[str] = None) -> None:
            await self.handle(websocket, client_id)

        return _handler


# --------------------------------------------------------------------------- #
# Module-level default manager — the single source of truth for the API.
# --------------------------------------------------------------------------- #
manager = WebSocketManager()
websocket_route = manager.route()


class TrackEventStream:
    """Stream detection events, tracking updates, engagement schedules."""

    def __init__(self, manager: Optional[WebSocketManager] = None) -> None:
        self._manager = manager if manager is not None else WebSocketManager()

    def emit_track(
        self,
        track_id: str,
        x: float,
        y: float,
        z: float,
        speed_mps: float,
        heading_deg: float,
        confidence: float,
    ) -> MessageEnvelope:
        return self._manager.publish_track_update(
            track_id, x, y, z, speed_mps, heading_deg, confidence
        )

    def emit_detection(
        self,
        event_id: str,
        source: str,
        target_id: str,
        threat_level: str,
        protocol: str,
        confidence: float,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        anomalies: Optional[List[str]] = None,
    ) -> MessageEnvelope:
        return self._manager.publish_detection_event(
            event_id,
            source,
            target_id,
            threat_level,
            protocol,
            confidence,
            latitude=latitude,
            longitude=longitude,
            anomalies=anomalies,
        )

    def emit_engagement(
        self,
        track_id: str,
        engage_start_s: float,
        engage_end_s: float,
        pk_base: float,
        priority: int,
    ) -> MessageEnvelope:
        return self._manager.publish_engagement_scheduled(
            track_id, engage_start_s, engage_end_s, pk_base, priority
        )

    def emit_alert(
        self,
        alert_id: str,
        severity: str,
        message: str,
        source: str,
        target_id: Optional[str] = None,
    ) -> MessageEnvelope:
        return self._manager.publish_alert(alert_id, severity, message, source, target_id=target_id)

    def history(self) -> List[MessageEnvelope]:
        return self._manager.get_event_history()


# Deterministic default timestamp for tests that need a fixed reference.
DEFAULT_TIMESTAMP = 1_777_000_000.0  # 2026-04-22T12:26:40Z
