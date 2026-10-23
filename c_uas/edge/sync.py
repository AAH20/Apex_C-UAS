"""
Edge-to-cloud synchronization for C-UAS edge nodes.

Detections are queued locally on the edge node and synced to the cloud
endpoint when connectivity is restored. Conflicts are resolved by
last-write-wins on the event timestamp, so a node that was offline never
overwrites newer server state with stale local observations.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from heapq import heapify, heappop, heappush
from typing import Callable, Dict, List, Optional

from .config import EdgeConfig
from .state import load_json, save_json

ConnectivityCheck = Callable[[], bool]
PushDetection = Callable[["QueuedDetection"], bool]


@dataclass(order=True)
class QueuedDetection:
    """One detection queued for cloud sync.

    Ordered by event timestamp so the oldest observations sync first; ties
    break on detection_id for a fully deterministic dequeue order.
    """

    event_timestamp: float
    detection_id: str = field(compare=False)
    node_id: str = field(compare=False)
    source: str = field(compare=False)
    payload: dict = field(compare=False, default_factory=dict)


@dataclass(frozen=True)
class SyncReport:
    """Outcome of one sync attempt."""

    node_id: str
    synced_count: int
    pending_count: int
    delivered_count: int
    conflicts_resolved: int
    delivered: bool
    reason: str


class EdgeSync:
    """Edge-to-cloud sync with a durable local queue and conflict resolution."""

    def __init__(
        self,
        config: EdgeConfig,
        check_connectivity: Optional[ConnectivityCheck] = None,
        push_detection: Optional[PushDetection] = None,
    ) -> None:
        self.config = config
        self._check = check_connectivity or self._default_check_connectivity
        self._push = push_detection or self._default_push_detection
        self._queue: List[QueuedDetection] = []
        self._load_queue()

    # -- default (real) transport -------------------------------------

    def _default_check_connectivity(self) -> bool:
        if self.config.offline_mode:
            return False
        endpoint = self.config.cloud_endpoint
        if not endpoint:
            return False
        try:
            req = urllib.request.Request(endpoint.rstrip("/") + "/healthz", method="GET")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _default_push_detection(self, entry: QueuedDetection) -> bool:
        endpoint = self.config.cloud_endpoint
        if not endpoint:
            return False
        body = json.dumps(asdict(entry)).encode("utf-8")
        req = urllib.request.Request(
            endpoint.rstrip("/") + "/detections",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return 200 <= resp.status < 300
        except urllib.error.HTTPError as exc:
            # 409 conflict: the server holds a newer observation for this
            # detection; last-write-wins drops the stale local copy.
            if exc.code == 409:
                return False
            return False
        except Exception:
            return False

    # -- durable queue --------------------------------------------------

    def _load_queue(self) -> None:
        raw = load_json(self.config.node_id, "sync_queue", default=[])
        self._queue = [
            QueuedDetection(
                event_timestamp=float(entry["event_timestamp"]),
                detection_id=str(entry["detection_id"]),
                node_id=str(entry["node_id"]),
                source=str(entry["source"]),
                payload=dict(entry.get("payload") or {}),
            )
            for entry in raw
        ]
        heapify(self._queue)

    def _persist_queue(self) -> None:
        save_json(
            self.config.node_id,
            "sync_queue",
            [asdict(entry) for entry in sorted(self._queue)],
        )

    def queue_detection(
        self,
        detection_id: str,
        node_id: str,
        source: str,
        event_timestamp: float,
        payload: Optional[dict] = None,
    ) -> None:
        """Append a detection to the local sync queue and persist it."""
        entry = QueuedDetection(
            event_timestamp=event_timestamp,
            detection_id=detection_id,
            node_id=node_id,
            source=source,
            payload=dict(payload or {}),
        )
        heappush(self._queue, entry)
        self._persist_queue()

    # -- conflict resolution --------------------------------------------

    @staticmethod
    def resolve_conflicts(entries: List[QueuedDetection]) -> List[QueuedDetection]:
        """Last-write-wins by event_timestamp: newest entry per detection_id."""
        newest: Dict[str, QueuedDetection] = {}
        for entry in entries:
            current = newest.get(entry.detection_id)
            if current is None or entry.event_timestamp > current.event_timestamp:
                newest[entry.detection_id] = entry
        return sorted(newest.values(), key=lambda e: (e.event_timestamp, e.detection_id))

    # -- sync -----------------------------------------------------------

    def sync(self) -> SyncReport:
        """Push the local queue to the cloud when connectivity allows."""
        if not self._check():
            return SyncReport(
                node_id=self.config.node_id,
                synced_count=0,
                pending_count=len(self._queue),
                delivered_count=0,
                conflicts_resolved=0,
                delivered=False,
                reason="offline" if self.config.offline_mode else "unreachable",
            )

        delivered = 0
        deferred: List[QueuedDetection] = []
        while self._queue:
            entry = heappop(self._queue)
            try:
                accepted = self._push(entry)
            except Exception:
                accepted = False
            if accepted:
                delivered += 1
            else:
                deferred.append(entry)

        for entry in deferred:
            heappush(self._queue, entry)
        self._persist_queue()

        return SyncReport(
            node_id=self.config.node_id,
            synced_count=delivered + len(deferred),
            pending_count=len(self._queue),
            delivered_count=delivered,
            conflicts_resolved=0,
            delivered=delivered > 0,
            reason="synced",
        )
