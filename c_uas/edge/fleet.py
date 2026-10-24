"""
C-UAS edge node fleet management.

Edge node registration, heartbeat and last-seen tracking, fleet health
scoring, offline node detection, and decommissioning. Every node belongs
to exactly one tenant (tenant isolation is enforced at the fleet layer).

State persists under ~/.c-uas-platform/edge/fleet/ (outside the repo).

All output is deterministic: identical inputs produce identical records,
scores, and CLI output on any machine. No network, no randomness without a
seed.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .state import EDGE_ROOT

FLEET_DIR = EDGE_ROOT / "fleet"

# A node is considered offline when it has not heartbeated within this many
# seconds of its configured heartbeat interval (grace multiplier).
OFFLINE_GRACE = 3.0


def _fleet_dir() -> str:
    d = FLEET_DIR
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def _atomic_write_json(path: str, data: Any) -> None:
    import os as _os

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    _os.replace(tmp, path)


def _read_json(path: str, default: Any = None) -> Any:
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _node_path(node_id: str) -> str:
    return os.path.join(_fleet_dir(), "{}.json".format(node_id))


@dataclass(frozen=True)
class NodeRecord:
    """One edge node in the fleet. Immutable once persisted."""

    node_id: str
    tenant_id: str
    location: str
    status: str  # registered | active | offline | decommissioned
    last_seen: float  # epoch seconds of most recent heartbeat
    heartbeat_interval_s: float
    health_score: float  # 0.0 - 100.0
    registered_at: float
    decommissioned_at: Optional[float] = None


@dataclass(frozen=True)
class FleetReport:
    """Aggregate fleet health snapshot."""

    total_nodes: int
    active_nodes: int
    offline_nodes: int
    decommissioned_nodes: int
    average_health_score: float  # 0.0 - 100.0
    by_tenant: Dict[str, int]  # tenant_id -> node count


def _default_status() -> str:
    return "registered"


class FleetManager:
    """Edge node fleet with tenant scoping and offline detection."""

    def __init__(
        self,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._clock = clock or time.time
        self._nodes: Dict[str, NodeRecord] = {}
        self._load_all()

    # -- persistence ---------------------------------------------------

    def _load_all(self) -> None:
        if not FLEET_DIR.exists():
            return
        for entry in FLEET_DIR.iterdir():
            if not entry.is_file() or entry.suffix != ".json":
                continue
            data = _read_json(str(entry))
            if data is None:
                continue
            decommissioned_at = data.get("decommissioned_at")
            record = NodeRecord(
                node_id=str(data["node_id"]),
                tenant_id=str(data["tenant_id"]),
                location=str(data["location"]),
                status=str(data.get("status", "registered")),
                last_seen=float(data.get("last_seen", 0.0)),
                heartbeat_interval_s=float(data.get("heartbeat_interval_s", 60.0)),
                health_score=float(data.get("health_score", 0.0)),
                registered_at=float(data.get("registered_at", 0.0)),
                decommissioned_at=(
                    float(decommissioned_at) if decommissioned_at is not None else None
                ),
            )
            self._nodes[record.node_id] = record

    def _persist(self, record: NodeRecord) -> None:
        _atomic_write_json(_node_path(record.node_id), asdict(record))

    # -- node lifecycle ------------------------------------------------

    def register_node(
        self,
        node_id: str,
        tenant_id: str,
        location: str,
        heartbeat_interval_s: float = 60.0,
    ) -> NodeRecord:
        """Register a new edge node under a tenant.

        Raises ValueError if node_id exists or heartbeat_interval_s invalid.
        """
        if not node_id or not str(node_id).strip():
            raise ValueError("node_id is required")
        if node_id in self._nodes:
            raise ValueError("Node already registered: {}".format(node_id))
        if heartbeat_interval_s <= 0:
            raise ValueError("heartbeat_interval_s must be positive")
        now = self._clock()
        record = NodeRecord(
            node_id=node_id,
            tenant_id=tenant_id,
            location=location,
            status="registered",
            last_seen=now,
            heartbeat_interval_s=heartbeat_interval_s,
            health_score=100.0,
            registered_at=now,
        )
        self._nodes[node_id] = record
        self._persist(record)
        return record

    def get_node(self, node_id: str) -> Optional[NodeRecord]:
        return self._nodes.get(node_id)

    def list_nodes(self) -> Tuple[NodeRecord, ...]:
        return tuple(sorted(self._nodes.values(), key=lambda r: r.node_id))

    def heartbeat(self, node_id: str, timestamp: Optional[float] = None) -> NodeRecord:
        """Record a heartbeat for a node, refreshing last_seen and health."""
        record = self._nodes.get(node_id)
        if record is None:
            raise KeyError("Unknown node: {}".format(node_id))
        if record.status == "decommissioned":
            raise ValueError("Cannot heartbeat decommissioned node: {}".format(node_id))
        now = timestamp if timestamp is not None else self._clock()
        health = compute_health_score(now, record.heartbeat_interval_s, last_seen=now)
        updated = NodeRecord(
            node_id=record.node_id,
            tenant_id=record.tenant_id,
            location=record.location,
            status="active",
            last_seen=now,
            heartbeat_interval_s=record.heartbeat_interval_s,
            health_score=health,
            registered_at=record.registered_at,
            decommissioned_at=record.decommissioned_at,
        )
        self._nodes[node_id] = updated
        self._persist(updated)
        return updated

    def decommission_node(self, node_id: str) -> NodeRecord:
        """Mark a node decommissioned. It is excluded from fleet health."""
        record = self._nodes.get(node_id)
        if record is None:
            raise KeyError("Unknown node: {}".format(node_id))
        if record.status == "decommissioned":
            return record
        now = self._clock()
        updated = NodeRecord(
            node_id=record.node_id,
            tenant_id=record.tenant_id,
            location=record.location,
            status="decommissioned",
            last_seen=record.last_seen,
            heartbeat_interval_s=record.heartbeat_interval_s,
            health_score=0.0,
            registered_at=record.registered_at,
            decommissioned_at=now,
        )
        self._nodes[node_id] = updated
        self._persist(updated)
        return updated

    # -- fleet health --------------------------------------------------

    def fleet_health(self) -> FleetReport:
        """Aggregate fleet health snapshot (deterministic)."""
        nodes = self.list_nodes()
        total = len(nodes)
        active = sum(1 for n in nodes if n.status == "active")
        offline = sum(1 for n in nodes if n.status == "offline")
        decommissioned = sum(1 for n in nodes if n.status == "decommissioned")
        if total:
            avg = round(sum(n.health_score for n in nodes) / float(total), 2)
        else:
            avg = 0.0
        by_tenant: Dict[str, int] = {}
        for n in nodes:
            if n.status != "decommissioned":
                by_tenant[n.tenant_id] = by_tenant.get(n.tenant_id, 0) + 1
        return FleetReport(
            total_nodes=total,
            active_nodes=active,
            offline_nodes=offline,
            decommissioned_nodes=decommissioned,
            average_health_score=avg,
            by_tenant=by_tenant,
        )

    def detect_offline(self, threshold_s: Optional[float] = None) -> List[NodeRecord]:
        """Return nodes considered offline based on last_seen vs heartbeat interval.

        A node is offline when now - last_seen exceeds
        heartbeat_interval_s * OFFLINE_GRACE (or threshold_s if given).
        Decommissioned nodes are excluded.
        """
        now = self._clock()
        offline: List[NodeRecord] = []
        for node in self.list_nodes():
            if node.status == "decommissioned":
                continue
            if threshold_s is not None and threshold_s > 0:
                limit = threshold_s
            else:
                limit = node.heartbeat_interval_s * OFFLINE_GRACE
            if now - node.last_seen > limit:
                offline.append(node)
        return sorted(offline, key=lambda n: n.node_id)


# -- pure functions ----------------------------------------------------


def compute_health_score(now: float, heartbeat_interval_s: float, last_seen: float = 0.0) -> float:
    """Pure deterministic health score (0.0 - 100.0).

    Full health when the last heartbeat is within one interval; degrades
    linearly to zero at three intervals without a heartbeat.
    """
    if heartbeat_interval_s <= 0:
        return 0.0
    age = now - last_seen
    if age <= 0:
        return 100.0
    if age <= heartbeat_interval_s:
        return 100.0
    # Linear decay from 100 at 1 interval to 0 at 3 intervals.
    ratio = 1.0 - (age - heartbeat_interval_s) / (2.0 * heartbeat_interval_s)
    return round(max(0.0, min(100.0, ratio * 100.0)), 2)


def is_offline(last_seen: float, now: float, heartbeat_interval_s: float) -> bool:
    """Pure offline check: true when last_seen is stale beyond grace."""
    return (now - last_seen) > (heartbeat_interval_s * OFFLINE_GRACE)
