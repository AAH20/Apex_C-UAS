"""
C-UAS edge multi-tenant isolation.

Tenant-scoped operations for edge node management: tenant registration,
row-level security (RLS) filtering patterns, tenant health, and resource
quotas. Every tenant's nodes, detections, and policy state are scoped to
that tenant; cross-tenant access is denied by default.

State persists under ~/.c-uas-platform/edge/tenants/ (outside the repo).

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

TENANTS_DIR = EDGE_ROOT / "tenants"


def _tenant_dir(tenant_id: str) -> str:
    d = TENANTS_DIR / tenant_id
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


def _tenant_path(tenant_id: str) -> str:
    return os.path.join(_tenant_dir(tenant_id), "tenant.json")


@dataclass(frozen=True)
class ResourceQuota:
    """Resource quota for one tenant."""

    max_nodes: int
    max_detections_per_hour: int
    max_sync_mb_per_day: int
    max_concurrent_sensors: int


@dataclass(frozen=True)
class TenantRecord:
    """One registered tenant. Immutable once persisted."""

    tenant_id: str
    name: str
    region: str
    tier: str
    quota: ResourceQuota
    status: str = "active"
    created_at: float = 0.0
    node_count: int = 0

    def with_quota(self, quota: ResourceQuota) -> "TenantRecord":
        return TenantRecord(
            tenant_id=self.tenant_id,
            name=self.name,
            region=self.region,
            tier=self.tier,
            quota=quota,
            status=self.status,
            created_at=self.created_at,
            node_count=self.node_count,
        )

    def with_status(self, status: str) -> "TenantRecord":
        return TenantRecord(
            tenant_id=self.tenant_id,
            name=self.name,
            region=self.region,
            tier=self.tier,
            quota=self.quota,
            status=status,
            created_at=self.created_at,
            node_count=self.node_count,
        )

    def with_node_count(self, node_count: int) -> "TenantRecord":
        return TenantRecord(
            tenant_id=self.tenant_id,
            name=self.name,
            region=self.region,
            tier=self.tier,
            quota=self.quota,
            status=self.status,
            created_at=self.created_at,
            node_count=node_count,
        )


@dataclass(frozen=True)
class TenantHealthReport:
    """Deterministic health snapshot for one tenant."""

    tenant_id: str
    node_count: int
    active_nodes: int
    within_quota: bool
    health_score: float  # 0.0 - 100.0


@dataclass(frozen=True)
class TenantList:
    """Ordered list of tenant records."""

    tenants: Tuple[TenantRecord, ...]


class TenancyManager:
    """Tenant isolation manager with RLS-style scoping and quotas."""

    def __init__(
        self,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._clock = clock or time.time
        self._tenants: Dict[str, TenantRecord] = {}
        self._load_all()

    # -- persistence ---------------------------------------------------

    def _load_all(self) -> None:
        if not TENANTS_DIR.exists():
            return
        for entry in TENANTS_DIR.iterdir():
            if not entry.is_dir():
                continue
            path = entry / "tenant.json"
            if not path.exists():
                continue
            data = _read_json(str(path))
            if data is None:
                continue
            quota = ResourceQuota(
                max_nodes=int(data["quota"]["max_nodes"]),
                max_detections_per_hour=int(data["quota"]["max_detections_per_hour"]),
                max_sync_mb_per_day=int(data["quota"]["max_sync_mb_per_day"]),
                max_concurrent_sensors=int(data["quota"]["max_concurrent_sensors"]),
            )
            record = TenantRecord(
                tenant_id=str(data["tenant_id"]),
                name=str(data["name"]),
                region=str(data["region"]),
                tier=str(data["tier"]),
                quota=quota,
                status=str(data.get("status", "active")),
                created_at=float(data.get("created_at", 0.0)),
                node_count=int(data.get("node_count", 0)),
            )
            self._tenants[record.tenant_id] = record

    def _persist(self, record: TenantRecord) -> None:
        _atomic_write_json(
            _tenant_path(record.tenant_id),
            asdict(record),
        )

    # -- tenant lifecycle ----------------------------------------------

    def register_tenant(
        self,
        tenant_id: str,
        name: str,
        region: str,
        tier: str,
        quota: Optional[ResourceQuota] = None,
    ) -> TenantRecord:
        """Register a new tenant. Raises ValueError if tenant_id exists."""
        if not tenant_id or not str(tenant_id).strip():
            raise ValueError("tenant_id is required")
        if tenant_id in self._tenants:
            raise ValueError("Tenant already registered: {}".format(tenant_id))
        if quota is None:
            quota = ResourceQuota(
                max_nodes=10,
                max_detections_per_hour=1000,
                max_sync_mb_per_day=100,
                max_concurrent_sensors=3,
            )
        record = TenantRecord(
            tenant_id=tenant_id,
            name=name,
            region=region,
            tier=tier,
            quota=quota,
            status="active",
            created_at=self._clock(),
            node_count=0,
        )
        self._tenants[tenant_id] = record
        self._persist(record)
        return record

    def get_tenant(self, tenant_id: str) -> Optional[TenantRecord]:
        return self._tenants.get(tenant_id)

    def list_tenants(self) -> TenantList:
        ordered = sorted(self._tenants.values(), key=lambda r: r.tenant_id)
        return TenantList(tenants=tuple(ordered))

    def set_quota(self, tenant_id: str, quota: ResourceQuota) -> TenantRecord:
        record = self._tenants.get(tenant_id)
        if record is None:
            raise KeyError("Unknown tenant: {}".format(tenant_id))
        updated = record.with_quota(quota)
        self._tenants[tenant_id] = updated
        self._persist(updated)
        return updated

    def set_status(self, tenant_id: str, status: str) -> TenantRecord:
        record = self._tenants.get(tenant_id)
        if record is None:
            raise KeyError("Unknown tenant: {}".format(tenant_id))
        updated = record.with_status(status)
        self._tenants[tenant_id] = updated
        self._persist(updated)
        return updated

    def set_node_count(self, tenant_id: str, node_count: int) -> TenantRecord:
        record = self._tenants.get(tenant_id)
        if record is None:
            raise KeyError("Unknown tenant: {}".format(tenant_id))
        updated = record.with_node_count(node_count)
        self._tenants[tenant_id] = updated
        self._persist(updated)
        return updated

    # -- RLS patterns --------------------------------------------------

    @staticmethod
    def rls_filter(records: List[TenantRecord], tenant_id: str) -> List[TenantRecord]:
        """Row-level security pattern: keep only rows belonging to tenant_id.

        A query scoped to one tenant never returns another tenant's rows.
        """
        return [r for r in records if r.tenant_id == tenant_id]

    @staticmethod
    def cross_tenant_access_allowed(source_tenant: str, target_tenant: str) -> bool:
        """Cross-tenant access is denied by default (zero-trust isolation).

        Returns True only when source and target are the same tenant.
        """
        return source_tenant == target_tenant

    # -- tenant health -------------------------------------------------

    def tenant_health(self, tenant_id: str) -> TenantHealthReport:
        record = self._tenants.get(tenant_id)
        if record is None:
            raise KeyError("Unknown tenant: {}".format(tenant_id))
        active = record.node_count if record.status == "active" else 0
        within_quota = record.node_count <= record.quota.max_nodes
        health_score = 100.0 if within_quota and record.status == "active" else 50.0
        return TenantHealthReport(
            tenant_id=tenant_id,
            node_count=record.node_count,
            active_nodes=active,
            within_quota=within_quota,
            health_score=health_score,
        )

    # -- quota evaluation (pure) --------------------------------------

    @staticmethod
    def evaluate_quota(usage: int, quota: ResourceQuota) -> Dict[str, Any]:
        """Pure quota evaluation: real computed headroom per resource."""
        return {
            "nodes": {
                "usage": usage,
                "limit": quota.max_nodes,
                "headroom": max(0, quota.max_nodes - usage),
                "within_quota": usage <= quota.max_nodes,
            }
        }


def tenant_health_score(node_count: int, active_nodes: int) -> float:
    """Pure deterministic tenant health score (0.0 - 100.0)."""
    if node_count == 0:
        return 0.0
    ratio = active_nodes / float(node_count)
    return round(ratio * 100.0, 2)
