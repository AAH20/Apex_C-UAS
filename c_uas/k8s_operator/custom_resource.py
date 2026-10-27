"""Kubernetes operator scaffolding for declarative C-UAS platform deployment.

CRD definitions, manifest generation, reconciliation loop, and CLI for the
``c-uas k8s`` subcommand. All output is deterministic: the same
:class:`CUASPlatformSpec` always produces the same manifests (sorted keys,
no randomness). State is persisted under ``~/.c-uas-platform/k8s_operator/``
(outside the repo).

License: AGPL-3.0.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "k8s_operator")
LAST_STATE_FILENAME = "last_state.json"

CRD_GROUP = "cuas.a2zsoc.com"
CRD_VERSION = "v1"
CRD_KIND = "CUASPlatform"
CRD_PLURAL = "cuasplatforms"
CRD_SHORTNAMES = ("cuas",)


@dataclass(frozen=True)
class CUASPlatformSpec:
    """Desired state of a C-UAS platform deployment on Kubernetes."""

    replicas: int = 3
    image: str = "ghcr.io/aah20/c-uas-platform:latest"
    auth_enabled: bool = True
    modules_enabled: Tuple[str, ...] = (
        "detection",
        "tracking",
        "engagement",
        "forensics",
    )

    def __post_init__(self) -> None:
        if self.replicas < 1:
            raise ValueError("replicas must be >= 1")
        if not self.image:
            raise ValueError("image must be non-empty")
        object.__setattr__(self, "modules_enabled", tuple(sorted(set(self.modules_enabled))))


@dataclass(frozen=True)
class CUASPlatformCondition:
    """A single condition observation of the CUASPlatform resource."""

    type: str  # e.g. Available, Progressing, Degraded
    status: str  # "True" / "False" / "Unknown"
    last_transition_time: str
    reason: str = ""
    message: str = ""


@dataclass(frozen=True)
class CUASPlatformStatus:
    """Observed status of a CUASPlatform deployment."""

    phase: str = "Pending"  # Pending / Running / Degraded / Terminating
    replicas_ready: int = 0
    conditions: Tuple[CUASPlatformCondition, ...] = ()

    def with_condition(self, condition: CUASPlatformCondition) -> "CUASPlatformStatus":
        """Return a new status with the given condition added/replaced."""
        existing = list(self.conditions)
        replaced = False
        for i, c in enumerate(existing):
            if c.type == condition.type:
                existing[i] = condition
                replaced = True
                break
        if not replaced:
            existing.append(condition)
        return CUASPlatformStatus(
            phase=self.phase,
            replicas_ready=self.replicas_ready,
            conditions=tuple(sorted(existing, key=lambda c: c.type)),
        )


@dataclass(frozen=True)
class CUASPlatform:
    """A CUASPlatform custom resource (spec + status + metadata)."""

    name: str
    namespace: str = "cuas-system"
    spec: CUASPlatformSpec = field(default_factory=CUASPlatformSpec)
    status: CUASPlatformStatus = field(default_factory=CUASPlatformStatus)

    def to_dict(self) -> Dict:
        return {
            "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
            "kind": CRD_KIND,
            "metadata": {"name": self.name, "namespace": self.namespace},
            "spec": asdict(self.spec),
            "status": {
                "phase": self.status.phase,
                "replicas_ready": self.status.replicas_ready,
                "conditions": [asdict(c) for c in self.status.conditions],
            },
        }


def spec_from_dict(data: Dict) -> CUASPlatformSpec:
    """Build a :class:`CUASPlatformSpec` from a raw dict (CRD / JSON input)."""
    return CUASPlatformSpec(
        replicas=int(data.get("replicas", 3)),
        image=str(data.get("image", CUASPlatformSpec.image)),
        auth_enabled=bool(data.get("auth_enabled", True)),
        modules_enabled=tuple(sorted(set(str(m) for m in data.get("modules_enabled", ())))),
    )


def status_from_dict(data: Dict) -> CUASPlatformStatus:
    """Build a :class:`CUASPlatformStatus` from a raw dict."""
    conditions = tuple(
        CUASPlatformCondition(
            type=str(c.get("type", "")),
            status=str(c.get("status", "Unknown")),
            last_transition_time=str(c.get("last_transition_time", "")),
            reason=str(c.get("reason", "")),
            message=str(c.get("message", "")),
        )
        for c in data.get("conditions", [])
    )
    return CUASPlatformStatus(
        phase=str(data.get("phase", "Pending")),
        replicas_ready=int(data.get("replicas_ready", 0)),
        conditions=conditions,
    )


def utc_now_iso() -> str:
    """Current UTC time as ISO-8601 (used only for condition timestamps)."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def condition_for_phase(
    phase: str,
    reason: str,
    message: str = "",
    status: str = "True",
    condition_type: str = "Available",
) -> CUASPlatformCondition:
    """Construct a :class:`CUASPlatformCondition` for a given phase."""
    return CUASPlatformCondition(
        type=condition_type,
        status=status,
        last_transition_time=utc_now_iso(),
        reason=reason,
        message=message,
    )


def load_last_state(state_dir: str = DEFAULT_STATE_DIR) -> Optional[CUASPlatform]:
    """Load the last reconciled state from disk (None if never reconciled)."""
    path = os.path.join(state_dir, LAST_STATE_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    spec = spec_from_dict(data.get("spec", {}))
    status = status_from_dict(data.get("status", {}))
    return CUASPlatform(
        name=str(data.get("metadata", {}).get("name", "cuas-platform")),
        namespace=str(data.get("metadata", {}).get("namespace", "cuas-system")),
        spec=spec,
        status=status,
    )


def save_last_state(resource: CUASPlatform, state_dir: str = DEFAULT_STATE_DIR) -> str:
    """Persist the reconciled state to disk and return the path written."""
    os.makedirs(state_dir, exist_ok=True)
    path = os.path.join(state_dir, LAST_STATE_FILENAME)
    payload = {
        "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
        "kind": CRD_KIND,
        "metadata": {
            "name": resource.name,
            "namespace": resource.namespace,
        },
        "spec": asdict(resource.spec),
        "status": {
            "phase": resource.status.phase,
            "replicas_ready": resource.status.replicas_ready,
            "conditions": [asdict(c) for c in resource.status.conditions],
        },
        "reconciled_at": utc_now_iso(),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path
