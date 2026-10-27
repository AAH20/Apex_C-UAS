"""Reconciliation loop: desired state vs actual state for the C-UAS operator.

Computes drift between the desired :class:`CUASPlatformSpec` and an observed
state, generates the corresponding Kubernetes manifests, and persists the
last reconciled state under ``~/.c-uas-platform/k8s_operator/``.

This module performs manifest generation and drift detection only -- no
actual Kubernetes cluster access is required or performed.

License: AGPL-3.0.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, List, Optional, Tuple

from .custom_resource import (
    CUASPlatform,
    CUASPlatformSpec,
    CUASPlatformStatus,
    condition_for_phase,
    save_last_state,
)
from .manifests import generate_all_manifests, manifests_to_yaml

PHASE_PENDING = "Pending"
PHASE_RUNNING = "Running"
PHASE_DEGRADED = "Degraded"
PHASE_TERMINATING = "Terminating"

CONDITION_AVAILABLE = "Available"
CONDITION_PROGRESSING = "Progressing"


@dataclass(frozen=True)
class DriftEntry:
    """A single detected drift between desired and observed state."""

    field: str
    desired: Any
    observed: Any


@dataclass(frozen=True)
class ReconciliationResult:
    """Outcome of one reconciliation pass."""

    resource: CUASPlatform
    drift: Tuple[DriftEntry, ...]
    manifests_yaml: str
    changed: bool
    applied: bool  # True when state was persisted (dry-run leaves False)


def _compare_specs(desired: CUASPlatformSpec, observed: CUASPlatformSpec) -> List[DriftEntry]:
    """Return drift entries for every differing spec field (sorted by field)."""
    fields = (
        ("replicas", desired.replicas, observed.replicas),
        ("image", desired.image, observed.image),
        ("auth_enabled", desired.auth_enabled, observed.auth_enabled),
        ("modules_enabled", list(desired.modules_enabled), list(observed.modules_enabled)),
    )
    drift: List[DriftEntry] = []
    for name, d, o in fields:
        if d != o:
            drift.append(DriftEntry(field=name, desired=d, observed=o))
    drift.sort(key=lambda d: d.field)
    return drift


def _compare_status(
    desired_status: CUASPlatformStatus, observed_status: CUASPlatformStatus
) -> List[DriftEntry]:
    drift: List[DriftEntry] = []
    if desired_status.phase != observed_status.phase:
        drift.append(
            DriftEntry(
                field="status.phase",
                desired=desired_status.phase,
                observed=observed_status.phase,
            )
        )
    if desired_status.replicas_ready != observed_status.replicas_ready:
        drift.append(
            DriftEntry(
                field="status.replicas_ready",
                desired=desired_status.replicas_ready,
                observed=observed_status.replicas_ready,
            )
        )
    desired_types = {c.type for c in desired_status.conditions}
    observed_types = {c.type for c in observed_status.conditions}
    for ctype in sorted(desired_types | observed_types):
        dc = next((c for c in desired_status.conditions if c.type == ctype), None)
        oc = next((c for c in observed_status.conditions if c.type == ctype), None)
        if dc is None or oc is None or asdict(dc) != asdict(oc):
            drift.append(
                DriftEntry(
                    field=f"status.conditions[{ctype}]",
                    desired=asdict(dc) if dc else None,
                    observed=asdict(oc) if oc else None,
                )
            )
    drift.sort(key=lambda d: d.field)
    return drift


def detect_drift(
    desired: CUASPlatform,
    observed: CUASPlatform,
) -> Tuple[DriftEntry, ...]:
    """Detect all drift between desired and observed CUASPlatform resources."""
    drift = _compare_specs(desired.spec, observed.spec)
    drift.extend(_compare_status(desired.status, observed.status))
    drift.sort(key=lambda d: d.field)
    return tuple(drift)


def reconcile(
    spec: CUASPlatformSpec,
    observed: Optional[CUASPlatformStatus] = None,
    namespace: str = "cuas-system",
    name: str = "cuas-platform",
    dry_run: bool = False,
    state_dir: str | None = None,
) -> ReconciliationResult:
    """Run one reconciliation pass against the desired spec.

    Parameters
    ----------
    spec:
        Desired state of the platform.
    observed:
        Last observed status (defaults to Pending/0 ready).
    namespace:
        Target Kubernetes namespace.
    name:
        Resource / deployment name.
    dry_run:
        When True, manifests are generated but no state is persisted.
    state_dir:
        Persistence directory (defaults to ``~/.c-uas-platform/k8s_operator/``).

    Returns
    -------
    ReconciliationResult
        The reconciled resource, detected drift, rendered YAML, and whether
        state changed / was applied.
    """
    from .custom_resource import DEFAULT_STATE_DIR

    if state_dir is None:
        state_dir = DEFAULT_STATE_DIR

    # Compute target status from spec first so drift comparison uses the
    # desired (converged) status rather than a Pending placeholder.
    phase = PHASE_RUNNING if spec.replicas >= 1 else PHASE_DEGRADED
    ready = min(int(spec.replicas), int(spec.replicas))
    conditions = (
        condition_for_phase(
            phase=phase,
            reason="Reconciled",
            message="Desired state matches generated manifests",
            condition_type=CONDITION_AVAILABLE,
        ),
        condition_for_phase(
            phase=phase,
            reason="ManifestsGenerated",
            message="Deployment, Service, ConfigMap, NetworkPolicy, PDB, Quota rendered",
            condition_type=CONDITION_PROGRESSING,
            status="True",
        ),
    )
    target_status = CUASPlatformStatus(
        phase=phase,
        replicas_ready=ready,
        conditions=conditions,
    )
    desired_resource = CUASPlatform(
        name=name,
        namespace=namespace,
        spec=spec,
        status=target_status,
    )

    previous = None
    if not dry_run:
        previous = _load_last_state(state_dir)

    drift: List[DriftEntry] = []
    changed = False

    if previous is not None:
        drift = list(detect_drift(desired_resource, previous))
        changed = bool(drift) or _status_out_of_sync(desired_resource, previous)
    else:
        # No prior state: everything is desired (initial reconciliation).
        changed = True

    target_resource = CUASPlatform(
        name=name,
        namespace=namespace,
        spec=spec,
        status=target_status,
    )

    manifests = generate_all_manifests(spec, namespace=namespace, name=name)
    yaml_text = manifests_to_yaml(manifests)

    applied = False
    if not dry_run:
        save_last_state(target_resource, state_dir=state_dir)
        applied = True

    return ReconciliationResult(
        resource=target_resource,
        drift=tuple(drift),
        manifests_yaml=yaml_text,
        changed=changed,
        applied=applied,
    )


def _status_out_of_sync(desired: CUASPlatform, previous: CUASPlatform) -> bool:
    return (
        desired.status.phase != previous.status.phase
        or desired.status.replicas_ready != previous.status.replicas_ready
    )


def _load_last_state(state_dir: str) -> Optional[CUASPlatform]:
    from .custom_resource import load_last_state

    return load_last_state(state_dir=state_dir)
