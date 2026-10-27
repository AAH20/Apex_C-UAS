"""Kubernetes operator for declarative C-UAS platform deployment on Kubernetes.

Manifest generation (Deployment, Service, ConfigMap, NetworkPolicy,
PodDisruptionBudget, ResourceQuota) and reconciliation/drift detection only --
no actual Kubernetes cluster access. State persists under
``~/.c-uas-platform/k8s_operator/`` (outside the repo).

License: AGPL-3.0.
"""

from __future__ import annotations

from .cli import build_subparser, k8s_main, main
from .custom_resource import (
    CRD_GROUP,
    CRD_KIND,
    CRD_PLURAL,
    CRD_VERSION,
    DEFAULT_STATE_DIR,
    CUASPlatform,
    CUASPlatformCondition,
    CUASPlatformSpec,
    CUASPlatformStatus,
    condition_for_phase,
    load_last_state,
    save_last_state,
    spec_from_dict,
    status_from_dict,
)
from .manifests import (
    generate_all_manifests,
    generate_configmap,
    generate_deployment,
    generate_networkpolicy,
    generate_poddisruptionbudget,
    generate_resourcequota,
    generate_service,
    manifest_to_yaml,
    manifests_to_yaml,
)
from .reconciler import (
    PHASE_DEGRADED,
    PHASE_PENDING,
    PHASE_RUNNING,
    PHASE_TERMINATING,
    DriftEntry,
    ReconciliationResult,
    detect_drift,
    reconcile,
)

__all__ = [
    "CRD_GROUP",
    "CRD_KIND",
    "CRD_PLURAL",
    "CRD_VERSION",
    "CUASPlatform",
    "CUASPlatformCondition",
    "CUASPlatformSpec",
    "CUASPlatformStatus",
    "DEFAULT_STATE_DIR",
    "DriftEntry",
    "PHASE_DEGRADED",
    "PHASE_PENDING",
    "PHASE_RUNNING",
    "PHASE_TERMINATING",
    "ReconciliationResult",
    "build_subparser",
    "condition_for_phase",
    "detect_drift",
    "generate_all_manifests",
    "generate_configmap",
    "generate_deployment",
    "generate_networkpolicy",
    "generate_poddisruptionbudget",
    "generate_resourcequota",
    "generate_service",
    "k8s_main",
    "load_last_state",
    "main",
    "manifest_to_yaml",
    "manifests_to_yaml",
    "reconcile",
    "save_last_state",
    "spec_from_dict",
    "status_from_dict",
]
