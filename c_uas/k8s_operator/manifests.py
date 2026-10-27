"""Deterministic Kubernetes manifest generation for the C-UAS platform.

Builds Deployment, Service, ConfigMap, NetworkPolicy, PodDisruptionBudget,
and ResourceQuota manifests from a :class:`CUASPlatformSpec`. All output is
deterministic (sorted mapping keys, stable ordering) so the same spec always
yields the same YAML bytes.

License: AGPL-3.0.
"""

from __future__ import annotations

from typing import Any, Dict, List

import yaml  # type: ignore[import-untyped]

from .custom_resource import (
    CUASPlatformSpec,
)

DEFAULT_NAMESPACE = "cuas-system"
DEFAULT_APP_LABEL = "c-uas-platform"
DEFAULT_PORT = 8000
DEFAULT_METRICS_PORT = 9090


def _labels(module: str, instance: str = "cuas-platform") -> Dict[str, str]:
    return {
        "app": DEFAULT_APP_LABEL,
        "module": module,
        "instance": instance,
        "managed-by": "c-uas-k8s-operator",
    }


def _selector_labels() -> Dict[str, str]:
    return {"app": DEFAULT_APP_LABEL, "instance": "cuas-platform"}


def _annotations() -> Dict[str, str]:
    return {
        "cuas.a2zsoc.com/managed": "true",
        "cuas.a2zsoc.com/operator": "c-uas-k8s-operator",
    }


def _container_env(spec: CUASPlatformSpec) -> List[Dict[str, str]]:
    env: List[Dict[str, str]] = [
        {"name": "C_UAS_AUTH_ENABLED", "value": str(spec.auth_enabled).lower()},
        {
            "name": "C_UAS_MODULES_ENABLED",
            "value": ",".join(sorted(spec.modules_enabled)),
        },
    ]
    return env


def _container_ports() -> List[Dict[str, Any]]:
    return [
        {"containerPort": DEFAULT_PORT, "name": "http", "protocol": "TCP"},
        {
            "containerPort": DEFAULT_METRICS_PORT,
            "name": "metrics",
            "protocol": "TCP",
        },
    ]


def _probe(port: int, path: str) -> Dict[str, Any]:
    return {
        "httpGet": {"path": path, "port": port},
        "initialDelaySeconds": 10,
        "periodSeconds": 10,
        "failureThreshold": 3,
    }


def _security_context() -> Dict[str, Any]:
    return {
        "runAsNonRoot": True,
        "runAsUser": 65534,
        "runAsGroup": 65534,
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def generate_deployment(
    spec: CUASPlatformSpec,
    namespace: str = DEFAULT_NAMESPACE,
    name: str = "cuas-platform",
) -> Dict[str, Any]:
    """Generate a Deployment manifest for the C-UAS platform."""
    replicas = max(1, int(spec.replicas))
    manifest: Dict[str, Any] = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": _labels("platform"),
            "annotations": _annotations(),
        },
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": _selector_labels()},
            "template": {
                "metadata": {
                    "labels": _labels("platform"),
                    "annotations": _annotations(),
                },
                "spec": {
                    "securityContext": _security_context(),
                    "containers": [
                        {
                            "name": "c-uas-platform",
                            "image": spec.image,
                            "imagePullPolicy": "IfNotPresent",
                            "ports": _container_ports(),
                            "env": _container_env(spec),
                            "resources": {
                                "requests": {
                                    "cpu": "250m",
                                    "memory": "256Mi",
                                },
                                "limits": {
                                    "cpu": "1000m",
                                    "memory": "512Mi",
                                },
                            },
                            "livenessProbe": _probe(DEFAULT_PORT, "/healthz"),
                            "readinessProbe": _probe(DEFAULT_PORT, "/healthz"),
                            "securityContext": _security_context(),
                        }
                    ],
                },
            },
        },
    }
    return manifest


def generate_service(
    spec: CUASPlatformSpec,
    namespace: str = DEFAULT_NAMESPACE,
    name: str = "cuas-platform",
) -> Dict[str, Any]:
    """Generate a Service manifest for the C-UAS platform."""
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": _labels("platform"),
            "annotations": _annotations(),
        },
        "spec": {
            "selector": _selector_labels(),
            "ports": [
                {
                    "name": "http",
                    "port": DEFAULT_PORT,
                    "targetPort": DEFAULT_PORT,
                    "protocol": "TCP",
                },
                {
                    "name": "metrics",
                    "port": DEFAULT_METRICS_PORT,
                    "targetPort": DEFAULT_METRICS_PORT,
                    "protocol": "TCP",
                },
            ],
            "type": "ClusterIP",
        },
    }


def generate_configmap(
    spec: CUASPlatformSpec,
    namespace: str = DEFAULT_NAMESPACE,
    name: str = "cuas-platform-config",
) -> Dict[str, Any]:
    """Generate a ConfigMap manifest with the platform configuration."""
    data = {
        "C_UAS_REPLICAS": str(spec.replicas),
        "C_UAS_IMAGE": spec.image,
        "C_UAS_AUTH_ENABLED": str(spec.auth_enabled).lower(),
        "C_UAS_MODULES_ENABLED": ",".join(sorted(spec.modules_enabled)),
        "C_UAS_NAMESPACE": namespace,
    }
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": _labels("platform"),
            "annotations": _annotations(),
        },
        "data": data,
    }


def generate_networkpolicy(
    spec: CUASPlatformSpec,
    namespace: str = DEFAULT_NAMESPACE,
    name: str = "cuas-platform-default-deny",
    mTLS: bool = True,
) -> List[Dict[str, Any]]:
    """Generate NetworkPolicy manifests: default-deny ingress plus app allow.

    When ``mTLS`` is true, an mTLS-oriented policy (istio-style peer
    authentication hint) is included as annotations. NetworkPolicy itself is
    L3/L4; mTLS is enforced at the service-mesh layer and recorded here.
    """
    policies: List[Dict[str, Any]] = []

    # Default-deny all inbound traffic to the namespace.
    policies.append(
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": _labels("network"),
                "annotations": _annotations(),
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        }
    )

    # Allow ingress to the C-UAS platform pods from labeled clients.
    base_annotations = _annotations()
    if mTLS:
        base_annotations = {
            **base_annotations,
            "networking.istio.io/mtls": "true",
            "authentication.istio.io/mtls-mode": "STRICT",
        }
    allow_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"{name}-allow-cu",
            "namespace": namespace,
            "labels": _labels("network"),
            "annotations": base_annotations,
        },
        "spec": {
            "podSelector": {"matchLabels": _selector_labels()},
            "policyTypes": ["Ingress"],
            "ingress": [
                {
                    "ports": [
                        {
                            "port": DEFAULT_PORT,
                            "protocol": "TCP",
                        },
                        {
                            "port": DEFAULT_METRICS_PORT,
                            "protocol": "TCP",
                        },
                    ],
                    "from": [
                        {
                            "podSelector": {
                                "matchLabels": {
                                    "app": "c-uas-client",
                                    "release": "cuas",
                                }
                            }
                        },
                        {
                            "namespaceSelector": {
                                "matchLabels": {
                                    "name": "ingress-nginx",
                                }
                            }
                        },
                    ],
                }
            ],
        },
    }
    policies.append(allow_policy)

    return policies


def generate_poddisruptionbudget(
    spec: CUASPlatformSpec,
    namespace: str = DEFAULT_NAMESPACE,
    name: str = "cuas-platform-pdb",
) -> Dict[str, Any]:
    """Generate a PodDisruptionBudget ensuring minimal availability."""
    replicas = max(1, int(spec.replicas))
    # Ensure at least one replica stays available; keep majority for even counts.
    min_available = max(1, replicas // 2)
    return {
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": _labels("platform"),
            "annotations": _annotations(),
        },
        "spec": {
            "minAvailable": min_available,
            "selector": {"matchLabels": _selector_labels()},
        },
    }


def generate_resourcequota(
    spec: CUASPlatformSpec,
    namespace: str = DEFAULT_NAMESPACE,
    name: str = "cuas-platform-quota",
) -> Dict[str, Any]:
    """Generate a ResourceQuota bounding platform resource consumption."""
    replicas = max(1, int(spec.replicas))
    return {
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": _labels("platform"),
            "annotations": _annotations(),
        },
        "spec": {
            "hard": {
                "requests.cpu": str(replicas * 1000) + "m",
                "requests.memory": str(replicas * 512) + "Mi",
                "limits.cpu": str(replicas * 1000) + "m",
                "limits.memory": str(replicas * 512) + "Mi",
                "pods": str(replicas),
                "services": "4",
                "configmaps": "8",
                "networkpolicies": "4",
            }
        },
    }


def generate_all_manifests(
    spec: CUASPlatformSpec,
    namespace: str = DEFAULT_NAMESPACE,
    name: str = "cuas-platform",
    with_mTLS: bool = True,
) -> List[Dict[str, Any]]:
    """Generate the full deterministic manifest set for a CUASPlatform spec."""
    manifests: List[Dict[str, Any]] = [
        generate_deployment(spec, namespace=namespace, name=name),
        generate_service(spec, namespace=namespace, name=name),
        generate_configmap(spec, namespace=namespace, name=f"{name}-config"),
        generate_poddisruptionbudget(spec, namespace=namespace, name=f"{name}-pdb"),
        generate_resourcequota(spec, namespace=namespace, name=f"{name}-quota"),
    ]
    manifests.extend(
        generate_networkpolicy(spec, namespace=namespace, name=f"{name}-netpol", mTLS=with_mTLS)
    )
    return manifests


def manifest_to_yaml(manifest: Dict[str, Any]) -> str:
    """Serialize a single manifest to deterministic YAML."""
    return yaml.safe_dump(
        manifest,
        sort_keys=True,
        default_flow_style=False,
        allow_unicode=True,
    ).rstrip()


def manifests_to_yaml(manifests: List[Dict[str, Any]]) -> str:
    """Serialize multiple manifests to a single deterministic YAML stream."""
    parts = [manifest_to_yaml(m) for m in manifests]
    return "---\n".join(parts)
