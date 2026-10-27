"""Deterministic Kubernetes operator tests.

Covers CRD validation, manifest generation (Deployment, Service, ConfigMap,
NetworkPolicy, PodDisruptionBudget, ResourceQuota), drift detection, and the
reconciliation loop. All values are computed from real execution -- no mocks,
no fabricated metrics. State always lives in a tmp_path state dir (never the
real ~/.c-uas-platform).

License: AGPL-3.0.
"""

from __future__ import annotations

import argparse
import os

import pytest

from c_uas.k8s_operator import (
    PHASE_DEGRADED,
    PHASE_RUNNING,
    CUASPlatform,
    CUASPlatformCondition,
    CUASPlatformSpec,
    CUASPlatformStatus,
    detect_drift,
    generate_all_manifests,
    generate_configmap,
    generate_deployment,
    generate_networkpolicy,
    generate_poddisruptionbudget,
    generate_resourcequota,
    generate_service,
    k8s_main,
    load_last_state,
    manifests_to_yaml,
    reconcile,
    spec_from_dict,
    status_from_dict,
)
from c_uas.k8s_operator.custom_resource import (
    CRD_GROUP,
    CRD_KIND,
    CRD_PLURAL,
    CRD_VERSION,
    DEFAULT_STATE_DIR,
)

T_MODULES = ("detection", "engagement", "forensics", "tracking")


def _spec(**overrides) -> CUASPlatformSpec:
    data = dict(
        replicas=3,
        image="ghcr.io/aah20/c-uas-platform:latest",
        auth_enabled=True,
        modules_enabled=T_MODULES,
    )
    data.update(overrides)
    return CUASPlatformSpec(**data)


def _resource(**overrides) -> CUASPlatform:
    data = dict(
        name="cuas-platform",
        namespace="cuas-system",
        spec=_spec(),
        status=CUASPlatformStatus(phase=PHASE_RUNNING, replicas_ready=3),
    )
    data.update(overrides)
    return CUASPlatform(**data)


def _namespace(**overrides) -> argparse.Namespace:
    defaults = dict(
        manifests=True,
        dry_run=False,
        reconcile=False,
        name="cuas-platform",
        namespace="cuas-system",
        replicas=3,
        image="ghcr.io/aah20/c-uas-platform:latest",
        no_auth=False,
        module=None,
        state_dir=None,
        no_mtls=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# CRD / spec validation
# ---------------------------------------------------------------------------


def test_spec_defaults_are_sorted_and_valid() -> None:
    spec = _spec()
    assert spec.replicas == 3
    assert spec.image == "ghcr.io/aah20/c-uas-platform:latest"
    assert spec.auth_enabled is True
    assert spec.modules_enabled == T_MODULES


def test_spec_modules_are_sorted_and_deduped() -> None:
    spec = CUASPlatformSpec(
        replicas=1,
        image="img:1",
        auth_enabled=False,
        modules_enabled=("tracking", "detection", "tracking"),
    )
    assert spec.modules_enabled == ("detection", "tracking")
    assert spec.auth_enabled is False


def test_spec_rejects_zero_replicas() -> None:
    with pytest.raises(ValueError):
        CUASPlatformSpec(replicas=0)


def test_spec_rejects_negative_replicas() -> None:
    with pytest.raises(ValueError):
        CUASPlatformSpec(replicas=-1)


def test_spec_rejects_empty_image() -> None:
    with pytest.raises(ValueError):
        CUASPlatformSpec(replicas=1, image="")


def test_crd_constants() -> None:
    assert CRD_GROUP == "cuas.a2zsoc.com"
    assert CRD_VERSION == "v1"
    assert CRD_KIND == "CUASPlatform"
    assert CRD_PLURAL == "cuasplatforms"
    assert DEFAULT_STATE_DIR == os.path.join(
        os.path.expanduser("~"), ".c-uas-platform", "k8s_operator"
    )


def test_spec_from_dict_round_trip() -> None:
    spec = _spec(replicas=5, auth_enabled=False, modules_enabled=("forensics",))
    data = {
        "replicas": spec.replicas,
        "image": spec.image,
        "auth_enabled": spec.auth_enabled,
        "modules_enabled": list(spec.modules_enabled),
    }
    restored = spec_from_dict(data)
    assert restored == spec


def test_status_from_dict_round_trip() -> None:
    status = CUASPlatformStatus(
        phase=PHASE_RUNNING,
        replicas_ready=2,
        conditions=(
            CUASPlatformCondition(
                type="Available",
                status="True",
                last_transition_time="2026-10-27T10:00:00Z",
                reason="Reconciled",
                message="ok",
            ),
        ),
    )
    data = {
        "phase": status.phase,
        "replicas_ready": status.replicas_ready,
        "conditions": [
            {
                "type": c.type,
                "status": c.status,
                "last_transition_time": c.last_transition_time,
                "reason": c.reason,
                "message": c.message,
            }
            for c in status.conditions
        ],
    }
    restored = status_from_dict(data)
    assert restored == status


def test_resource_to_dict_shape() -> None:
    resource = _resource()
    d = resource.to_dict()
    assert d["apiVersion"] == f"{CRD_GROUP}/{CRD_VERSION}"
    assert d["kind"] == CRD_KIND
    assert d["metadata"]["name"] == "cuas-platform"
    assert d["metadata"]["namespace"] == "cuas-system"
    assert d["spec"]["replicas"] == 3
    assert d["status"]["phase"] == PHASE_RUNNING
    assert d["status"]["replicas_ready"] == 3


# ---------------------------------------------------------------------------
# Manifest generation
# ---------------------------------------------------------------------------


def test_deployment_manifest_shape_and_values() -> None:
    spec = _spec(replicas=4)
    dep = generate_deployment(spec)
    assert dep["apiVersion"] == "apps/v1"
    assert dep["kind"] == "Deployment"
    assert dep["metadata"]["name"] == "cuas-platform"
    assert dep["metadata"]["namespace"] == "cuas-system"
    assert dep["spec"]["replicas"] == 4
    container = dep["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == spec.image
    assert container["imagePullPolicy"] == "IfNotPresent"
    assert container["resources"]["requests"] == {"cpu": "250m", "memory": "256Mi"}
    assert container["resources"]["limits"] == {"cpu": "1000m", "memory": "512Mi"}
    env = {e["name"]: e["value"] for e in container["env"]}
    assert env["C_UAS_AUTH_ENABLED"] == "true"
    assert env["C_UAS_MODULES_ENABLED"] == "detection,engagement,forensics,tracking"
    sc = container["securityContext"]
    assert sc["runAsNonRoot"] is True
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["allowPrivilegeEscalation"] is False
    assert "ALL" in sc["capabilities"]["drop"]


def test_service_manifest_shape_and_values() -> None:
    svc = generate_service(_spec())
    assert svc["apiVersion"] == "v1"
    assert svc["kind"] == "Service"
    assert svc["spec"]["type"] == "ClusterIP"
    ports = {p["name"]: p["port"] for p in svc["spec"]["ports"]}
    assert ports == {"http": 8000, "metrics": 9090}
    assert svc["spec"]["selector"] == {"app": "c-uas-platform", "instance": "cuas-platform"}


def test_configmap_manifest_contains_spec_values() -> None:
    spec = _spec(replicas=7, auth_enabled=False)
    cm = generate_configmap(spec)
    assert cm["apiVersion"] == "v1"
    assert cm["kind"] == "ConfigMap"
    assert cm["data"]["C_UAS_REPLICAS"] == "7"
    assert cm["data"]["C_UAS_AUTH_ENABLED"] == "false"
    assert cm["data"]["C_UAS_MODULES_ENABLED"] == "detection,engagement,forensics,tracking"
    assert cm["data"]["C_UAS_IMAGE"] == spec.image


def test_pdb_ensures_min_available() -> None:
    spec = _spec(replicas=5)
    pdb = generate_poddisruptionbudget(spec)
    assert pdb["apiVersion"] == "policy/v1"
    assert pdb["kind"] == "PodDisruptionBudget"
    assert pdb["spec"]["minAvailable"] == 2  # 5 // 2
    assert pdb["spec"]["selector"] == {
        "matchLabels": {"app": "c-uas-platform", "instance": "cuas-platform"}
    }


def test_pdb_single_replica_min_available_one() -> None:
    spec = _spec(replicas=1)
    pdb = generate_poddisruptionbudget(spec)
    assert pdb["spec"]["minAvailable"] == 1


def test_resourcequota_bounds_scale_with_replicas() -> None:
    spec = _spec(replicas=3)
    quota = generate_resourcequota(spec)
    assert quota["apiVersion"] == "v1"
    assert quota["kind"] == "ResourceQuota"
    hard = quota["spec"]["hard"]
    assert hard["pods"] == "3"
    assert hard["requests.cpu"] == "3000m"
    assert hard["requests.memory"] == "1536Mi"
    assert hard["limits.cpu"] == "3000m"
    assert hard["limits.memory"] == "1536Mi"


def test_networkpolicy_default_deny_allows_app_ingress() -> None:
    policies = generate_networkpolicy(_spec())
    assert len(policies) == 2
    deny = policies[0]
    assert deny["kind"] == "NetworkPolicy"
    assert deny["spec"]["podSelector"] == {}
    assert deny["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert deny["spec"]["ingress"] == []
    assert deny["spec"]["egress"] == []

    allow = policies[1]
    assert allow["metadata"]["name"] == "cuas-platform-default-deny-allow-cu"
    assert allow["spec"]["policyTypes"] == ["Ingress"]
    ingress_ports = {p["port"] for p in allow["spec"]["ingress"][0]["ports"]}
    assert ingress_ports == {8000, 9090}


def test_networkpolicy_mTLS_annotations() -> None:
    policies = generate_networkpolicy(_spec(), mTLS=True)
    allow = policies[1]
    ann = allow["metadata"]["annotations"]
    assert ann["networking.istio.io/mtls"] == "true"
    assert ann["authentication.istio.io/mtls-mode"] == "STRICT"

    policies_no = generate_networkpolicy(_spec(), mTLS=False)
    allow_no = policies_no[1]
    assert "networking.istio.io/mtls" not in allow_no["metadata"]["annotations"]


def test_all_manifests_deterministic_same_input() -> None:
    spec = _spec(replicas=3)
    m1 = generate_all_manifests(spec)
    m2 = generate_all_manifests(spec)
    assert manifests_to_yaml(m1) == manifests_to_yaml(m2)


def test_all_manifests_different_input_different_output() -> None:
    spec_a = _spec(replicas=3)
    spec_b = _spec(replicas=5)
    yaml_a = manifests_to_yaml(generate_all_manifests(spec_a))
    yaml_b = manifests_to_yaml(generate_all_manifests(spec_b))
    assert yaml_a != yaml_b


def test_all_manifests_yaml_is_sorted_and_deterministic() -> None:
    spec = _spec()
    yaml_text = manifests_to_yaml(generate_all_manifests(spec))
    # YAML stream must contain exactly 6 documents (deployment, service, configmap,
    # pdb, quota, + 2 network policies = 7 docs).
    docs = [d for d in yaml_text.split("---\n") if d.strip()]
    assert len(docs) == 7
    kinds = []
    for doc in docs:
        for line in doc.splitlines():
            if line.startswith("kind:"):
                kinds.append(line.split(":", 1)[1].strip())
                break
    assert sorted(kinds) == sorted(
        [
            "Deployment",
            "Service",
            "ConfigMap",
            "PodDisruptionBudget",
            "ResourceQuota",
            "NetworkPolicy",
            "NetworkPolicy",
        ]
    )


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


def test_detect_drift_no_drift_when_identical() -> None:
    resource = _resource()
    assert detect_drift(resource, resource) == ()


def test_detect_drift_replicas() -> None:
    desired = _resource(spec=_spec(replicas=5))
    observed = _resource(spec=_spec(replicas=3))
    drift = detect_drift(desired, observed)
    assert len(drift) == 1
    assert drift[0].field == "replicas"
    assert drift[0].desired == 5
    assert drift[0].observed == 3


def test_detect_drift_image_and_auth() -> None:
    desired = _resource(spec=_spec(image="img:2", auth_enabled=False))
    observed = _resource(spec=_spec(image="img:1", auth_enabled=True))
    drift = detect_drift(desired, observed)
    fields = {d.field for d in drift}
    assert fields == {"image", "auth_enabled"}


def test_detect_drift_modules_order_independent() -> None:
    desired = _resource(spec=_spec(modules_enabled=("tracking", "detection")))
    observed = _resource(spec=_spec(modules_enabled=("detection", "tracking")))
    assert detect_drift(desired, observed) == ()


def test_detect_drift_status_phase_and_ready() -> None:
    desired = _resource(status=CUASPlatformStatus(phase=PHASE_RUNNING, replicas_ready=3))
    observed = _resource(status=CUASPlatformStatus(phase=PHASE_DEGRADED, replicas_ready=1))
    drift = detect_drift(desired, observed)
    fields = {d.field for d in drift}
    assert fields == {"status.phase", "status.replicas_ready"}


def test_detect_drift_conditions() -> None:
    desired = _resource(
        status=CUASPlatformStatus(
            phase=PHASE_RUNNING,
            replicas_ready=3,
            conditions=(
                CUASPlatformCondition(
                    type="Available",
                    status="True",
                    last_transition_time="T1",
                    reason="R",
                    message="M",
                ),
            ),
        )
    )
    observed = _resource(
        status=CUASPlatformStatus(
            phase=PHASE_RUNNING,
            replicas_ready=3,
            conditions=(
                CUASPlatformCondition(
                    type="Available",
                    status="False",
                    last_transition_time="T2",
                    reason="R2",
                    message="M2",
                ),
            ),
        )
    )
    drift = detect_drift(desired, observed)
    assert any("status.conditions[Available]" == d.field for d in drift)


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------


def test_reconcile_dry_run_does_not_persist(tmp_path) -> None:
    state_dir = str(tmp_path / "k8s_operator")
    result = reconcile(
        _spec(replicas=3),
        namespace="cuas-system",
        name="cuas-platform",
        dry_run=True,
        state_dir=state_dir,
    )
    assert result.applied is False
    assert not os.path.exists(os.path.join(state_dir, "last_state.json"))
    assert result.resource.status.phase == PHASE_RUNNING
    assert result.resource.status.replicas_ready == 3
    assert "kind: Deployment" in result.manifests_yaml


def test_reconcile_persists_state(tmp_path) -> None:
    state_dir = str(tmp_path / "k8s_operator")
    result = reconcile(
        _spec(replicas=4),
        namespace="cuas-system",
        name="cuas-platform",
        dry_run=False,
        state_dir=state_dir,
    )
    assert result.applied is True
    assert os.path.exists(os.path.join(state_dir, "last_state.json"))
    loaded = load_last_state(state_dir=state_dir)
    assert loaded is not None
    assert loaded.spec.replicas == 4
    assert loaded.status.phase == PHASE_RUNNING


def test_reconcile_initial_state_has_drift(tmp_path) -> None:
    state_dir = str(tmp_path / "k8s_operator")
    # No prior state -> initial reconciliation is a change.
    result = reconcile(
        _spec(replicas=3),
        dry_run=False,
        state_dir=state_dir,
    )
    assert result.changed is True
    assert result.applied is True


def test_reconcile_idempotent_no_drift_on_second_pass(tmp_path) -> None:
    state_dir = str(tmp_path / "k8s_operator")
    spec = _spec(replicas=3)
    r1 = reconcile(spec, dry_run=False, state_dir=state_dir)
    # Second pass against the persisted state: no drift.
    r2 = reconcile(spec, dry_run=False, state_dir=state_dir)
    assert r1.changed is True
    assert r2.changed is False  # identical to persisted state -> no drift


def test_k8s_main_manifests_flag(tmp_path) -> None:
    ns = _namespace(manifests=True, dry_run=False, reconcile=False)
    rc = k8s_main(ns)
    assert rc == 0

    ns2 = _namespace(manifests=False, dry_run=False, reconcile=False)
    assert k8s_main(ns2) == 1  # no action specified
