"""Deterministic tests for the C-UAS edge multi-tenant isolation, fleet
management, and zero-trust network policy modules.

Covers c_uas.edge.tenancy (tenant registration, RLS filtering, tenant
health, resource quotas), c_uas.edge.fleet (node registration, heartbeat,
last-seen tracking, fleet health scoring, offline detection, decommissioning),
c_uas.edge.zero_trust (default-deny ingress, mTLS, network segmentation,
service-to-service authentication, policy evaluation), and the
c-uas edge --tenant / --fleet / --zero-trust CLI.

All values are real computations -- no mocks, no network, no fabricated
metrics. State persists under a temporary dir outside the repo
(C_UAS_EDGE_STATE_DIR) so tests are hermetic and repeatable.
"""

from __future__ import annotations

import os
import shutil
import tempfile

# Point edge state at a temporary directory before the edge modules import
# EDGE_ROOT, so every test writes outside the repo and to a fresh location.
os.environ["C_UAS_EDGE_STATE_DIR"] = tempfile.mkdtemp(prefix="c-uas-edge-tests-")

from c_uas.edge.cli import edge_main  # noqa: E402
from c_uas.edge.fleet import (  # noqa: E402
    FLEET_DIR,
    FleetManager,
    compute_health_score,
    is_offline,
)
from c_uas.edge.state import EDGE_ROOT  # noqa: E402
from c_uas.edge.tenancy import (  # noqa: E402
    TENANTS_DIR,
    ResourceQuota,
    TenancyManager,
    tenant_health_score,
)
from c_uas.edge.zero_trust import (  # noqa: E402
    ZERO_TRUST_DIR,
    NetworkPolicy,
    ZeroTrustManager,
    default_deny_eval,
)


def _clear_state() -> None:
    """Remove persisted tenant/fleet/zero-trust state for test isolation."""
    for directory in (TENANTS_DIR, FLEET_DIR, ZERO_TRUST_DIR):
        if directory.exists():
            shutil.rmtree(directory)


# --------------------------------------------------------------------------- #
# Tenancy: tenant registration, RLS, quotas, health
# --------------------------------------------------------------------------- #


def test_register_tenant_creates_record() -> None:
    _clear_state()
    mgr = TenancyManager()
    record = mgr.register_tenant(
        tenant_id="T-1",
        name="Site One",
        region="us-east-1",
        tier="standard",
    )
    assert record.tenant_id == "T-1"
    assert record.name == "Site One"
    assert record.region == "us-east-1"
    assert record.tier == "standard"
    assert record.status == "active"
    assert record.node_count == 0
    assert record.quota.max_nodes == 10


def test_register_tenant_default_quota() -> None:
    _clear_state()
    mgr = TenancyManager()
    record = mgr.register_tenant("T-1", "n", "r", "t")
    assert record.quota.max_detections_per_hour == 1000
    assert record.quota.max_sync_mb_per_day == 100
    assert record.quota.max_concurrent_sensors == 3


def test_duplicate_tenant_raises() -> None:
    _clear_state()
    mgr = TenancyManager()
    mgr.register_tenant("T-1", "n", "r", "t")
    try:
        mgr.register_tenant("T-1", "n", "r", "t")
    except ValueError:
        return
    raise AssertionError("expected ValueError for duplicate tenant")


def test_get_tenant_unknown_returns_none() -> None:
    _clear_state()
    mgr = TenancyManager()
    assert mgr.get_tenant("DOES-NOT-EXIST") is None


def test_list_tenants_ordered_by_tenant_id() -> None:
    _clear_state()
    mgr = TenancyManager()
    mgr.register_tenant("T-b", "B", "r", "t")
    mgr.register_tenant("T-a", "A", "r", "t")
    mgr.register_tenant("T-c", "C", "r", "t")
    ids = [t.tenant_id for t in mgr.list_tenants().tenants]
    assert ids == ["T-a", "T-b", "T-c"]


def test_rls_filter_keeps_only_requested_tenant() -> None:
    _clear_state()
    mgr = TenancyManager()
    mgr.register_tenant("T-1", "One", "r", "t")
    mgr.register_tenant("T-2", "Two", "r", "t")
    records = list(mgr.list_tenants().tenants)
    filtered = TenancyManager.rls_filter(records, "T-1")
    assert len(filtered) == 1
    assert filtered[0].tenant_id == "T-1"


def test_cross_tenant_access_denied_by_default() -> None:
    assert TenancyManager.cross_tenant_access_allowed("T-1", "T-2") is False
    assert TenancyManager.cross_tenant_access_allowed("T-1", "T-1") is True


def test_set_quota_updates_node_limit() -> None:
    _clear_state()
    mgr = TenancyManager()
    mgr.register_tenant("T-1", "n", "r", "t")
    quota = ResourceQuota(
        max_nodes=50,
        max_detections_per_hour=1000,
        max_sync_mb_per_day=100,
        max_concurrent_sensors=3,
    )
    updated = mgr.set_quota("T-1", quota)
    assert updated.quota.max_nodes == 50
    assert mgr.get_tenant("T-1").quota.max_nodes == 50


def test_set_quota_unknown_tenant_raises() -> None:
    _clear_state()
    mgr = TenancyManager()
    try:
        mgr.set_quota("T-ghost", ResourceQuota(1, 1, 1, 1))
    except KeyError:
        return
    raise AssertionError("expected KeyError for unknown tenant")


def test_tenant_health_active_within_quota_is_perfect() -> None:
    _clear_state()
    mgr = TenancyManager()
    mgr.register_tenant("T-1", "n", "r", "t")
    mgr.set_node_count("T-1", 3)
    health = mgr.tenant_health("T-1")
    assert health.node_count == 3
    assert health.active_nodes == 3
    assert health.within_quota is True
    assert health.health_score == 100.0


def test_tenant_health_over_quota_is_degraded() -> None:
    _clear_state()
    mgr = TenancyManager()
    mgr.register_tenant("T-1", "n", "r", "t")
    mgr.set_node_count("T-1", 12)  # quota max_nodes is 10
    health = mgr.tenant_health("T-1")
    assert health.within_quota is False
    assert health.health_score == 50.0


def test_tenant_health_inactive_has_no_active_nodes() -> None:
    _clear_state()
    mgr = TenancyManager()
    mgr.register_tenant("T-1", "n", "r", "t")
    mgr.set_status("T-1", "inactive")
    mgr.set_node_count("T-1", 5)
    health = mgr.tenant_health("T-1")
    assert health.active_nodes == 0


def test_evaluate_quota_headroom() -> None:
    quota = ResourceQuota(
        max_nodes=10,
        max_detections_per_hour=1000,
        max_sync_mb_per_day=100,
        max_concurrent_sensors=3,
    )
    result = TenancyManager.evaluate_quota(usage=4, quota=quota)
    assert result["nodes"]["usage"] == 4
    assert result["nodes"]["limit"] == 10
    assert result["nodes"]["headroom"] == 6
    assert result["nodes"]["within_quota"] is True


def test_tenant_health_score_pure() -> None:
    assert tenant_health_score(0, 0) == 0.0
    assert tenant_health_score(10, 10) == 100.0
    assert tenant_health_score(10, 5) == 50.0
    assert tenant_health_score(10, 7) == 70.0


def test_tenant_persistence_round_trip() -> None:
    _clear_state()
    mgr = TenancyManager()
    mgr.register_tenant("T-persist", "Persist", "eu", "enterprise")
    mgr.set_node_count("T-persist", 7)

    loaded = TenancyManager()  # new manager, reads from same state dir
    again = loaded.get_tenant("T-persist")
    assert again is not None
    assert again.tenant_id == "T-persist"
    assert again.name == "Persist"
    assert again.node_count == 7
    assert again.tier == "enterprise"


def test_tenant_state_dir_is_outside_repo() -> None:
    repo_root = "/Users/ahmedhassan/c-uas-platform"
    # State must live outside the repo, under ~/.c-uas-platform/edge/tenants
    # by default (or a temp dir when C_UAS_EDGE_STATE_DIR is set in tests).
    assert str(TENANTS_DIR).endswith("/tenants")
    assert repo_root not in str(TENANTS_DIR)
    assert repo_root not in str(EDGE_ROOT)
    assert str(TENANTS_DIR) == str(EDGE_ROOT / "tenants")


# --------------------------------------------------------------------------- #
# Fleet: node registration, heartbeat, health, offline, decommission
# --------------------------------------------------------------------------- #


def test_register_node_creates_record() -> None:
    _clear_state()
    mgr = FleetManager()
    record = mgr.register_node("N-1", "T-1", "Roof A")
    assert record.node_id == "N-1"
    assert record.tenant_id == "T-1"
    assert record.location == "Roof A"
    assert record.status == "registered"
    assert record.health_score == 100.0


def test_duplicate_node_raises() -> None:
    _clear_state()
    mgr = FleetManager()
    mgr.register_node("N-1", "T-1", "Roof A")
    try:
        mgr.register_node("N-1", "T-1", "Roof A")
    except ValueError:
        return
    raise AssertionError("expected ValueError for duplicate node")


def test_invalid_heartbeat_interval_raises() -> None:
    _clear_state()
    mgr = FleetManager()
    try:
        mgr.register_node("N-1", "T-1", "Roof A", heartbeat_interval_s=0)
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-positive interval")


def test_heartbeat_refreshes_node() -> None:
    _clear_state()
    mgr = FleetManager()
    mgr.register_node("N-1", "T-1", "Roof A")
    first = mgr.get_node("N-1")
    record = mgr.heartbeat("N-1")
    assert record.status == "active"
    assert record.last_seen >= first.last_seen
    assert record.health_score == 100.0


def test_heartbeat_unknown_node_raises() -> None:
    _clear_state()
    mgr = FleetManager()
    try:
        mgr.heartbeat("N-ghost")
    except KeyError:
        return
    raise AssertionError("expected KeyError for unknown node")


def test_fleet_health_aggregates() -> None:
    _clear_state()
    mgr = FleetManager()
    mgr.register_node("N-1", "T-1", "A")
    mgr.heartbeat("N-1")
    mgr.register_node("N-2", "T-1", "B")
    mgr.heartbeat("N-2")
    mgr.register_node("N-3", "T-2", "C")
    mgr.heartbeat("N-3")
    report = mgr.fleet_health()
    assert report.total_nodes == 3
    assert report.active_nodes == 3
    assert report.offline_nodes == 0
    assert report.decommissioned_nodes == 0
    assert report.average_health_score == 100.0
    assert report.by_tenant == {"T-1": 2, "T-2": 1}


def test_detect_offline_flags_stale_node() -> None:
    _clear_state()
    mgr = FleetManager()
    mgr.register_node("N-1", "T-1", "Roof A")
    mgr.heartbeat("N-1", timestamp=1000.0)  # last_seen in the distant past
    offline = mgr.detect_offline(threshold_s=1.0)
    assert len(offline) == 1
    assert offline[0].node_id == "N-1"


def test_detect_offline_excludes_decommissioned() -> None:
    _clear_state()
    mgr = FleetManager()
    mgr.register_node("N-1", "T-1", "Roof A")
    mgr.decommission_node("N-1")
    offline = mgr.detect_offline(threshold_s=1.0)
    assert offline == []


def test_decommission_node_zeroes_health() -> None:
    _clear_state()
    mgr = FleetManager()
    mgr.register_node("N-1", "T-1", "Roof A")
    mgr.heartbeat("N-1")
    record = mgr.decommission_node("N-1")
    assert record.status == "decommissioned"
    assert record.health_score == 0.0
    assert record.decommissioned_at is not None

    report = mgr.fleet_health()
    assert report.decommissioned_nodes == 1
    assert report.active_nodes == 0


def test_decommission_unknown_node_raises() -> None:
    _clear_state()
    mgr = FleetManager()
    try:
        mgr.decommission_node("N-ghost")
    except KeyError:
        return
    raise AssertionError("expected KeyError for unknown node")


def test_compute_health_score_pure() -> None:
    now = 1000.0
    assert compute_health_score(now, 60.0, last_seen=1000.0) == 100.0
    assert compute_health_score(now, 60.0, last_seen=940.0) == 100.0
    assert compute_health_score(now, 60.0, last_seen=900.0) == 66.67
    assert compute_health_score(now, 60.0, last_seen=820.0) == 0.0
    assert compute_health_score(now, 60.0, last_seen=0.0) == 0.0


def test_is_offline_pure() -> None:
    assert is_offline(1000.0, 2000.0, 60.0) is True  # age 1000 > 180s grace
    assert is_offline(1900.0, 2000.0, 60.0) is False  # age 100 < 180s grace
    assert is_offline(2000.0, 2000.0, 60.0) is False  # age 0


# --------------------------------------------------------------------------- #
# Zero trust: default-deny, mTLS, segmentation, service auth, policy eval
# --------------------------------------------------------------------------- #


def test_default_deny_ingress_blocks_all() -> None:
    mgr = ZeroTrustManager()
    result = mgr.evaluate_ingress(
        source="A",
        dest="B",
        port=443,
        has_mtls=True,
        same_segment=True,
        authenticated=True,
    )
    assert result.allowed is False
    assert result.reason == "ingress denied by default-deny rule"
    assert "default-deny-ingress" in result.rules_checked


def test_mtls_required_when_enforced() -> None:
    policy = NetworkPolicy(
        default_deny_ingress=False,
        mTLS_enforced=True,
        network_segmentation=False,
        service_to_service_auth=False,
    )
    mgr = ZeroTrustManager()
    mgr.policy = policy
    result = mgr.evaluate_ingress(
        source="A",
        dest="B",
        port=443,
        has_mtls=False,
        same_segment=True,
        authenticated=True,
    )
    assert result.allowed is False
    assert "mTLS" in result.reason


def test_network_segmentation_blocks_cross_segment() -> None:
    policy = NetworkPolicy(
        default_deny_ingress=False,
        mTLS_enforced=False,
        network_segmentation=True,
        service_to_service_auth=False,
    )
    mgr = ZeroTrustManager()
    mgr.policy = policy
    result = mgr.evaluate_ingress(
        source="A",
        dest="B",
        port=443,
        has_mtls=True,
        same_segment=False,
        authenticated=True,
    )
    assert result.allowed is False
    assert "segment" in result.reason


def test_service_auth_required_when_enforced() -> None:
    policy = NetworkPolicy(
        default_deny_ingress=False,
        mTLS_enforced=False,
        network_segmentation=False,
        service_to_service_auth=True,
    )
    mgr = ZeroTrustManager()
    mgr.policy = policy
    result = mgr.evaluate_ingress(
        source="A",
        dest="B",
        port=443,
        has_mtls=True,
        same_segment=True,
        authenticated=False,
    )
    assert result.allowed is False
    assert "authentication" in result.reason


def test_allowed_flow_when_default_deny_off_and_all_checks_pass() -> None:
    policy = NetworkPolicy(
        default_deny_ingress=False,
        mTLS_enforced=True,
        network_segmentation=True,
        service_to_service_auth=True,
    )
    mgr = ZeroTrustManager()
    mgr.policy = policy
    result = mgr.evaluate_ingress(
        source="A",
        dest="B",
        port=443,
        has_mtls=True,
        same_segment=True,
        authenticated=True,
    )
    assert result.allowed is True
    assert "allowed" in result.reason


def test_default_deny_eval_pure() -> None:
    # mTLS missing -> denied
    r = default_deny_eval("A", "B", 443, has_mtls=False, same_segment=True, authenticated=True)
    assert r.allowed is False
    # all present -> but default-deny still denies (strict policy)
    r2 = default_deny_eval("A", "B", 443, has_mtls=True, same_segment=True, authenticated=True)
    assert r2.allowed is False


def test_policy_save_and_reload() -> None:
    _clear_state()
    mgr = ZeroTrustManager()
    policy = NetworkPolicy(
        default_deny_ingress=False,
        mTLS_enforced=True,
        network_segmentation=False,
        service_to_service_auth=True,
        allowed_segments=("seg-a", "seg-b"),
    )
    mgr.save_policy(policy)

    reloaded = ZeroTrustManager()
    assert reloaded.policy.default_deny_ingress is False
    assert reloaded.policy.mTLS_enforced is True
    assert reloaded.policy.network_segmentation is False
    assert reloaded.policy.service_to_service_auth is True
    assert reloaded.policy.allowed_segments == ("seg-a", "seg-b")


# --------------------------------------------------------------------------- #
# CLI: deterministic output for --tenant / --fleet / --zero-trust
# --------------------------------------------------------------------------- #


def test_cli_tenant_register_output(capsys) -> None:
    _clear_state()
    rc = edge_main(
        [
            "--tenant",
            "--register-tenant",
            "--tenant-id",
            "T-CLI",
            "--name",
            "Site One",
            "--region",
            "us-east-1",
            "--tier",
            "standard",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Tenant registered: T-CLI" in out
    assert "Name     : Site One" in out
    assert "Tier     : standard" in out


def test_cli_tenant_list_output(capsys) -> None:
    _clear_state()
    edge_main(
        [
            "--tenant",
            "--register-tenant",
            "--tenant-id",
            "T-CLI",
            "--name",
            "Site One",
            "--region",
            "us-east-1",
            "--tier",
            "standard",
        ]
    )
    out = capsys.readouterr().out
    rc = edge_main(["--tenant", "--list-tenants"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Tenants (1)" in out
    assert "T-CLI  Site One  us-east-1  standard" in out


def test_cli_tenant_health_output(capsys) -> None:
    _clear_state()
    edge_main(
        [
            "--tenant",
            "--register-tenant",
            "--tenant-id",
            "T-CLI",
            "--name",
            "n",
            "--region",
            "r",
            "--tier",
            "t",
        ]
    )
    edge_main(
        [
            "--tenant",
            "--set-quota",
            "--tenant-id",
            "T-CLI",
            "--quota-key",
            "nodes",
            "--quota-value",
            "4",
        ]
    )
    edge_main(["--tenant", "--tenant-health", "--tenant-id", "T-CLI"])
    out = capsys.readouterr().out
    assert "Within quota : True" in out
    assert "Health score : 100.0" in out


def test_cli_tenant_isolation_denied(capsys) -> None:
    rc = edge_main(["--tenant", "--check-isolation", "--tenant-id", "T-1", "--name", "T-2"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Allowed : False" in out
    assert "deny-by-default" in out


def test_cli_fleet_register_and_health_output(capsys) -> None:
    _clear_state()
    edge_main(
        [
            "--fleet",
            "--register-node",
            "--node-id",
            "N-CLI",
            "--tenant-id",
            "T-CLI",
            "--location",
            "Roof A",
        ]
    )
    edge_main(["--fleet", "--heartbeat", "--node-id", "N-CLI"])
    rc = edge_main(["--fleet", "--fleet-health"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Fleet health" in out
    assert "Total nodes      : 1" in out
    assert "Avg health score : 100.0" in out


def test_cli_fleet_detect_offline_output(capsys) -> None:
    _clear_state()
    edge_main(
        [
            "--fleet",
            "--register-node",
            "--node-id",
            "N-CLI",
            "--tenant-id",
            "T-CLI",
            "--location",
            "Roof A",
        ]
    )
    edge_main(["--fleet", "--heartbeat", "--node-id", "N-CLI"])
    rc = edge_main(["--fleet", "--detect-offline"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Offline nodes (" in out


def test_cli_fleet_decommission_output(capsys) -> None:
    _clear_state()
    edge_main(
        [
            "--fleet",
            "--register-node",
            "--node-id",
            "N-CLI",
            "--tenant-id",
            "T-CLI",
            "--location",
            "Roof A",
        ]
    )
    rc = edge_main(["--fleet", "--decommission-node", "--node-id", "N-CLI"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Node decommissioned: N-CLI" in out
    assert "Status         : decommissioned" in out


def test_cli_zero_trust_evaluate_denies(capsys) -> None:
    rc = edge_main(
        ["--zero-trust", "--evaluate-policy", "--source", "A", "--dest", "B", "--port", "443"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Allowed    : False" in out
    assert "default-deny-ingress" in out


def test_cli_zero_trust_show_policy(capsys) -> None:
    rc = edge_main(
        [
            "--zero-trust",
            "--set-policy",
            "--default-deny-ingress",
            "--mtls",
            "--segmentation",
            "--service-auth",
        ]
    )
    assert rc == 0
    rc = edge_main(["--zero-trust", "--show-policy"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Default-deny ingress : True" in out
    assert "mTLS enforced        : True" in out


def test_cli_missing_required_args_return_one() -> None:
    assert edge_main(["--tenant", "--register-tenant"]) == 1
    assert edge_main(["--fleet", "--register-node"]) == 1
    assert edge_main(["--zero-trust", "--evaluate-policy"]) == 1
