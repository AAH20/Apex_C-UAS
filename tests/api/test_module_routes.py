"""Tests for the module analysis HTTP routes on c_uas/api/server.py.

Every route mirrors a CLI subcommand and returns real, deterministic,
computed values (no fabricated metrics). Tests use TestClient and assert
status codes plus real computed values.
"""

from fastapi.testclient import TestClient

from c_uas.api.server import app
from c_uas.edge.fleet import FleetManager
from c_uas.edge.tenancy import ResourceQuota as _TenantResourceQuota
from c_uas.edge.tenancy import TenancyManager

CLIENT = TestClient(app)

MODULE_ROUTES = [
    "/performance/benchmark",
    "/performance/profile",
    "/performance/sla",
    "/security/audit",
    "/security/penetrate",
    "/security/compliance",
    "/observability/metrics",
    "/observability/alerts",
    "/observability/health",
    "/observability/slo",
    "/datacenter/capacity",
    "/datacenter/lifecycle",
    "/datacenter/efficiency",
    "/edge/tenant",
    "/edge/fleet",
    "/edge/zero-trust",
]


def _get(path):
    return CLIENT.get(path)


class TestAllRoutesStatus:
    def test_all_module_routes_return_200(self):
        for path in MODULE_ROUTES:
            resp = _get(path)
            assert resp.status_code == 200, f"{path} returned {resp.status_code}"

    def test_routes_return_json(self):
        for path in MODULE_ROUTES:
            resp = _get(path)
            assert resp.headers["content-type"].startswith("application/json")
            resp.json()  # must be valid JSON


class TestPerformanceRoutes:
    def test_benchmark_computed_values(self):
        resp = _get("/performance/benchmark")
        assert resp.status_code == 200
        data = resp.json()
        assert data["module"] == "default"
        assert data["seed"] == 42
        assert data["astar_found"] is True
        assert data["astar_cost"] == 8.0
        assert data["astar_nodes_expanded"] == 12
        assert len(data["astar_path"]) == 9
        assert data["set_cover_covered"] == 7
        assert data["set_cover_universe"] == 7
        assert data["set_cover_chosen"] == ["S2", "S3", "S1"]
        assert data["local_search_best_cost"] == 0.0
        assert data["local_search_iterations"] == 11
        assert data["local_search_improved"] is True

    def test_benchmark_deterministic(self):
        first = _get("/performance/benchmark").json()
        second = _get("/performance/benchmark").json()
        assert first == second

    def test_sla_computed_values(self):
        resp = _get("/performance/sla")
        assert resp.status_code == 200
        data = resp.json()
        assert data["module"] == "default"
        assert data["sample_count"] == 1000
        assert data["overall_compliant"] is True
        assert data["compliance_status"] == "compliant"
        assert data["p99_compliant"] is True
        assert data["error_budget_compliant"] is True
        assert data["error_rate"] == 0.002
        assert 0.0 <= data["latency_p99_s"] <= 1.0

    def test_sla_deterministic_fields(self):
        first = _get("/performance/sla").json()
        second = _get("/performance/sla").json()
        for key in (
            "sample_count",
            "latency_p50_s",
            "latency_p95_s",
            "latency_p99_s",
            "error_rate",
            "error_budget_remaining",
            "p99_compliant",
            "error_budget_compliant",
            "overall_compliant",
            "recovery_time_s",
            "compliance_status",
        ):
            assert first[key] == second[key], f"sla.{key} not deterministic"

    def test_profile_computed_values(self):
        resp = _get("/performance/profile")
        assert resp.status_code == 200
        data = resp.json()
        assert data["module"] == "default"
        assert data["memory_pressure"] is False
        assert data["peak_rss_bytes"] == 128 * 1024 * 1024
        assert "default" in data["endpoints"]
        ep = data["endpoints"]["default"]
        assert ep["count"] == 200
        assert ep["error_count"] == 0
        assert ep["error_rate"] == 0.0
        assert isinstance(data["bottlenecks"], list)


class TestSecurityRoutes:
    def test_audit_computed_values(self):
        resp = _get("/security/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["checks_total"] == 11
        assert data["checks_passed"] == 8
        assert data["overall_score"] == 74.0
        assert data["grade"] == "C"
        assert data["audit_id"].startswith("HARDEN-")

    def test_audit_deterministic(self):
        first = _get("/security/audit").json()
        second = _get("/security/audit").json()
        assert first == second

    def test_penetrate_computed_values(self):
        resp = _get("/security/penetrate")
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall_passed"] is False
        assert data["pass_rate"] == 40.0
        assert data["report_id"].startswith("PENTEST-")
        assert len(data["results"]) == 5
        for result in data["results"]:
            assert "scenario_id" in result
            assert "passed" in result
            assert "risk_level" in result

    def test_penetrate_deterministic(self):
        first = _get("/security/penetrate").json()
        second = _get("/security/penetrate").json()
        assert first == second

    def test_compliance_computed_values(self):
        resp = _get("/security/compliance")
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall_coverage"] == 25.0
        assert data["iso_coverage"] == 0.0
        assert data["soc2_coverage"] == 50.0
        assert data["matrix_id"].startswith("COMPLIANCE-")
        assert isinstance(data["gaps"], list)
        assert len(data["gaps"]) > 0


class TestObservabilityRoutes:
    def test_metrics_computed_values(self):
        resp = _get("/observability/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert data["counters"] == 3
        assert data["gauges"] == 1
        assert data["histograms"] == 1
        assert data["summaries"] == 1
        assert isinstance(data["collected_at"], str)

    def test_alerts_computed_values(self):
        resp = _get("/observability/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "firing" in data
        assert "active" in data
        assert "resolved" in data
        assert "by_severity" in data
        assert set(data["by_severity"]) == {"info", "warning", "critical", "emergency"}

    def test_health_computed_values(self):
        resp = _get("/observability/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall_status"] in ("healthy", "degraded", "unhealthy", "unknown")
        assert isinstance(data["composite_score"], float)
        assert isinstance(data["components"], list)
        assert isinstance(data["unhealthy"], list)
        assert isinstance(data["degraded"], list)
        assert isinstance(data["healthy"], list)

    def test_slo_computed_values(self):
        resp = _get("/observability/slo")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["results"]) == 3
        by_metric = {r["metric"]: r for r in data["results"]}
        assert by_metric["availability"]["compliant"] is True
        assert by_metric["availability"]["actual"] == 0.9995
        assert by_metric["latency_p95"]["compliant"] is True
        assert by_metric["latency_p95"]["actual"] == 0.42
        assert by_metric["error_rate"]["compliant"] is False
        assert by_metric["error_rate"]["actual"] == 0.003

    def test_slo_deterministic_fields(self):
        first = _get("/observability/slo").json()
        second = _get("/observability/slo").json()
        for r1, r2 in zip(first["results"], second["results"]):
            assert r1["service"] == r2["service"]
            assert r1["metric"] == r2["metric"]
            assert r1["target"] == r2["target"]
            assert r1["actual"] == r2["actual"]
            assert r1["compliant"] == r2["compliant"]


class TestDatacenterRoutes:
    def test_capacity_computed_values(self):
        resp = _get("/datacenter/capacity")
        assert resp.status_code == 200
        data = resp.json()
        assert data["plan_id"].startswith("plan-")
        assert data["total_it_load_kw"] == 25.0
        assert data["overall_utilization_pct"] == 67.32
        assert data["overcommitted_racks"] == 0
        assert len(data["racks"]) == 3

    def test_capacity_deterministic(self):
        first = _get("/datacenter/capacity").json()
        second = _get("/datacenter/capacity").json()
        assert first == second

    def test_lifecycle_computed_values(self):
        resp = _get("/datacenter/lifecycle")
        assert resp.status_code == 200
        data = resp.json()
        assert data["report_id"].startswith("lc-")
        assert data["total_assets"] == 3
        assert data["assets_needing_retirement"] == 1
        assert data["total_decommission_cost_usd"] == 7500.0
        assert data["stage_counts"]["active"] == 3

    def test_lifecycle_deterministic(self):
        first = _get("/datacenter/lifecycle").json()
        second = _get("/datacenter/lifecycle").json()
        assert first == second

    def test_efficiency_computed_values(self):
        resp = _get("/datacenter/efficiency")
        assert resp.status_code == 200
        data = resp.json()
        assert data["report_id"].startswith("eff-")
        assert data["pue"] == 1.5
        assert data["dcie"] == 0.6667
        assert data["compute_per_watt"] == 0.05
        assert data["efficiency_rating"] == "B"

    def test_efficiency_deterministic(self):
        first = _get("/datacenter/efficiency").json()
        second = _get("/datacenter/efficiency").json()
        assert first == second


class TestEdgeRoutes:
    def test_zero_trust_default_deny(self):
        resp = _get("/edge/zero-trust")
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False
        assert data["reason"] == "ingress denied by default-deny rule"
        assert isinstance(data["rules_checked"], list)
        assert "default-deny-ingress" in data["rules_checked"]

    def test_zero_trust_still_denied_with_all_flags(self):
        resp = CLIENT.get(
            "/edge/zero-trust",
            params={
                "source": "node-A",
                "dest": "node-B",
                "port": 443,
                "has_mtls": "true",
                "same_segment": "true",
                "authenticated": "true",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        # default-deny short-circuits before any enforcement check
        assert data["allowed"] is False
        assert data["reason"] == "ingress denied by default-deny rule"

    def test_tenant_route_registers_and_lists(self):
        manager = TenancyManager()
        tenant_id = "T-TEST-ROUTE"
        try:
            manager.register_tenant(
                tenant_id=tenant_id,
                name="Test Route Tenant",
                region="us-east-1",
                tier="standard",
                quota=_TenantResourceQuota(
                    max_nodes=10,
                    max_detections_per_hour=1000,
                    max_sync_mb_per_day=100,
                    max_concurrent_sensors=3,
                ),
            )
        except ValueError:
            pass  # may already exist from a prior run
        resp = _get("/edge/tenant")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["tenants"], list)
        ids = [t["tenant_id"] for t in data["tenants"]]
        assert tenant_id in ids

    def test_fleet_route_registers_and_lists(self):
        manager = FleetManager()
        node_id = "N-TEST-ROUTE"
        try:
            manager.register_node(
                node_id=node_id,
                tenant_id="T-TEST-ROUTE",
                location="Test Rack",
                heartbeat_interval_s=60.0,
            )
        except (ValueError, KeyError):
            pass  # may already exist from a prior run
        resp = _get("/edge/fleet")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_nodes"] >= 1
        assert isinstance(data["by_tenant"], dict)
        assert data["average_health_score"] >= 0.0
