"""Tests for the C-UAS REST API server."""

from fastapi.testclient import TestClient

from c_uas.api.server import app


class TestAPIHealth:
    def test_health(self):
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["platform"] == "C-UAS Platform"


class TestScanRF:
    def test_scan_rf(self):
        client = TestClient(app)
        resp = client.post(
            "/detection/scan-rf",
            json={"freq_mhz": 2450.0, "bw_mhz": 20.0},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "protocol" in data
        assert "threat_category" in data


class TestSpoof:
    def test_detect_spoof_nominal(self):
        client = TestClient(app)
        resp = client.post(
            "/detection/spoof",
            json={
                "carrier_to_noise_db_hz": 42.0,
                "pseudorange_rate_mps": 10.0,
                "clock_drift_ppm": 0.05,
                "num_satellites": 10,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["threat_level"] == "NOMINAL"

    def test_detect_spoof_spoofed(self):
        client = TestClient(app)
        resp = client.post(
            "/detection/spoof",
            json={
                "carrier_to_noise_db_hz": 60.0,
                "pseudorange_rate_mps": 0.0,
                "clock_drift_ppm": 3.8,
                "num_satellites": 2,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["threat_level"] == "CRITICAL"


class TestEngagement:
    def test_schedule(self):
        client = TestClient(app)
        resp = client.post(
            "/engagement/schedule",
            json={"num_drones": 4, "dwell_s": 4.0, "slew_s": 1.5, "time_limit_s": 30.0},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["expected_kills"] > 0.0
        assert data["engaged_targets"] >= 1


class TestGovernance:
    def test_register_system(self):
        client = TestClient(app)
        resp = client.post(
            "/systems",
            json={
                "name": "EKF Tracking",
                "module_path": "c_uas.tracking.ekf_interceptor",
                "lifecycle_stage": "operation",
                "risk_level": "medium",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "system_id" in data
        assert data["system"]["name"] == "EKF Tracking"

    def test_list_systems(self):
        client = TestClient(app)
        # Register one first
        client.post(
            "/systems",
            json={
                "name": "Test Sys",
                "module_path": "mod.test",
                "lifecycle_stage": "development",
                "risk_level": "low",
            },
        )
        resp = client.get("/systems")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1

    def test_assess_risk(self):
        client = TestClient(app)
        # Register a system first
        reg_resp = client.post(
            "/systems",
            json={
                "name": "Risk Sys",
                "module_path": "mod.risk",
                "lifecycle_stage": "operation",
                "risk_level": "low",
            },
        )
        system_id = reg_resp.json()["system_id"]
        resp = client.post(
            "/risks",
            json={
                "system_id": system_id,
                "description": "Test risk",
                "likelihood": "high",
                "impact": "high",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["risk"]["risk_level"] == "critical"

    def test_compliance_report(self):
        client = TestClient(app)
        resp = client.get("/compliance")
        assert resp.status_code == 200
        data = resp.json()
        assert "compliance_percentage" in data
        assert "overall_status" in data

    def test_implement_control(self):
        client = TestClient(app)
        resp = client.post(
            "/controls/A.8.2/implement",
            json={"control_id": "A.8.2", "evidence": "API test evidence"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["control"]["implemented"] is True

    def test_record_incident(self):
        client = TestClient(app)
        resp = client.post(
            "/incidents",
            json={
                "title": "API Test Incident",
                "description": "Test incident via API",
                "severity": "medium",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["incident"]["severity"] == "medium"

    def test_verify_evidence(self):
        client = TestClient(app)
        resp = client.get("/evidence/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert "valid" in data


class TestCompetitiveLandscape:
    def test_list_systems(self):
        client = TestClient(app)
        resp = client.get("/competitive-landscape")
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert "systems" in data
        assert data["summary"]["total"] >= 1


class TestUnitEconomics:
    def test_compute(self):
        client = TestClient(app)
        resp = client.post(
            "/unit-economics",
            json={
                "system_type": "software_only",
                "capital_cost_usd": 250_000,
                "annual_engagements": 1_000,
                "service_life_years": 5,
                "marginal_cost_usd": 0.0,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_cost_per_engagement_usd"] >= 0.0


class TestSwarm:
    def test_simulate(self):
        client = TestClient(app)
        resp = client.post(
            "/swarm/simulate",
            json={"num_drones": 8, "spread_s": 10.0, "speed_mps": 30.0, "evasion": 0.3},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tracks_generated"] == 8
        assert "leak_rate" in data


class TestBenchmarks:
    def test_run(self):
        client = TestClient(app)
        resp = client.get("/benchmarks")
        assert resp.status_code == 200
        data = resp.json()
        assert "scheduler" in data
        assert "ekf" in data
        assert "end_to_end" in data


class TestOpenDEW:
    def test_classify(self):
        client = TestClient(app)
        resp = client.post("/detection/opendew")
        assert resp.status_code == 200
        data = resp.json()
        assert "predicted_class" in data
        assert "available" in data
