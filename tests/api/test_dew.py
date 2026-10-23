"""Tests for the /dew/model API endpoint (directed-energy beam modeling)."""

from fastapi.testclient import TestClient

from c_uas.api.server import app


class TestDewModel:
    def setup_method(self):
        self.client = TestClient(app)

    def test_dew_model_defaults(self):
        resp = self.client.post(
            "/dew/model",
            json={"laser": "fiber_50kw", "range_m": 3000, "material": "aluminum"},
        )
        assert resp.status_code == 200
        data = resp.json()
        for key in (
            "dwell_s",
            "fluence_j_cm2",
            "required_fluence_j_cm2",
            "transmission",
            "attenuation_db_km",
            "spot_cm",
            "range_m",
            "material",
            "laser",
        ):
            assert key in data, f"missing key {key}"
        assert data["range_m"] == 3000
        assert data["material"] == "aluminum"
        assert data["laser"] == "50 kW Fiber Laser"
        assert data["spot_cm"] > 0.0
        assert 0.0 < data["transmission"] <= 1.0
        assert data["dwell_s"] > 0.0

    def test_dew_model_spot_grows_with_range(self):
        near = self.client.post(
            "/dew/model", json={"laser": "fiber_50kw", "range_m": 1000, "material": "aluminum"}
        ).json()
        far = self.client.post(
            "/dew/model", json={"laser": "fiber_50kw", "range_m": 5000, "material": "aluminum"}
        ).json()
        # Diffraction, jitter, and turbulence terms all scale with range,
        # so the effective spot diameter must grow with range.
        assert far["spot_cm"] > near["spot_cm"]

    def test_dew_model_higher_power_smaller_dwell(self):
        low = self.client.post(
            "/dew/model", json={"laser": "fiber_50kw", "range_m": 3000, "material": "aluminum"}
        ).json()
        high = self.client.post(
            "/dew/model", json={"laser": "solid_state_150kw", "range_m": 3000, "material": "aluminum"}
        ).json()
        assert high["dwell_s"] < low["dwell_s"]

    def test_dew_model_rain_cuts_transmission(self):
        dry = self.client.post(
            "/dew/model",
            json={"laser": "fiber_50kw", "range_m": 3000, "material": "aluminum", "rain_mm_hr": 0.0},
        ).json()
        wet = self.client.post(
            "/dew/model",
            json={"laser": "fiber_50kw", "range_m": 3000, "material": "aluminum", "rain_mm_hr": 50.0},
        ).json()
        assert wet["transmission"] < dry["transmission"]

    def test_dew_model_unknown_laser(self):
        resp = self.client.post(
            "/dew/model", json={"laser": "no_such_laser", "range_m": 3000}
        )
        assert resp.status_code == 400
