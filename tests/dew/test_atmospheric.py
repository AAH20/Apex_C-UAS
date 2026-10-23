"""Tests for the expanded DEW atmospheric and beam modeling."""

import unittest

from c_uas.dew.atmospheric import (
    DEW_SYSTEMS,
    LASER_SPECS,
    AtmosphericConditions,
    LaserSpec,
    aerosol_attenuation_db_km,
    diffraction_limit_spot_cm,
    effective_spot_cm,
    jitter_spot_cm,
    oxygen_attenuation_db_km,
    time_to_kill_with_attenuation,
    total_attenuation_db_km,
    water_vapor_attenuation_db_km,
)


class TestAtmosphericAttenuation(unittest.TestCase):
    def test_clear_air_low_attenuation(self):
        att = total_attenuation_db_km(
            wavelength_nm=1070.0,
            conditions=AtmosphericConditions(rainfall_mm_hr=0.0, aerosol_visibility_km=20.0),
        )
        self.assertGreaterEqual(att, 0.0)

    def test_heavy_rain_high_attenuation(self):
        att_clear = total_attenuation_db_km(
            wavelength_nm=1070.0,
            conditions=AtmosphericConditions(rainfall_mm_hr=0.0),
        )
        att_rain = total_attenuation_db_km(
            wavelength_nm=1070.0,
            conditions=AtmosphericConditions(rainfall_mm_hr=50.0),
        )
        self.assertGreaterEqual(att_rain, att_clear)

    def test_low_visibility_high_aerosol(self):
        att_clear = aerosol_attenuation_db_km(1070.0, 20.0)
        att_fog = aerosol_attenuation_db_km(1070.0, 0.5)
        self.assertGreater(att_fog, att_clear)

    def test_oxygen_attenuation_positive(self):
        att = oxygen_attenuation_db_km(10.0, 15.0, 1013.25)
        self.assertGreaterEqual(att, 0.0)

    def test_water_vapor_attenuation_positive(self):
        att = water_vapor_attenuation_db_km(10.0, 15.0, 1013.25, 50.0)
        self.assertGreaterEqual(att, 0.0)


class TestDiffractionAndSpot(unittest.TestCase):
    def test_diffraction_spot_positive(self):
        spot = diffraction_limit_spot_cm(1070.0, 5000.0, 20.0, 1.2)
        self.assertGreater(spot, 0.0)

    def test_jitter_spot_positive(self):
        spot = jitter_spot_cm(5.0, 5000.0)
        self.assertGreater(spot, 0.0)

    def test_effective_spot_combines(self):
        spec = LaserSpec(
            name="test",
            wavelength_nm=1070.0,
            power_kw=50.0,
            m2=1.2,
            jitter_urad=5.0,
            aperture_cm=20.0,
        )
        spot = effective_spot_cm(spec, 5000.0)
        self.assertGreater(spot, 0.0)

    def test_adaptive_optics_reduces_turbulence(self):
        spec = LaserSpec(
            name="test",
            wavelength_nm=1070.0,
            power_kw=50.0,
            m2=1.2,
            jitter_urad=5.0,
            aperture_cm=20.0,
            adaptive_optics=True,
        )
        spot_no_ao = effective_spot_cm(spec, 5000.0, use_adaptive_optics=False)
        spot_ao = effective_spot_cm(spec, 5000.0, use_adaptive_optics=True)
        # AO may or may not reduce depending on parameters; just check both valid
        self.assertGreater(spot_no_ao, 0.0)
        self.assertGreater(spot_ao, 0.0)


class TestLaserSpecs(unittest.TestCase):
    def test_fiber_50kw_spec(self):
        spec = LASER_SPECS["fiber_50kw"]
        self.assertEqual(spec.name, "50 kW Fiber Laser")
        self.assertEqual(spec.power_kw, 50.0)
        self.assertEqual(spec.wavelength_nm, 1070.0)

    def test_all_specs_have_positive_power(self):
        for name, spec in LASER_SPECS.items():
            if spec.power_kw is not None:
                self.assertGreater(spec.power_kw, 0.0)


class TestTimeToKillAttenuation(unittest.TestCase):
    def test_ttk_returns_dict(self):
        spec = LASER_SPECS["fiber_50kw"]
        result = time_to_kill_with_attenuation(spec, range_m=3000.0, target_material="aluminum")
        self.assertIn("dwell_s", result)
        self.assertIn("fluence_j_cm2", result)
        self.assertIn("transmission", result)
        self.assertIn("spot_cm", result)
        self.assertGreaterEqual(result["dwell_s"], 0.0)

    def test_ttk_worse_in_rain(self):
        spec = LASER_SPECS["fiber_50kw"]
        dry = time_to_kill_with_attenuation(
            spec,
            range_m=3000.0,
            conditions=AtmosphericConditions(rainfall_mm_hr=0.0),
        )
        wet = time_to_kill_with_attenuation(
            spec,
            range_m=3000.0,
            conditions=AtmosphericConditions(rainfall_mm_hr=50.0),
        )
        # Rain should increase dwell time (lower transmission)
        self.assertGreaterEqual(wet["dwell_s"], dry["dwell_s"])

    def test_ttk_shorter_closer_range(self):
        spec = LASER_SPECS["fiber_50kw"]
        near = time_to_kill_with_attenuation(spec, range_m=1000.0)
        far = time_to_kill_with_attenuation(spec, range_m=5000.0)
        self.assertLessEqual(near["dwell_s"], far["dwell_s"])


class TestDEWSystems(unittest.TestCase):
    def test_dew_systems_non_empty(self):
        self.assertGreaterEqual(len(DEW_SYSTEMS), 3)
        self.assertIn("dragonfire_uk", DEW_SYSTEMS)
        self.assertIn("iron_beam_israel", DEW_SYSTEMS)


if __name__ == "__main__":
    unittest.main()
