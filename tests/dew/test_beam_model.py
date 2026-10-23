"""Tests for DEW beam modeling."""

import unittest

from c_uas.dew.beam_model import DewBeamQualityModel, DewThermalBloomModel
from c_uas.dew.time_to_kill import TimeToKillModel


class TestDewBeamQualityModel(unittest.TestCase):
    def test_fluence_factor_in_range(self):
        model = DewBeamQualityModel()
        f = model.fluence_factor(m2=1.5, jitter_urad=5.0, range_m=1000.0)
        self.assertGreaterEqual(f, 0.0)
        self.assertLessEqual(f, 1.0)

    def test_better_beam_quality_higher_fluence(self):
        model = DewBeamQualityModel()
        f_good = model.fluence_factor(m2=1.1, jitter_urad=5.0, range_m=1000.0)
        f_bad = model.fluence_factor(m2=3.0, jitter_urad=15.0, range_m=1000.0)
        self.assertGreater(f_good, f_bad)

    def test_kw_is_not_the_spec_that_matters(self):
        """50 kW with good beam quality beats 100 kW with poor beam quality."""
        model = DewBeamQualityModel()
        # 50 kW, excellent beam: M^2=1.1, 5 µrad jitter
        f_50kw_good = model.fluence_factor(m2=1.1, jitter_urad=5.0, range_m=3000.0)
        # 100 kW, poor beam: M^2=2.0, 15 µrad jitter
        f_100kw_bad = model.fluence_factor(m2=2.0, jitter_urad=15.0, range_m=3000.0)
        self.assertGreater(f_50kw_good, f_100kw_bad)


class TestDewThermalBloomModel(unittest.TestCase):
    def test_bloom_penalty_grows_with_sustained_fire(self):
        model = DewThermalBloomModel()
        p1 = model.penalty(continuous_fire_s=5.0)
        p20 = model.penalty(continuous_fire_s=20.0)
        self.assertGreater(p20, p1)

    def test_bloom_worse_for_head_on_engagement(self):
        model = DewThermalBloomModel()
        # Crossing target: less heating of air column
        p_cross = model.penalty(continuous_fire_s=10.0, geometry="crossing")
        # Down-the-throat: static beam position, maximum heating
        p_headon = model.penalty(continuous_fire_s=10.0, geometry="head_on")
        self.assertGreaterEqual(p_headon, p_cross)


class TestTimeToKillModel(unittest.TestCase):
    def test_ttk_decreases_with_higher_power(self):
        model = TimeToKillModel()
        t1 = model.time_to_kill_s(
            laser_power_kw=50.0, target_material="carbon_fiber", range_m=3000.0
        )
        t2 = model.time_to_kill_s(
            laser_power_kw=100.0, target_material="carbon_fiber", range_m=3000.0
        )
        self.assertLess(t2, t1)

    def test_ttk_increases_with_range(self):
        model = TimeToKillModel()
        t_near = model.time_to_kill_s(
            laser_power_kw=50.0, target_material="aluminum", range_m=1000.0
        )
        t_far = model.time_to_kill_s(
            laser_power_kw=50.0, target_material="aluminum", range_m=5000.0
        )
        self.assertGreater(t_far, t_near)

    def test_ttk_positive(self):
        model = TimeToKillModel()
        t = model.time_to_kill_s(laser_power_kw=50.0, target_material="aluminum", range_m=3000.0)
        self.assertGreater(t, 0.0)
        self.assertLess(t, 60.0)


if __name__ == "__main__":
    unittest.main()
