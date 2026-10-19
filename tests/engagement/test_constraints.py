"""Tests for engagement constraint models."""

import unittest
from c_uas.engagement.constraints import (
    ThermalBloomModel,
    BeamQualityModel,
    DwellModel,
)


class TestThermalBloomModel(unittest.TestCase):
    def test_bloom_increases_with_sustained_fire(self):
        model = ThermalBloomModel(base_penalty=0.05, max_penalty=0.5)
        p1 = model.penalty(targets_engaged=1)
        p5 = model.penalty(targets_engaged=5)
        self.assertGreater(p5, p1)

    def test_bloom_capped_at_max(self):
        model = ThermalBloomModel(base_penalty=0.05, max_penalty=0.3)
        p = model.penalty(targets_engaged=1000)
        self.assertAlmostEqual(p, 0.3)

    def test_zero_targets_zero_penalty(self):
        model = ThermalBloomModel()
        p = model.penalty(targets_engaged=0)
        self.assertEqual(p, 0.0)


class TestBeamQualityModel(unittest.TestCase):
    def test_higher_m2_reduces_fluence(self):
        model = BeamQualityModel()
        f_low = model.fluence_factor(m2=1.1, jitter_urad=5.0, range_m=1000.0)
        f_high = model.fluence_factor(m2=3.0, jitter_urad=15.0, range_m=1000.0)
        self.assertGreater(f_low, f_high)

    def test_higher_jitter_reduces_fluence(self):
        model = BeamQualityModel()
        f_low = model.fluence_factor(m2=1.5, jitter_urad=5.0, range_m=1000.0)
        f_high = model.fluence_factor(m2=1.5, jitter_urad=20.0, range_m=1000.0)
        self.assertGreater(f_low, f_high)

    def test_longer_range_reduces_fluence(self):
        model = BeamQualityModel()
        f_near = model.fluence_factor(m2=1.5, jitter_urad=5.0, range_m=1000.0)
        f_far = model.fluence_factor(m2=1.5, jitter_urad=5.0, range_m=5000.0)
        self.assertGreater(f_near, f_far)

    def test_fluence_factor_in_zero_one(self):
        model = BeamQualityModel()
        f = model.fluence_factor(m2=1.1, jitter_urad=1.0, range_m=100.0)
        self.assertGreaterEqual(f, 0.0)
        self.assertLessEqual(f, 1.0)


class TestDwellModel(unittest.TestCase):
    def test_dwell_time_from_power_and_energy(self):
        model = DwellModel()
        t = model.dwell_time_s(laser_power_kw=50.0, energy_required_kj=200.0, absorption=0.8)
        # Energy = Power * time => time = Energy / Power = 200 kJ / (50 kW * 0.8) = 5s
        self.assertAlmostEqual(t, 5.0, places=1)

    def test_higher_power_shorter_dwell(self):
        model = DwellModel()
        t1 = model.dwell_time_s(laser_power_kw=50.0, energy_required_kj=100.0, absorption=0.8)
        t2 = model.dwell_time_s(laser_power_kw=100.0, energy_required_kj=100.0, absorption=0.8)
        self.assertLess(t2, t1)

    def test_minimum_dwell_time(self):
        model = DwellModel(min_dwell_s=1.0)
        t = model.dwell_time_s(laser_power_kw=10000.0, energy_required_kj=1.0, absorption=1.0)
        self.assertGreaterEqual(t, 1.0)


if __name__ == "__main__":
    unittest.main()
