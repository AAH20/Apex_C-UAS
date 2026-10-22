"""Tests for the unit economics model."""

import unittest
from c_uas.unit_economics import (
    EngagementParams,
    EngagementEconomics,
    EconomiesOfScaleModel,
    UnitEconomicsModel,
)


class TestUnitEconomicsModel(unittest.TestCase):
    def setUp(self):
        self.model = UnitEconomicsModel(attacker_drone_cost_usd=5000.0)

    def test_cost_per_engagement_structure(self):
        params = EngagementParams(
            system_type="test",
            capital_cost_usd=100_000,
            annual_engagements=100,
            service_life_years=5,
            marginal_cost_usd=10.0,
        )
        result = self.model.cost_per_engagement(params)
        self.assertIsInstance(result, EngagementEconomics)
        self.assertEqual(result.system_type, "test")
        self.assertGreater(result.total_cost_per_engagement_usd, 0)
        self.assertGreater(result.cost_exchange_ratio_vs_drone, 0)

    def test_capital_amortization(self):
        # $100k capital, 100 engagements/year, 5 years life
        # $20k/year capital / 100 engagements = $200 per engagement capital
        params = EngagementParams(
            system_type="test",
            capital_cost_usd=100_000,
            annual_engagements=100,
            service_life_years=5,
            marginal_cost_usd=10.0,
        )
        result = self.model.cost_per_engagement(params)
        self.assertEqual(result.capital_amortized_per_engagement_usd, 200.0)
        self.assertEqual(result.marginal_cost_per_engagement_usd, 10.0)
        self.assertEqual(result.total_cost_per_engagement_usd, 210.0)

    def test_cost_exchange_ratio(self):
        params = EngagementParams(
            system_type="test",
            capital_cost_usd=100_000,
            annual_engagements=100,
            service_life_years=5,
            marginal_cost_usd=10.0,
        )
        result = self.model.cost_per_engagement(params)
        # CPE $210 / $5000 drone = 0.042
        self.assertAlmostEqual(result.cost_exchange_ratio_vs_drone, 0.042, places=4)

    def test_directed_energy_laser(self):
        result = self.model.directed_energy_laser()
        self.assertEqual(result.system_type, "directed_energy_laser")
        self.assertEqual(result.marginal_cost_per_engagement_usd, 60.0)  # 500 kWh * $0.12
        self.assertGreater(result.total_cost_per_engagement_usd, 60.0)

    def test_kinetic_missile(self):
        result = self.model.kinetic_missile()
        self.assertEqual(result.system_type, "kinetic_missile")
        self.assertEqual(result.marginal_cost_per_engagement_usd, 120_000.0)

    def test_rf_jamming(self):
        result = self.model.rf_jamming()
        self.assertEqual(result.system_type, "rf_jamming")
        self.assertEqual(result.marginal_cost_per_engagement_usd, 2.0)

    def test_software_only(self):
        result = self.model.software_only()
        self.assertEqual(result.system_type, "software_only")
        self.assertEqual(result.marginal_cost_per_engagement_usd, 0.0)

    def test_compare_all(self):
        results = self.model.compare_all()
        self.assertEqual(set(results.keys()), {
            "directed_energy_laser", "kinetic_missile", "rf_jamming", "software_only",
        })
        # Software-only should have lowest CPE
        self.assertEqual(
            results["software_only"].total_cost_per_engagement_usd,
            min(r.total_cost_per_engagement_usd for r in results.values()),
        )


class TestEconomiesOfScaleModel(unittest.TestCase):
    def setUp(self):
        self.model = UnitEconomicsModel()
        self.scale = EconomiesOfScaleModel(self.model)

    def test_scale_curve_structure(self):
        points = self.scale.scale_curve(
            system_type="kinetic_missile",
            max_deployments=40,
            step=10,
        )
        self.assertEqual(len(points), 4)
        self.assertEqual(points[0].deployments, 10)
        self.assertEqual(points[-1].deployments, 40)

    def test_scale_curve_capital_grows_linearly(self):
        points = self.scale.scale_curve(
            system_type="kinetic_missile",
            max_deployments=40,
            step=10,
            capital_per_site_usd=1_000_000,
        )
        # Capital should grow linearly with deployments
        self.assertEqual(points[0].total_capital_usd, 10_000_000)
        self.assertEqual(points[-1].total_capital_usd, 40_000_000)

    def test_software_scale_curve_capital_amortizes(self):
        points = self.scale.software_scale_curve(
            max_deployments=1000,
            step=100,
            development_cost_usd=250_000,
        )
        self.assertEqual(len(points), 10)
        # Amortized capital per site should decrease as deployments grow
        self.assertGreater(points[0].amortized_capital_per_site_usd, points[-1].amortized_capital_per_site_usd)
        self.assertEqual(points[0].amortized_capital_per_site_usd, 2500.0)   # 250k/100
        self.assertEqual(points[-1].amortized_capital_per_site_usd, 250.0)   # 250k/1000

    def test_software_marginal_approaches_zero(self):
        points = self.scale.software_scale_curve(
            max_deployments=400,
            step=100,
            marginal_per_deployment_usd=0.0,
        )
        for p in points:
            self.assertEqual(p.marginal_cost_per_engagement_usd, 0.0)


if __name__ == "__main__":
    unittest.main()
