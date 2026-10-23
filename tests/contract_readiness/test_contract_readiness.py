"""Tests for contract readiness model."""

import unittest
from c_uas.contract_readiness import ContractReadinessModel, BurnRateInput, CACLTVInput


class TestBurnRate(unittest.TestCase):
    def test_default_burn_rate(self):
        model = ContractReadinessModel()
        result = model.burn_rate()
        self.assertGreater(result.monthly_burn_usd, 0.0)
        self.assertEqual(result.annual_burn_usd, result.monthly_burn_usd * 12)
        self.assertEqual(result.runway_months, 12)

    def test_custom_burn_rate(self):
        model = ContractReadinessModel()
        inp = BurnRateInput(
            monthly_engineer_cost_usd=20_000,
            num_engineers=2,
            months_of_runway=6,
        )
        result = model.burn_rate(inp)
        self.assertEqual(result.monthly_burn_usd, 40_500.0)  # 20k*2 + 500
        self.assertEqual(result.runway_months, 6)
        self.assertEqual(result.total_runway_usd, 40_500.0 * 6)

    def test_free_tier_infra(self):
        # infra and tool costs are zero by default (free-tier only)
        model = ContractReadinessModel()
        inp = BurnRateInput(num_engineers=1)
        result = model.burn_rate(inp)
        self.assertEqual(result.monthly_burn_usd, 15_500.0)  # 15k + 500


class TestCACLTV(unittest.TestCase):
    def test_default_cac_ltv(self):
        model = ContractReadinessModel()
        result = model.cac_ltv()
        self.assertGreater(result.ltv_usd, 0.0)
        self.assertGreater(result.cac_usd, 0.0)
        self.assertGreater(result.cac_ltv_ratio, 0.0)
        self.assertIsInstance(result.viable, bool)

    def test_healthy_ratio_viable(self):
        model = ContractReadinessModel()
        inp = CACLTVInput(
            avg_contract_value_usd=100_000,
            gross_margin=0.9,
            customer_lifespan_years=5.0,
            marketing_spend_usd=1_000,
            contracts_won_per_year=10,
        )
        result = model.cac_ltv(inp)
        # Low CAC, high LTV → viable
        self.assertTrue(result.viable)
        self.assertLess(result.cac_ltv_ratio, 0.33)

    def test_unhealthy_ratio_not_viable(self):
        model = ContractReadinessModel()
        inp = CACLTVInput(
            avg_contract_value_usd=10_000,
            gross_margin=0.5,
            customer_lifespan_years=1.0,
            marketing_spend_usd=50_000,
            contracts_won_per_year=1,
        )
        result = model.cac_ltv(inp)
        self.assertFalse(result.viable)
        self.assertGreaterEqual(result.cac_ltv_ratio, 0.33)


class TestMVPScope(unittest.TestCase):
    def test_mvp_has_three_phases(self):
        model = ContractReadinessModel()
        scope = model.mvp_scope()
        self.assertEqual(len(scope.phases), 3)
        self.assertGreater(scope.total_weeks, 0)
        self.assertGreater(scope.earliest_contract_month, 0)

    def test_mvp_features_have_effort_and_value(self):
        model = ContractReadinessModel()
        scope = model.mvp_scope()
        for phase in scope.phases:
            for feature in phase:
                self.assertIsInstance(feature.name, str)
                self.assertGreater(feature.effort_weeks, 0)
                self.assertIsInstance(feature.business_value, str)

    def test_full_analysis(self):
        model = ContractReadinessModel()
        analysis = model.full_analysis()
        self.assertIn("burn_rate", analysis)
        self.assertIn("cac_ltv", analysis)
        self.assertIn("mvp_scope", analysis)
        self.assertIn("fastest_route_to_contract", analysis)
        frc = analysis["fastest_route_to_contract"]
        self.assertIn("earliest_contract_month", frc)
        self.assertIn("cac_ltv_viable", frc)
