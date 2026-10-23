"""
Unit Economics Model for Counter-UAS Systems.

Computes cost-per-engagement (CPE), cost-exchange ratio, marginal cost curves,
and capital amortization for deployed vs. software-only C-UAS approaches.

All inputs are illustrative estimates derived from public disclosures and
academic studies (SSRN cost-effectiveness analysis, drone-warfare.com cost
data, vendor documentation). Labeled illustrative per grounding policy — no
revenue, customer count, or AUM exists for this project.

Usage:
    from c_uas.unit_economics import UnitEconomicsModel, EngagementParams
    model = UnitEconomicsModel()
    result = model.cost_per_engagement(system_type="directed_energy_laser", ...)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class EngagementParams:
    """Parameters for a single engagement cost calculation."""

    system_type: str  # "directed_energy_laser", "kinetic_missile", "rf_jamming", "rf_detection", "software_only"
    capital_cost_usd: float  # system acquisition cost
    annual_engagements: int  # expected engagements per year
    service_life_years: int  # system service life
    marginal_cost_usd: float  # per-engagement consumable cost (missile, fuel, power)
    electricity_kwh_per_engagement: float = 0.0  # for directed energy
    electricity_cost_usd_per_kwh: float = 0.12  # industrial rate


@dataclass(frozen=True)
class EngagementEconomics:
    """Result of a unit economics calculation."""

    system_type: str
    capital_amortized_per_engagement_usd: float
    marginal_cost_per_engagement_usd: float
    total_cost_per_engagement_usd: float
    cost_exchange_ratio_vs_drone: float  # CPE / attacker drone cost
    annual_cost_usd: float
    lifetime_cost_usd: float


@dataclass(frozen=True)
class ScalePoint:
    """A single point on an economies-of-scale curve."""

    deployments: int
    total_capital_usd: float
    total_annual_cost_usd: float
    amortized_capital_per_site_usd: float
    marginal_cost_per_engagement_usd: float
    total_cost_per_engagement_usd: float


class UnitEconomicsModel:
    """
    Computes unit economics for counter-UAS engagements.

    Model:
      CAC = capital_cost_usd / (annual_engagements * service_life_years)
      CPE = CAC + marginal_cost_per_engagement
      CER = CPE / attacker_drone_cost_usd  (cost-exchange ratio; <1 is favorable)
    """

    DEFAULT_DRONE_COST_USD = 5_000  # illustrative: low-cost drone threat

    def __init__(self, attacker_drone_cost_usd: float = DEFAULT_DRONE_COST_USD) -> None:
        self.attacker_drone_cost_usd = attacker_drone_cost_usd

    def cost_per_engagement(self, params: EngagementParams) -> EngagementEconomics:
        """Compute full unit economics for one system type."""
        capital_per_year = params.capital_cost_usd / params.service_life_years
        capital_amortized = capital_per_year / params.annual_engagements
        total_cpe = capital_amortized + params.marginal_cost_usd
        annual_cost = capital_per_year + (params.marginal_cost_usd * params.annual_engagements)
        lifetime_cost = annual_cost * params.service_life_years
        cer = (
            total_cpe / self.attacker_drone_cost_usd
            if self.attacker_drone_cost_usd > 0
            else float("inf")
        )

        return EngagementEconomics(
            system_type=params.system_type,
            capital_amortized_per_engagement_usd=round(capital_amortized, 2),
            marginal_cost_per_engagement_usd=round(params.marginal_cost_usd, 2),
            total_cost_per_engagement_usd=round(total_cpe, 2),
            cost_exchange_ratio_vs_drone=round(cer, 4),
            annual_cost_usd=round(annual_cost, 2),
            lifetime_cost_usd=round(lifetime_cost, 2),
        )

    def directed_energy_laser(
        self,
        capital_cost_usd: float = 50_000_000,
        annual_engagements: int = 500,
        service_life_years: int = 10,
        electricity_kwh_per_engagement: float = 500.0,
    ) -> EngagementEconomics:
        """DEW: high capital, near-zero marginal (electricity only)."""
        marginal = electricity_kwh_per_engagement * 0.12  # $0.12/kWh
        return self.cost_per_engagement(
            EngagementParams(
                system_type="directed_energy_laser",
                capital_cost_usd=capital_cost_usd,
                annual_engagements=annual_engagements,
                service_life_years=service_life_years,
                marginal_cost_usd=marginal,
                electricity_kwh_per_engagement=electricity_kwh_per_engagement,
            )
        )

    def kinetic_missile(
        self,
        capital_cost_usd: float = 1_000_000,
        annual_engagements: int = 50,
        service_life_years: int = 15,
        missile_cost_usd: float = 120_000,
    ) -> EngagementEconomics:
        """Kinetic: lower capital, high marginal (expendable interceptor)."""
        return self.cost_per_engagement(
            EngagementParams(
                system_type="kinetic_missile",
                capital_cost_usd=capital_cost_usd,
                annual_engagements=annual_engagements,
                service_life_years=service_life_years,
                marginal_cost_usd=missile_cost_usd,
            )
        )

    def rf_jamming(
        self,
        capital_cost_usd: float = 150_000,
        annual_engagements: int = 200,
        service_life_years: int = 7,
        marginal_cost_usd: float = 2.0,
    ) -> EngagementEconomics:
        """RF jamming: moderate capital, very low marginal (power only)."""
        return self.cost_per_engagement(
            EngagementParams(
                system_type="rf_jamming",
                capital_cost_usd=capital_cost_usd,
                annual_engagements=annual_engagements,
                service_life_years=service_life_years,
                marginal_cost_usd=marginal_cost_usd,
            )
        )

    def software_only(
        self,
        development_cost_usd: float = 250_000,
        annual_engagements: int = 1_000,
        service_life_years: int = 5,
        marginal_cost_usd: float = 0.0,
    ) -> EngagementEconomics:
        """Software-only platform (this repo): dev cost only, zero marginal."""
        return self.cost_per_engagement(
            EngagementParams(
                system_type="software_only",
                capital_cost_usd=development_cost_usd,
                annual_engagements=annual_engagements,
                service_life_years=service_life_years,
                marginal_cost_usd=marginal_cost_usd,
            )
        )

    def compare_all(self) -> Dict[str, EngagementEconomics]:
        """Run all four system-type models and return keyed by type."""
        return {
            "directed_energy_laser": self.directed_energy_laser(),
            "kinetic_missile": self.kinetic_missile(),
            "rf_jamming": self.rf_jamming(),
            "software_only": self.software_only(),
        }


class EconomiesOfScaleModel:
    """
    Models how unit economics change with deployment scale.

    For hardware systems: capital cost is fixed per site; more sites = more
    total capital but same per-site economics.
    For software-only: development cost is amortized across unlimited sites;
    marginal cost per additional deployment approaches zero.
    """

    def __init__(self, model: UnitEconomicsModel) -> None:
        self.model = model

    def scale_curve(
        self,
        system_type: str,
        max_deployments: int = 100,
        step: int = 10,
        capital_per_site_usd: float = 1_000_000,
        marginal_per_engagement_usd: float = 100.0,
        engagements_per_site_per_year: int = 100,
        service_life_years: int = 10,
    ) -> List[ScalePoint]:
        """Generate scale curve points for a hardware system type."""
        points: List[ScalePoint] = []
        for deployments in range(step, max_deployments + 1, step):
            total_capital = capital_per_site_usd * deployments
            total_annual_engagements = deployments * engagements_per_site_per_year
            total_annual_cost = (
                capital_per_site_usd / service_life_years
            ) * deployments + marginal_per_engagement_usd * total_annual_engagements
            amortized_per_site = (
                capital_per_site_usd  # capital is per-site, doesn't amortize across sites
            )
            marginal = marginal_per_engagement_usd
            total_cpe = (
                capital_per_site_usd / (service_life_years * engagements_per_site_per_year)
            ) + marginal
            points.append(
                ScalePoint(
                    deployments=deployments,
                    total_capital_usd=total_capital,
                    total_annual_cost_usd=round(total_annual_cost, 2),
                    amortized_capital_per_site_usd=round(amortized_per_site, 2),
                    marginal_cost_per_engagement_usd=round(marginal, 2),
                    total_cost_per_engagement_usd=round(total_cpe, 2),
                )
            )
        return points

    def software_scale_curve(
        self,
        development_cost_usd: float = 250_000,
        max_deployments: int = 1000,
        step: int = 100,
        marginal_per_deployment_usd: float = 0.0,
        engagements_per_site_per_year: int = 100,
        service_life_years: int = 5,
    ) -> List[ScalePoint]:
        """Software-only scale curve: dev cost amortized across all deployments."""
        points: List[ScalePoint] = []
        for deployments in range(step, max_deployments + 1, step):
            total_capital = development_cost_usd  # one-time dev cost, not per site
            total_annual_engagements = deployments * engagements_per_site_per_year
            total_annual_cost = (
                development_cost_usd / service_life_years
                + marginal_per_deployment_usd * deployments
            )
            amortized_capital_per_site = development_cost_usd / deployments
            total_cpe = (
                (development_cost_usd / service_life_years) / total_annual_engagements
                + marginal_per_deployment_usd / engagements_per_site_per_year
            )
            points.append(
                ScalePoint(
                    deployments=deployments,
                    total_capital_usd=total_capital,
                    total_annual_cost_usd=round(total_annual_cost, 2),
                    amortized_capital_per_site_usd=round(amortized_capital_per_site, 4),
                    marginal_cost_per_engagement_usd=round(
                        marginal_per_deployment_usd / engagements_per_site_per_year, 6
                    ),
                    total_cost_per_engagement_usd=round(total_cpe, 6),
                )
            )
        return points
