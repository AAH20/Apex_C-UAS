"""
Contract Readiness & Go-to-Market Analysis.

Computes burn rate, CAC:LTV, fastest route to contract, and minimized MVP
scope for the C-UAS platform. All figures are illustrative models, not
actual revenue or cost data. Labeled illustrative per grounding policy.

Usage:
    from c_uas.contract_readiness import ContractReadinessModel
    model = ContractReadinessModel()
    analysis = model.full_analysis()
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class BurnRateInput:
    """Inputs for burn rate calculation."""

    monthly_engineer_cost_usd: float = 15_000
    monthly_infra_cost_usd: float = 500  # free-tier only
    monthly_tool_cost_usd: float = 0  # no proprietary subscriptions
    num_engineers: int = 1  # founder-led
    months_of_runway: int = 12


@dataclass(frozen=True)
class BurnRateResult:
    """Burn rate calculation result."""

    monthly_burn_usd: float
    annual_burn_usd: float
    runway_months: int
    total_runway_usd: float


@dataclass(frozen=True)
class CACLTVInput:
    """Inputs for CAC:LTV calculation."""

    avg_contract_value_usd: float = 75_000
    gross_margin: float = 0.85
    customer_lifespan_years: float = 3.0
    sales_cycle_months: float = 6.0
    marketing_spend_usd: float = 5_000
    contracts_won_per_year: int = 2


@dataclass(frozen=True)
class CACLTVResult:
    """CAC:LTV calculation result."""

    cac_usd: float
    ltv_usd: float
    cac_ltv_ratio: float
    payback_months: float
    viable: bool


@dataclass(frozen=True)
class MVPFeature:
    """A single MVP feature with effort and value."""

    name: str
    effort_weeks: int
    business_value: str
    dependency: Optional[str] = None


@dataclass(frozen=True)
class MVPScope:
    """Minimized MVP scope for fastest route to contract."""

    phases: list[list[MVPFeature]]
    total_weeks: int
    earliest_contract_month: int


class ContractReadinessModel:
    """
    Models burn rate, CAC:LTV, and MVP scope for contract readiness.

    All financial figures are illustrative models, not actual data.
    """

    def __init__(self) -> None:
        pass

    def burn_rate(self, inputs: Optional[BurnRateInput] = None) -> BurnRateResult:
        """Compute monthly and annual burn rate."""
        inp = inputs or BurnRateInput()
        monthly = (
            inp.monthly_engineer_cost_usd * inp.num_engineers
            + inp.monthly_infra_cost_usd
            + inp.monthly_tool_cost_usd
        )
        annual = monthly * 12
        total_runway = monthly * inp.months_of_runway
        return BurnRateResult(
            monthly_burn_usd=round(monthly, 2),
            annual_burn_usd=round(annual, 2),
            runway_months=inp.months_of_runway,
            total_runway_usd=round(total_runway, 2),
        )

    def cac_ltv(self, inputs: Optional[CACLTVInput] = None) -> CACLTVResult:
        """Compute CAC:LTV ratio and viability."""
        inp = inputs or CACLTVInput()
        # CAC = marketing spend / contracts won per year
        cac = inp.marketing_spend_usd / max(inp.contracts_won_per_year, 1)
        # LTV = ACV * margin * lifespan
        ltv = inp.avg_contract_value_usd * inp.gross_margin * inp.customer_lifespan_years
        ratio = cac / ltv if ltv > 0 else float("inf")
        # Payback = CAC / (monthly gross profit)
        monthly_gross_profit = inp.avg_contract_value_usd * inp.gross_margin / 12.0
        payback = cac / monthly_gross_profit if monthly_gross_profit > 0 else float("inf")
        viable = ratio < 0.33  # LTV:CAC > 3:1 is healthy
        return CACLTVResult(
            cac_usd=round(cac, 2),
            ltv_usd=round(ltv, 2),
            cac_ltv_ratio=round(ratio, 4),
            payback_months=round(payback, 2),
            viable=viable,
        )

    def mvp_scope(self) -> MVPScope:
        """
        Minimized MVP for fastest route to contract.

        Phase 1: Core detection + forensics (weeks 1-4) — sellable to
                 critical infrastructure / airports
        Phase 2: Engagement scheduler + controller location (weeks 5-8)
        Phase 3: ISO 42001 governance + DEW modeling (weeks 9-12)
        """
        phases: list[list[MVPFeature]] = [
            [
                MVPFeature(
                    "RF signal classification (DJI OcuSync, MAVLink, ExpressLRS, LoRa)",
                    1,
                    "Detect drone protocols from RF emissions",
                ),
                MVPFeature(
                    "GNSS spoofing detection",
                    1,
                    "Detect GPS spoof/meaconing attacks",
                ),
                MVPFeature(
                    "Ed25519-signed forensic dossiers",
                    1,
                    "Legal-defense-grade evidence for courts / regulators",
                ),
                MVPFeature(
                    "CLI + Python API",
                    1,
                    "Integratable by system integrators",
                ),
            ],
            [
                MVPFeature(
                    "EKF trajectory prediction",
                    2,
                    "Predict drone intercept point",
                ),
                MVPFeature(
                    "Controller geolocation (TDOA / BEARING / RSSI)",
                    2,
                    "Find pilot location hundreds of km away",
                ),
                MVPFeature(
                    "NP-hard engagement scheduler",
                    2,
                    "Optimal engagement sequence under time limit",
                ),
            ],
            [
                MVPFeature(
                    "ISO 42001 AI governance chassis",
                    2,
                    "First-mover AI governance for agentic C-UAS",
                ),
                MVPFeature(
                    "DEW beam modeling (M^2, thermal bloom, attenuation)",
                    2,
                    "Directed-energy engagement analysis",
                ),
            ],
        ]
        total_weeks = sum(f.effort_weeks for phase in phases for f in phase)
        # Contract possible after Phase 1 (4 weeks) + sales cycle (2 months)
        earliest_contract_month = 3  # 1 month build + 2 month sales cycle
        return MVPScope(
            phases=phases,
            total_weeks=total_weeks,
            earliest_contract_month=earliest_contract_month,
        )

    def full_analysis(self) -> dict:
        """Run all analyses and return combined results."""
        burn = self.burn_rate()
        cac_ltv = self.cac_ltv()
        mvp = self.mvp_scope()
        return {
            "burn_rate": asdict(burn),
            "cac_ltv": asdict(cac_ltv),
            "mvp_scope": {
                "total_weeks": mvp.total_weeks,
                "earliest_contract_month": mvp.earliest_contract_month,
                "phases": [
                    [
                        {
                            "name": f.name,
                            "effort_weeks": f.effort_weeks,
                            "business_value": f.business_value,
                            "dependency": f.dependency,
                        }
                        for f in phase
                    ]
                    for phase in mvp.phases
                ],
            },
            "fastest_route_to_contract": {
                "build_weeks": mvp.total_weeks,
                "sales_cycle_months": 2,
                "earliest_contract_month": mvp.earliest_contract_month,
                "monthly_burn_usd": burn.monthly_burn_usd,
                "cac_usd": cac_ltv.cac_usd,
                "ltv_usd": cac_ltv.ltv_usd,
                "cac_ltv_viable": cac_ltv.viable,
            },
        }


def asdict(obj):  # type: ignore[no-redef]
    from dataclasses import asdict as _asdict

    return _asdict(obj)
