"""C-UAS Red Team Adversarial Testing Framework.

Simulates drone attacks (GNSS spoofing/meaconing/replay, RF jamming/barrage/
deceptive, controller hijacking/MAVLink injection, swarm saturation, identity
spoofing, man-in-the-middle) to validate platform detection, tracking, and
engagement defenses under adversarial conditions.

Defensive only: synthetic attack telemetry is fed into real platform
detectors. No exploitation code, no live RF, no effector control.

State persists under ~/.c-uas-platform/red_team/ (outside the repo).
"""

from .attack_simulator import AttackSimulator, ScenarioResult
from .campaign import (
    Campaign,
    CampaignResult,
    CampaignRunner,
    CampaignStore,
    build_default_campaign,
    campaign_id_for,
    run_default_campaign,
)
from .report import (
    RedTeamReport,
    ReportStore,
    compute_passed,
    generate_report,
    run_all_scenarios,
    sid_lookup,
)
from .scenarios import (
    ALL_SCENARIOS,
    SCENARIO_BY_ID,
    AdversarialScenario,
    AttackResult,
    Scenario,
    ScenarioStore,
    default_store,
)

__all__ = [
    "AdversarialScenario",
    "AttackResult",
    "AttackSimulator",
    "Campaign",
    "CampaignResult",
    "CampaignRunner",
    "CampaignStore",
    "RedTeamReport",
    "ReportStore",
    "Scenario",
    "ScenarioResult",
    "ScenarioStore",
    "ALL_SCENARIOS",
    "SCENARIO_BY_ID",
    "default_store",
    "build_default_campaign",
    "campaign_id_for",
    "run_default_campaign",
    "compute_passed",
    "generate_report",
    "run_all_scenarios",
    "sid_lookup",
]
