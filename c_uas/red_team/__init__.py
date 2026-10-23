"""C-UAS Red Team Adversarial Testing Framework.

Simulates drone attacks (GNSS spoofing, RF jamming, swarm saturation,
coordinated multi-vector attacks, controller hijacking) to validate platform
detection, tracking, and engagement defenses under adversarial conditions.

Defensive only: synthetic attack telemetry is fed into real platform
detectors. No exploitation code, no live RF, no effector control.

State persists under ~/.c-uas-platform/red_team/ (outside the repo).
"""

from .attack_simulator import AttackResult, AttackSimulator
from .report import (
    RedTeamReport,
    ReportStore,
    generate_report,
    run_all_scenarios,
)
from .scenarios import (
    ALL_SCENARIOS,
    SCENARIO_BY_ID,
    AdversarialScenario,
    ScenarioStore,
    default_store,
)

__all__ = [
    "AdversarialScenario",
    "AttackResult",
    "AttackSimulator",
    "RedTeamReport",
    "ReportStore",
    "ScenarioStore",
    "ALL_SCENARIOS",
    "SCENARIO_BY_ID",
    "default_store",
    "generate_report",
    "run_all_scenarios",
]
