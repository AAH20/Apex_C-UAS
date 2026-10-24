"""Chaos / resilience testing for the C-UAS platform.

Injects faults (network latency, packet loss, backend crash, API timeout,
memory pressure) against platform components, runs deterministic chaos
scenarios, and produces a resilience report with pass/fail per scenario,
recovery time, and remediation recommendations.

Defensive only: exercises real platform modules under fault conditions. No
exploitation code, no live RF, no effector control.

State persists under ~/.c-uas-platform/chaos/ (outside the repo).
"""

from .faults import Fault, FaultInjector
from .scenarios import ChaosScenario, ChaosScenarioStore
from .runner import ChaosRunner, ChaosRunResult
from .report import ResilienceReport, ResilienceReportStore

__all__ = [
    "Fault",
    "FaultInjector",
    "ChaosScenario",
    "ChaosScenarioStore",
    "ChaosRunner",
    "ChaosRunResult",
    "ResilienceReport",
    "ResilienceReportStore",
]
