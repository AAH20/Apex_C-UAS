"""NP-hard engagement scheduler sub-package."""

from .scheduler import EngagementScheduler, EngagementPlan
from .backtest import (
    Scenario,
    run_backtest,
    run_sweep,
    ControlResult,
)

__all__ = [
    "EngagementScheduler",
    "EngagementPlan",
    "Scenario",
    "run_backtest",
    "run_sweep",
    "ControlResult",
]
