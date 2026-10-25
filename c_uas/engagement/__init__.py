"""NP-hard engagement scheduler sub-package.

Modules:
  * scheduler   — NP-hard engagement scheduler (Pk-per-second greedy)
  * constraints — thermal bloom, beam quality, and dwell-time physics models
  * backtest    — deterministic counterfactual alpha backtest harness
  * evolution   — (mu + lambda) evolutionary scheduler tuner
  * alpha       — scheduler alpha vs counterfactuals with deterministic bootstrap
  * cli         --backtest / --evolve / --alpha subcommands
"""

from .alpha import AlphaResult, compute_alpha, measure_alpha, save_alpha_result
from .backtest import (
    ControlResult,
    Scenario,
    control_deadline_first,
    control_direction_flip,
    control_fifo,
    control_greedy_pk_only,
    control_longest_queue_first,
    control_random_entry,
    control_random_scheduler,
    control_round_robin,
    control_shortest_hold_first,
    control_shortest_job_first,
    run_backtest,
    run_scheduler,
    run_sweep,
)
from .cli import build_subparser, engagement_main, main
from .evolution import (
    EvolutionParams,
    EvolvedScheduler,
    FitnessFunction,
    Individual,
    MutationOperator,
    SelectionOperator,
    save_evolution_result,
)
from .scheduler import EngagementPlan, EngagementScheduler

__all__ = [
    "EngagementScheduler",
    "EngagementPlan",
    "Scenario",
    "run_backtest",
    "run_sweep",
    "run_scheduler",
    "ControlResult",
    "AlphaResult",
    "compute_alpha",
    "measure_alpha",
    "save_alpha_result",
    "EvolvedScheduler",
    "EvolutionParams",
    "FitnessFunction",
    "Individual",
    "MutationOperator",
    "SelectionOperator",
    "save_evolution_result",
    "build_subparser",
    "engagement_main",
    "main",
    "control_random_entry",
    "control_shortest_hold_first",
    "control_greedy_pk_only",
    "control_deadline_first",
    "control_direction_flip",
    "control_random_scheduler",
    "control_round_robin",
    "control_fifo",
    "control_longest_queue_first",
    "control_shortest_job_first",
]
