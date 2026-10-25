"""``c-uas engagement`` subcommand: backtest, evolution, and alpha measurement.

Usage:
    c-uas engagement --backtest --scenario swarm_8 --trials 5
    c-uas engagement --evolve --generations 10 --population-size 12 --seed 7
    c-uas engagement --alpha --scenario swarm_8 --seed 42

All subcommands are deterministic and persist results under
~/.c-uas-platform/engagement/{backtest,evolution,alpha}/.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any, Optional, Sequence

from c_uas.engagement.alpha import compute_alpha, save_alpha_result
from c_uas.engagement.backtest import (
    Scenario,
    run_backtest,
    run_sweep,
)
from c_uas.engagement.evolution import (
    EvolutionParams,
    EvolvedScheduler,
    save_evolution_result,
)


def _build_backtest_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scenario",
        choices=["swarm_4", "swarm_8", "swarm_16", "swarm_32"],
        default="swarm_8",
        help="Backtest scenario to run.",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=1,
        help="Number of deterministic trials (different seeds).",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a full multi-scenario sweep report as JSON.",
    )


def _build_evolve_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--generations",
        type=int,
        default=6,
        help="Number of evolutionary generations.",
    )
    parser.add_argument(
        "--population-size",
        type=int,
        default=10,
        help="Population size per generation.",
    )
    parser.add_argument(
        "--initial-mutation-rate",
        type=float,
        default=0.3,
        help="Starting mutation rate (decays over generations).",
    )
    parser.add_argument(
        "--final-mutation-rate",
        type=float,
        default=0.05,
        help="Final mutation rate.",
    )
    parser.add_argument(
        "--elitism-count",
        type=int,
        default=1,
        help="Number of elite individuals carried forward each generation.",
    )
    parser.add_argument(
        "--tournament-size",
        type=int,
        default=3,
        help="Tournament size for parent selection.",
    )
    parser.add_argument(
        "--dwell-s",
        type=float,
        default=4.0,
        help="Base dwell seconds per target.",
    )
    parser.add_argument(
        "--slew-s",
        type=float,
        default=1.5,
        help="Base slew seconds per hand-off.",
    )
    parser.add_argument(
        "--num-drones",
        type=int,
        default=6,
        help="Number of drones in each evaluation scenario.",
    )
    parser.add_argument(
        "--time-limit",
        type=float,
        default=30.0,
        help="Time limit in seconds for each scheduler run.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic RNG seed.",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print the full evolution result as JSON.",
    )


def _build_alpha_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scenario",
        choices=["swarm_4", "swarm_8", "swarm_16", "swarm_32"],
        default="swarm_8",
        help="Scenario used to derive scheduler/counterfactual Pk values.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Scenario seed (deterministic).",
    )
    parser.add_argument(
        "--bootstrap",
        type=int,
        default=2000,
        help="Number of deterministic bootstrap replicates.",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print the alpha result as JSON.",
    )


def _handle_backtest(args: argparse.Namespace) -> int:
    scenario_map = {
        "swarm_4": Scenario(name="swarm_4", num_drones=4, time_limit_s=25.0, seed=42),
        "swarm_8": Scenario(name="swarm_8", num_drones=8, time_limit_s=40.0, seed=42),
        "swarm_16": Scenario(name="swarm_16", num_drones=16, time_limit_s=60.0, seed=42),
        "swarm_32": Scenario(name="swarm_32", num_drones=32, time_limit_s=90.0, seed=42),
    }

    if args.report:
        scenarios = [
            Scenario(
                name=f"swarm_{n}",
                num_drones=n,
                time_limit_s=max(25.0, n * 3.0),
                seed=s,
            )
            for n, s in [(4, 1), (8, 42), (16, 123), (32, 456)]
        ]
        report = run_sweep(scenarios)
        print(json.dumps(report, indent=2))
        return 0

    scenario = scenario_map[args.scenario]
    results = []
    for trial in range(args.trials):
        s = Scenario(
            name=scenario.name,
            num_drones=scenario.num_drones,
            time_limit_s=scenario.time_limit_s,
            seed=scenario.seed + trial,
            dwell_s=scenario.dwell_s,
            slew_s=scenario.slew_s,
            thermal_bloom=scenario.thermal_bloom,
            pk_min=scenario.pk_min,
            pk_max=scenario.pk_max,
        )
        results.append(run_backtest(s))

    alpha_wins = sum(1 for r in results if r["alpha_determination"]["alpha_claimed"])
    print(
        json.dumps(
            {
                "scenario": scenario.name,
                "trials": args.trials,
                "alpha_claimed_count": alpha_wins,
                "alpha_claim_rate": round(alpha_wins / args.trials, 4),
                "results": results,
            },
            indent=2,
        )
    )
    return 0


def _handle_evolve(args: argparse.Namespace) -> int:
    params = EvolutionParams(
        population_size=args.population_size,
        generations=args.generations,
        initial_mutation_rate=args.initial_mutation_rate,
        final_mutation_rate=args.final_mutation_rate,
        elitism_count=args.elitism_count,
        tournament_size=args.tournament_size,
        seed=args.seed,
        dwell_s=args.dwell_s,
        slew_s=args.slew_s,
        num_drones=args.num_drones,
        time_limit_s=args.time_limit,
    )
    engine = EvolvedScheduler(
        population_size=params.population_size,
        generations=params.generations,
        initial_mutation_rate=params.initial_mutation_rate,
        final_mutation_rate=params.final_mutation_rate,
        elitism_count=params.elitism_count,
        tournament_size=params.tournament_size,
        dwell_s=params.dwell_s,
        slew_s=params.slew_s,
        num_drones=params.num_drones,
        time_limit_s=params.time_limit_s,
        leak_penalty=params.leak_penalty,
        seed=params.seed,
    )
    result = engine.evolve()
    save_evolution_result(params, result)
    print(json.dumps(result, indent=2))
    return 0


def _handle_alpha(args: argparse.Namespace) -> int:
    # Derive scheduler and counterfactual Pk from a single backtest run so the
    # alpha measurement is grounded in real computed values (never fabricated).
    scenario_map = {
        "swarm_4": Scenario(name="swarm_4", num_drones=4, time_limit_s=25.0, seed=42),
        "swarm_8": Scenario(name="swarm_8", num_drones=8, time_limit_s=40.0, seed=42),
        "swarm_16": Scenario(name="swarm_16", num_drones=16, time_limit_s=60.0, seed=42),
        "swarm_32": Scenario(name="swarm_32", num_drones=32, time_limit_s=90.0, seed=42),
    }
    scenario = scenario_map[args.scenario]
    backtest_result = run_backtest(scenario)

    scheduler_pk = backtest_result["scheduler"]["expected_kills"]
    controls = backtest_result["controls"]
    # Exclude the scheduler itself; counterfactuals only.
    counterfactuals = [c for c in controls if c["control_name"] != "scheduler"]
    control_pks = [c["expected_kills"] for c in counterfactuals]
    control_names = [c["control_name"] for c in counterfactuals]

    result = compute_alpha(
        scheduler_pk=scheduler_pk,
        control_pks=control_pks,
        control_names=control_names,
        seed=args.seed,
        n_bootstrap=args.bootstrap,
    )
    result = AlphaResult_with_scenario(result, scenario.name, args.seed)
    save_alpha_result(result)
    print(json.dumps(asdict(result), indent=2))
    return 0


def AlphaResult_with_scenario(result: Any, scenario_name: str, seed: int) -> Any:
    """Re-package a compute_alpha result with scenario metadata."""
    from c_uas.engagement.alpha import AlphaResult

    return AlphaResult(
        scenario_name=scenario_name,
        seed=seed,
        scheduler_pk=result.scheduler_pk,
        best_counterfactual_pk=result.best_counterfactual_pk,
        alpha=result.alpha,
        p_value=result.p_value,
        significant=result.significant,
        n_bootstrap=result.n_bootstrap,
        bootstrap_mean=result.bootstrap_mean,
        bootstrap_std=result.bootstrap_std,
        bootstrap_ci_lower=result.bootstrap_ci_lower,
        bootstrap_ci_upper=result.bootstrap_ci_upper,
        control_pks=result.control_pks,
    )


def build_subparser(subparsers: Any) -> Any:
    """Register the ``engagement`` subcommand on a parent parser."""
    parser = subparsers.add_parser(
        "engagement",
        help=(
            "Engagement scheduler backtest, evolutionary tuning, and alpha "
            "measurement against counterfactual baselines"
        ),
    )
    sub = parser.add_subparsers(dest="engagement_command", help="Engagement modes")

    bt = sub.add_parser("backtest", help="Run counterfactual alpha backtest")
    _build_backtest_parser(bt)

    ev = sub.add_parser("evolve", help="Run evolutionary scheduler tuning")
    _build_evolve_parser(ev)

    al = sub.add_parser("alpha", help="Measure scheduler alpha vs counterfactuals")
    _build_alpha_parser(al)

    return parser


def engagement_main(argv: Optional[Sequence[str]] = None) -> int:
    """Dispatch engagement CLI modes: --backtest / --evolve / --alpha."""
    parser = argparse.ArgumentParser(
        prog="c-uas engagement",
        description=(
            "C-UAS engagement scheduler: backtest against counterfactual "
            "controls, evolutionary parameter tuning, and alpha measurement."
        ),
    )
    sub = parser.add_subparsers(dest="engagement_command")

    bt = sub.add_parser("backtest", help="Run counterfactual alpha backtest")
    _build_backtest_parser(bt)

    ev = sub.add_parser("evolve", help="Run evolutionary scheduler tuning")
    _build_evolve_parser(ev)

    al = sub.add_parser("alpha", help="Measure scheduler alpha vs counterfactuals")
    _build_alpha_parser(al)

    args = parser.parse_args(argv)

    if args.engagement_command == "backtest":
        return _handle_backtest(args)
    if args.engagement_command == "evolve":
        return _handle_evolve(args)
    if args.engagement_command == "alpha":
        return _handle_alpha(args)

    parser.print_help()
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Standalone entry point for ``python -m c_uas.engagement.cli``."""
    return engagement_main(argv)


if __name__ == "__main__":
    sys.exit(main())
