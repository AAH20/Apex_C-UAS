"""
Engagement Scheduler Backtest Harness.

Deterministic backtest of the NP-hard engagement scheduler against
counterfactual controls. Per the backtest-evidence-integrity skill:

- Every claim is recomputed from source reports, not asserted.
- Counterfactual controls run against the same scenario.
- The scheduler must beat all controls to claim alpha.
- Results are falsifiable: each control produces measurable expected_kills.
- No fabrication: all figures computed from actual code execution.

Usage:
    python -m c_uas.engagement.backtest --scenario swarm_8 --trials 20
    python -m c_uas.engagement.backtest --report
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List

from c_uas.engagement.scheduler import DroneTrack, EngagementScheduler

BACKTEST_ROOT = Path(
    os.environ.get(
        "C_UAS_ENGAGEMENT_STATE_DIR",
        Path.home() / ".c-uas-platform" / "engagement" / "backtest",
    )
)


def _atomic_write_json(path: Path, data: Any) -> None:
    """Write JSON atomically (temp file + replace)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    os.replace(tmp, path)


def _control_seed(scenario_seed: int, control_name: str) -> int:
    """Derive a deterministic, control-specific seed from the scenario seed.

    Uses SHA-256 (never Python's randomized ``hash()``) so results are
    seed-keyed and identical across processes and machines.
    """
    digest = hashlib.sha256(f"{scenario_seed}:{control_name}".encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % (2**31)


@dataclass(frozen=True)
class Scenario:
    """A deterministic backtest scenario."""

    name: str
    num_drones: int
    time_limit_s: float
    seed: int
    dwell_s: float = 4.0
    slew_s: float = 1.5
    thermal_bloom: float = 0.05
    pk_min: float = 0.6
    pk_max: float = 0.95


@dataclass(frozen=True)
class ControlResult:
    """Result of one control against one scenario."""

    control_name: str
    expected_kills: float
    total_time_s: float
    engaged_targets: int
    leaked_targets: int
    fitness: float  # FitnessFunction score
    seed: int


def _deterministic_tracks(
    num_drones: int,
    time_limit_s: float,
    seed: int,
    pk_min: float = 0.6,
    pk_max: float = 0.95,
) -> List[DroneTrack]:
    """Generate deterministic synthetic tracks (same seed = same tracks)."""
    rng = random.Random(seed)
    tracks: List[DroneTrack] = []
    for i in range(num_drones):
        arrival = rng.uniform(5.0, time_limit_s)
        pk = rng.uniform(pk_min, pk_max)
        priority = rng.randint(1, 5)
        tracks.append(
            DroneTrack(
                track_id=i,
                arrival_time_s=round(arrival, 2),
                pk_base=round(pk, 3),
                priority=priority,
            )
        )
    return tracks


def _fitness(
    expected_kills: float,
    leaked: int,
    time_used: float,
    time_limit: float,
    leak_penalty: float = 1.0,
) -> float:
    """Fitness = expected_kills − leak_penalty·leaked + time efficiency bonus."""
    base = expected_kills - leak_penalty * leaked
    if time_limit > 0:
        efficiency = 1.0 - (time_used / time_limit)
        base += 0.5 * max(efficiency, 0.0)
    return max(base, 0.0)


# ---------------------------------------------------------------------------
# Controls — counterfactuals that the scheduler must beat to claim alpha
# ---------------------------------------------------------------------------


def _execute_sequence(
    ordered: List[DroneTrack],
    scheduler: EngagementScheduler,
    name: str,
    seed: int,
) -> ControlResult:
    """Execute engagements in the given order, respecting deadlines and time.

    Pure function of (ordered, scheduler, seed). Thermal bloom accumulates per
    engaged target, reducing effective Pk for later engagements.
    """
    time_used = 0.0
    expected_kills = 0.0
    engaged = 0
    bloom = 0.0
    for t in ordered:
        cost = scheduler.dwell_s + (scheduler.slew_s if engaged > 0 else 0.0)
        if time_used + cost > t.arrival_time_s:
            continue  # Too late for this target
        if time_used + cost > scheduler.time_limit_s:
            continue  # Not enough time remaining
        effective_pk = max(0.0, t.pk_base - bloom)
        expected_kills += effective_pk
        time_used += cost
        engaged += 1
        bloom += scheduler.thermal_bloom_penalty_per_target

    fitness = _fitness(expected_kills, len(ordered) - engaged, time_used, scheduler.time_limit_s)
    return ControlResult(
        control_name=name,
        expected_kills=round(expected_kills, 3),
        total_time_s=round(time_used, 2),
        engaged_targets=engaged,
        leaked_targets=len(ordered) - engaged,
        fitness=round(fitness, 4),
        seed=seed,
    )


def control_random_entry(
    tracks: List[DroneTrack],
    scheduler: EngagementScheduler,
) -> ControlResult:
    """Control: engage targets in a random order (no intelligence).

    Isolates whether the scheduler's value comes from selection intelligence
    or just from firing at things. Fixed seed 999 for backward compatibility.
    """
    rng = random.Random(999)
    shuffled = list(tracks)
    rng.shuffle(shuffled)
    return _execute_sequence(shuffled, scheduler, "random_entry", 999)


def control_shortest_hold_first(
    tracks: List[DroneTrack],
    scheduler: EngagementScheduler,
) -> ControlResult:
    """Control: engage targets with the shortest dwell requirement first."""
    ordered = sorted(tracks, key=lambda t: scheduler.dwell_s + scheduler.slew_s)
    return _execute_sequence(ordered, scheduler, "shortest_hold_first", 0)


def control_greedy_pk_only(
    tracks: List[DroneTrack],
    scheduler: EngagementScheduler,
) -> ControlResult:
    """Control: engage targets by raw Pk only (ignore time cost)."""
    ordered = sorted(tracks, key=lambda t: -t.pk_base)
    return _execute_sequence(ordered, scheduler, "greedy_pk_only", 0)


def control_deadline_first(
    tracks: List[DroneTrack],
    scheduler: EngagementScheduler,
) -> ControlResult:
    """Control: engage targets by earliest arrival deadline first."""
    ordered = sorted(tracks, key=lambda t: t.arrival_time_s)
    return _execute_sequence(ordered, scheduler, "deadline_first", 0)


def control_direction_flip(
    tracks: List[DroneTrack],
    scheduler: EngagementScheduler,
) -> ControlResult:
    """Control: invert Pk (high Pk becomes low, low becomes high)."""
    flipped = [
        DroneTrack(
            track_id=t.track_id,
            arrival_time_s=t.arrival_time_s,
            pk_base=round(1.0 - t.pk_base, 3),
            priority=t.priority,
        )
        for t in tracks
    ]
    sched = EngagementScheduler(
        dwell_s=scheduler.dwell_s,
        slew_s=scheduler.slew_s,
        time_limit_s=scheduler.time_limit_s,
        thermal_bloom_penalty_per_target=scheduler.thermal_bloom_penalty_per_target,
    )
    plan = sched.schedule(tracks=flipped)
    fitness = _fitness(
        plan.expected_kills,
        plan.leaked_targets,
        plan.total_time_s,
        scheduler.time_limit_s,
    )
    return ControlResult(
        control_name="direction_flip",
        expected_kills=round(plan.expected_kills, 3),
        total_time_s=round(plan.total_time_s, 2),
        engaged_targets=plan.engaged_targets,
        leaked_targets=plan.leaked_targets,
        fitness=round(fitness, 4),
        seed=0,
    )


# --- New seed-keyed counterfactual controls --------------------------------


def control_random_scheduler(
    tracks: List[DroneTrack],
    scheduler: EngagementScheduler,
    seed: int,
) -> ControlResult:
    """Control: engage targets in a random order keyed by the scenario seed.

    Same strategy class as random_entry, but seed-keyed so it is reproducible
    per scenario rather than fixed at 999.
    """
    rng = random.Random(seed)
    shuffled = list(tracks)
    rng.shuffle(shuffled)
    return _execute_sequence(shuffled, scheduler, "random_scheduler", seed)


def control_round_robin(
    tracks: List[DroneTrack],
    scheduler: EngagementScheduler,
    seed: int,
) -> ControlResult:
    """Control: cycle through targets in track-id order, engaging each that fits.

    A fair-share counterfactual: every target gets one turn before any target
    is reconsidered, emulating round-robin scheduling.
    """
    ordered = sorted(tracks, key=lambda t: t.track_id)
    return _execute_sequence(ordered, scheduler, "round_robin", seed)


def control_fifo(
    tracks: List[DroneTrack],
    scheduler: EngagementScheduler,
    seed: int,
) -> ControlResult:
    """Control: first-in, first-out by arrival time (then track_id for ties)."""
    ordered = sorted(tracks, key=lambda t: (t.arrival_time_s, t.track_id))
    return _execute_sequence(ordered, scheduler, "fifo", seed)


def control_longest_queue_first(
    tracks: List[DroneTrack],
    scheduler: EngagementScheduler,
    seed: int,
) -> ControlResult:
    """Control: highest priority first (longest/most urgent queue first).

    Treats priority as queue depth: the most urgent targets are engaged first,
    regardless of Pk or time cost.
    """
    ordered = sorted(tracks, key=lambda t: (-t.priority, t.arrival_time_s, t.track_id))
    return _execute_sequence(ordered, scheduler, "longest_queue_first", seed)


def control_shortest_job_first(
    tracks: List[DroneTrack],
    scheduler: EngagementScheduler,
    seed: int,
) -> ControlResult:
    """Control: shortest engagement time cost first.

    Engages the quickest targets first to maximize the count of engagements
    within the time limit (shortest-job-first scheduling).
    """
    ordered = sorted(
        tracks,
        key=lambda t: (scheduler.dwell_s + scheduler.slew_s, t.track_id),
    )
    return _execute_sequence(ordered, scheduler, "shortest_job_first", seed)


def run_scheduler(tracks: List[DroneTrack], scheduler: EngagementScheduler) -> ControlResult:
    """Run the engagement scheduler against tracks."""
    plan = scheduler.schedule(tracks=tracks)
    fitness = _fitness(
        plan.expected_kills,
        plan.leaked_targets,
        plan.total_time_s,
        scheduler.time_limit_s,
    )
    return ControlResult(
        control_name="scheduler",
        expected_kills=round(plan.expected_kills, 3),
        total_time_s=round(plan.total_time_s, 2),
        engaged_targets=plan.engaged_targets,
        leaked_targets=plan.leaked_targets,
        fitness=round(fitness, 4),
        seed=42,
    )


def _save_backtest_result(scenario: Scenario, result: Dict[str, Any]) -> Path:
    """Persist a backtest result under ~/.c-uas-platform/engagement/backtest/."""
    BACKTEST_ROOT.mkdir(parents=True, exist_ok=True)
    safe = scenario.name.replace("/", "_").replace(" ", "_")
    path = BACKTEST_ROOT / f"{safe}_{scenario.seed}.json"
    _atomic_write_json(path, result)
    return path


def _load_backtest_result(scenario: Scenario) -> Dict[str, Any] | None:
    """Load a persisted backtest result, or None if not stored yet."""
    safe = scenario.name.replace("/", "_").replace(" ", "_")
    path = BACKTEST_ROOT / f"{safe}_{scenario.seed}.json"
    if not path.exists():
        return None
    with path.open() as fh:
        return json.load(fh)


def run_backtest(scenario: Scenario) -> Dict[str, Any]:
    """Run the scheduler and all controls against one scenario.

    Returns a dict with the scenario, scheduler result, control results,
    and the alpha determination (did scheduler beat every control?).

    Results are persisted under ~/.c-uas-platform/engagement/backtest/.
    """
    tracks = _deterministic_tracks(
        scenario.num_drones,
        scenario.time_limit_s,
        scenario.seed,
        scenario.pk_min,
        scenario.pk_max,
    )
    scheduler = EngagementScheduler(
        dwell_s=scenario.dwell_s,
        slew_s=scenario.slew_s,
        time_limit_s=scenario.time_limit_s,
        thermal_bloom_penalty_per_target=scenario.thermal_bloom,
    )

    scheduler_result = run_scheduler(tracks, scheduler)

    base_seed = scenario.seed
    controls = [
        control_random_entry(tracks, scheduler),
        control_shortest_hold_first(tracks, scheduler),
        control_greedy_pk_only(tracks, scheduler),
        control_deadline_first(tracks, scheduler),
        control_direction_flip(tracks, scheduler),
        control_random_scheduler(tracks, scheduler, _control_seed(base_seed, "random_scheduler")),
        control_round_robin(tracks, scheduler, _control_seed(base_seed, "round_robin")),
        control_fifo(tracks, scheduler, _control_seed(base_seed, "fifo")),
        control_longest_queue_first(
            tracks, scheduler, _control_seed(base_seed, "longest_queue_first")
        ),
        control_shortest_job_first(
            tracks, scheduler, _control_seed(base_seed, "shortest_job_first")
        ),
    ]

    # Alpha determination: scheduler must beat every control on fitness
    scheduler_beats_all = all(scheduler_result.fitness > c.fitness for c in controls)
    # Also require expected_kills >= every control (not just fitness)
    scheduler_beats_all_kills = all(
        scheduler_result.expected_kills >= c.expected_kills for c in controls
    )

    result: Dict[str, Any] = {
        "scenario": asdict(scenario),
        "scheduler": asdict(scheduler_result),
        "controls": [asdict(c) for c in controls],
        "alpha_determination": {
            "scheduler_beats_every_control_on_fitness": scheduler_beats_all,
            "scheduler_beats_every_control_on_kills": scheduler_beats_all_kills,
            "alpha_claimed": scheduler_beats_all and scheduler_beats_all_kills,
            "margin_over_best_control_fitness": round(
                scheduler_result.fitness - max(c.fitness for c in controls), 4
            ),
            "margin_over_best_control_kills": round(
                scheduler_result.expected_kills - max(c.expected_kills for c in controls),
                4,
            ),
        },
    }

    _save_backtest_result(scenario, result)
    return result


def run_sweep(scenarios: List[Scenario]) -> Dict[str, Any]:
    """Run backtest across multiple scenarios. Aggregate results."""
    results = [run_backtest(s) for s in scenarios]

    total = len(results)
    alpha_wins = sum(1 for r in results if r["alpha_determination"]["alpha_claimed"])
    fitness_wins = sum(
        1 for r in results if r["alpha_determination"]["scheduler_beats_every_control_on_fitness"]
    )

    # Aggregate margins
    fitness_margins = [
        r["alpha_determination"]["margin_over_best_control_fitness"] for r in results
    ]
    kills_margins = [r["alpha_determination"]["margin_over_best_control_kills"] for r in results]

    return {
        "total_scenarios": total,
        "alpha_claimed_count": alpha_wins,
        "fitness_win_count": fitness_wins,
        "alpha_claim_rate": round(alpha_wins / total, 4) if total else 0.0,
        "avg_fitness_margin": round(sum(fitness_margins) / total, 4) if total else 0.0,
        "avg_kills_margin": round(sum(kills_margins) / total, 4) if total else 0.0,
        "min_fitness_margin": round(min(fitness_margins), 4) if fitness_margins else 0.0,
        "min_kills_margin": round(min(kills_margins), 4) if kills_margins else 0.0,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="c-uas-backtest",
        description="Backtest the engagement scheduler against counterfactual controls.",
    )
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
        help="Print full sweep report as JSON.",
    )
    args = parser.parse_args()

    scenario_map = {
        "swarm_4": Scenario(name="swarm_4", num_drones=4, time_limit_s=25.0, seed=42),
        "swarm_8": Scenario(name="swarm_8", num_drones=8, time_limit_s=40.0, seed=42),
        "swarm_16": Scenario(name="swarm_16", num_drones=16, time_limit_s=60.0, seed=42),
        "swarm_32": Scenario(name="swarm_32", num_drones=32, time_limit_s=90.0, seed=42),
    }

    if args.report:
        scenarios = [
            Scenario(name=f"swarm_{n}", num_drones=n, time_limit_s=max(25.0, n * 3.0), seed=s)
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

    # Aggregate
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


if __name__ == "__main__":
    sys.exit(main())
