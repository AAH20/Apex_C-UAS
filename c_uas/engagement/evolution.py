"""
Evolutionary optimizer for the engagement scheduler.

Enhanced (mu + lambda) evolutionary algorithm that tunes the engagement
scheduler's dwell/slew parameters to maximize expected kills under a time
limit. Pure Python, deterministic, no hardware.

Components:
  * EvolutionParams      — frozen hyperparameters (population, generations,
                           mutation-rate schedule, elitism, tournament size)
  * FitnessFunction      — deterministic fitness = expected_kills −
                           leak_penalty·leaked + time bonus; reports
                           pk-per-second and leak rate
  * MutationOperator     — Gaussian perturbation clamped to safe bounds, with
                           per-generation mutation-rate scheduling
  * SelectionOperator    — tournament selection (+ elitism)
  * EvolvedScheduler     — runs generations, returns best params + history

All results are deterministic: identical seed → identical trajectory.
Results persist under ~/.c-uas-platform/engagement/evolution/.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

from c_uas.engagement.scheduler import EngagementScheduler

EVOLUTION_ROOT = Path(
    os.environ.get(
        "C_UAS_ENGAGEMENT_STATE_DIR",
        Path.home() / ".c-uas-platform" / "engagement" / "evolution",
    )
)


def _atomic_write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    os.replace(tmp, path)


def _evolution_seed(scenario_seed: int, tag: str) -> int:
    digest = hashlib.sha256(f"{scenario_seed}:evolution:{tag}".encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % (2**31)


@dataclass(frozen=True)
class EvolutionParams:
    """Frozen hyperparameters for the evolutionary scheduler tuner."""

    population_size: int = 8
    generations: int = 5
    initial_mutation_rate: float = 0.3
    final_mutation_rate: float = 0.05
    elitism_count: int = 1
    tournament_size: int = 3
    seed: int = 42
    dwell_s: float = 4.0
    slew_s: float = 1.5
    num_drones: int = 6
    time_limit_s: float = 30.0
    leak_penalty: float = 1.0

    def __post_init__(self) -> None:
        if self.population_size <= 0:
            raise ValueError("population_size must be > 0")
        if self.generations <= 0:
            raise ValueError("generations must be > 0")
        if not 0.0 <= self.initial_mutation_rate <= 1.0:
            raise ValueError("initial_mutation_rate must be in [0, 1]")
        if not 0.0 <= self.final_mutation_rate <= 1.0:
            raise ValueError("final_mutation_rate must be in [0, 1]")
        if self.elitism_count < 0:
            raise ValueError("elitism_count must be >= 0")
        if self.elitism_count > self.population_size:
            raise ValueError("elitism_count must be <= population_size")
        if self.tournament_size <= 0:
            raise ValueError("tournament_size must be > 0")


@dataclass(frozen=True)
class Individual:
    """One scheduler parameter set with its evaluated fitness."""

    dwell_s: float
    slew_s: float
    fitness: float
    generation: int
    uid: int
    pk_per_second: float
    leak_rate: float

    def __lt__(self, other: "Individual") -> bool:
        """Heapq tie-breaker: lower uid wins when fitness ties."""
        if not isinstance(other, Individual):
            return NotImplemented
        if self.fitness != other.fitness:
            return self.fitness < other.fitness
        return self.uid < other.uid


@dataclass(frozen=True)
class FitnessFunction:
    """Deterministic fitness scoring.

    Fitness = expected_kills − leak_penalty·leaked + time_efficiency_bonus,
    clamped to [0, ∞). Also reports pk-per-second and leak rate.
    """

    leak_penalty: float = 1.0
    time_bonus: bool = True

    def score(
        self,
        expected_kills: float,
        leaked: int,
        time_used: float,
        time_limit: float,
        total_targets: int,
    ) -> Tuple[float, float, float]:
        """Return (fitness, pk_per_second, leak_rate)."""
        base = expected_kills - self.leak_penalty * leaked
        if self.time_bonus and time_limit > 0:
            efficiency = 1.0 - (time_used / time_limit)
            base += 0.5 * max(efficiency, 0.0)
        fitness = max(base, 0.0)

        pk_per_second = expected_kills / time_used if time_used > 0 else 0.0
        leak_rate = leaked / total_targets if total_targets > 0 else 0.0
        return fitness, pk_per_second, leak_rate


@dataclass(frozen=True)
class MutationOperator:
    """Gaussian perturbation clamped to safe bounds.

    mutation_rate is supplied per-generation by the scheduler (rate scheduling).
    """

    seed: int = 42

    # Safe bounds for scheduler parameters
    _BOUNDS = {
        "dwell_s": (0.5, 20.0),
        "slew_s": (0.1, 10.0),
    }
    _rng: Any = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_rng", random.Random(self.seed))

    def mutate(
        self,
        dwell_s: float,
        slew_s: float,
        mutation_rate: float,
    ) -> Tuple[float, float]:
        """Return a mutated (dwell_s, slew_s). mutation_rate=0.0 → unchanged."""
        if self._rng.random() > mutation_rate:
            return dwell_s, slew_s
        key = self._rng.choice(list(self._BOUNDS.keys()))
        lo, hi = self._BOUNDS[key]
        step = self._rng.gauss(0.0, (hi - lo) * 0.2)
        if key == "dwell_s":
            dwell_s = min(hi, max(lo, dwell_s + step))
        else:
            slew_s = min(hi, max(lo, slew_s + step))
        return round(dwell_s, 2), round(slew_s, 2)


@dataclass(frozen=True)
class SelectionOperator:
    """Tournament selection with elitism."""

    tournament_size: int = 3

    def select_parent(self, population: List[Individual], rng: random.Random) -> Individual:
        """Pick the best of ``tournament_size`` randomly drawn contenders."""
        k = min(self.tournament_size, len(population))
        contenders = rng.sample(population, k)
        return max(contenders, key=lambda ind: ind.fitness)

    def select_elites(self, population: List[Individual], count: int) -> List[Individual]:
        """Return the top-``count`` individuals by fitness (descending)."""
        count = min(count, len(population))
        return sorted(population, key=lambda ind: ind.fitness, reverse=True)[:count]


def _mutation_rate_at(
    generation: int,
    total_generations: int,
    initial: float,
    final: float,
) -> float:
    """Linearly decayed mutation rate for ``generation`` of ``total_generations``."""
    if total_generations <= 1:
        return final
    frac = generation / (total_generations - 1)
    return initial + (final - initial) * frac


def _evaluate(
    dwell_s: float,
    slew_s: float,
    scheduler_kwargs: Dict[str, Any],
    fitness_fn: FitnessFunction,
) -> Tuple[float, float, float]:
    """Run the scheduler and return (fitness, pk_per_second, leak_rate)."""
    sched = EngagementScheduler(dwell_s=dwell_s, slew_s=slew_s)
    plan = sched.schedule(**scheduler_kwargs)
    return fitness_fn.score(
        expected_kills=plan.expected_kills,
        leaked=plan.leaked_targets,
        time_used=plan.total_time_s,
        time_limit=sched.time_limit_s,
        total_targets=plan.engaged_targets + plan.leaked_targets,
    )


def _random_params(rng: random.Random) -> Tuple[float, float]:
    return (
        round(rng.uniform(0.5, 20.0), 2),
        round(rng.uniform(0.1, 10.0), 2),
    )


class EvolvedScheduler:
    """(mu + lambda) evolutionary scheduler tuner.

    Each individual is a (dwell_s, slew_s) parameter set. Fitness is computed
    by running EngagementScheduler.schedule() and scoring with FitnessFunction.
    Tournament selection chooses parents; elitism carries the best forward;
    mutation rate decays linearly across generations (rate scheduling).
    """

    def __init__(
        self,
        population_size: int = 8,
        generations: int = 5,
        initial_mutation_rate: float = 0.3,
        final_mutation_rate: float = 0.05,
        elitism_count: int = 1,
        tournament_size: int = 3,
        dwell_s: float = 4.0,
        slew_s: float = 1.5,
        num_drones: int = 6,
        time_limit_s: float = 30.0,
        leak_penalty: float = 1.0,
        seed: int = 42,
    ) -> None:
        self.params = EvolutionParams(
            population_size=population_size,
            generations=generations,
            initial_mutation_rate=initial_mutation_rate,
            final_mutation_rate=final_mutation_rate,
            elitism_count=elitism_count,
            tournament_size=tournament_size,
            seed=seed,
            dwell_s=dwell_s,
            slew_s=slew_s,
            num_drones=num_drones,
            time_limit_s=time_limit_s,
            leak_penalty=leak_penalty,
        )
        self._rng = random.Random(seed)
        self.fitness = FitnessFunction(leak_penalty=leak_penalty)
        self.mutation = MutationOperator(seed=seed)
        self.selection = SelectionOperator(tournament_size=tournament_size)

    def evolve(self) -> Dict[str, Any]:
        """Run the evolutionary loop. Returns best result + history.

        Deterministic: same seed → same trajectory.
        """
        p = self.params
        rng = self._rng

        # Initialize population
        population: List[Individual] = []
        uid_counter = 0
        for _ in range(p.population_size):
            dwell_s, slew_s = _random_params(rng)
            fitness, pk_per_second, leak_rate = _evaluate(
                dwell_s,
                slew_s,
                {
                    "num_drones": p.num_drones,
                    "time_limit_s": p.time_limit_s,
                },
                self.fitness,
            )
            population.append(
                Individual(
                    dwell_s=dwell_s,
                    slew_s=slew_s,
                    fitness=fitness,
                    generation=0,
                    uid=uid_counter,
                    pk_per_second=pk_per_second,
                    leak_rate=leak_rate,
                )
            )
            uid_counter += 1

        fitness_history: List[float] = []
        best_history: List[Dict[str, Any]] = []

        for generation in range(p.generations):
            # Elitism: carry forward the best individuals
            elites = self.selection.select_elites(population, p.elitism_count)
            best = elites[0]
            fitness_history.append(best.fitness)
            best_history.append(
                {
                    "generation": generation,
                    "dwell_s": best.dwell_s,
                    "slew_s": best.slew_s,
                    "fitness": best.fitness,
                    "pk_per_second": best.pk_per_second,
                    "leak_rate": best.leak_rate,
                }
            )

            # Mutation rate scheduling: decay over generations
            mutation_rate = _mutation_rate_at(
                generation,
                p.generations,
                p.initial_mutation_rate,
                p.final_mutation_rate,
            )

            offspring: List[Individual] = list(elites)
            while len(offspring) < p.population_size:
                parent = self.selection.select_parent(population, rng)
                child_dwell, child_slew = self.mutation.mutate(
                    parent.dwell_s, parent.slew_s, mutation_rate
                )
                child_fitness, child_pkps, child_leak = _evaluate(
                    child_dwell,
                    child_slew,
                    {
                        "num_drones": p.num_drones,
                        "time_limit_s": p.time_limit_s,
                    },
                    self.fitness,
                )
                offspring.append(
                    Individual(
                        dwell_s=child_dwell,
                        slew_s=child_slew,
                        fitness=child_fitness,
                        generation=generation + 1,
                        uid=uid_counter,
                        pk_per_second=child_pkps,
                        leak_rate=child_leak,
                    )
                )
                uid_counter += 1
            population = offspring

        # Final generation history
        final_best = self.selection.select_elites(population, 1)[0]
        result = {
            "best_params": {
                "dwell_s": final_best.dwell_s,
                "slew_s": final_best.slew_s,
            },
            "best_fitness": round(final_best.fitness, 4),
            "best_pk_per_second": round(final_best.pk_per_second, 4),
            "best_leak_rate": round(final_best.leak_rate, 4),
            "generations_run": p.generations,
            "fitness_history": [round(f, 4) for f in fitness_history],
            "population_size": p.population_size,
            "seed": p.seed,
        }
        return result


def save_evolution_result(params: EvolutionParams, result: Dict[str, Any]) -> Path:
    """Persist an evolution result under ~/.c-uas-platform/engagement/evolution/."""
    EVOLUTION_ROOT.mkdir(parents=True, exist_ok=True)
    path = EVOLUTION_ROOT / f"{params.seed}.json"
    payload = {"params": asdict(params), "result": result}
    _atomic_write_json(path, payload)
    return path
