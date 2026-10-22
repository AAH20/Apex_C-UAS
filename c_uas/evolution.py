"""
Evolution module — adaptive engagement scheduler parameters.

Implements a (μ + λ) evolutionary algorithm that tunes the engagement
scheduler's dwell/slew/pk parameters to maximize expected kills under a
time limit. Pure Python, no hardware, no Nvidia API.

Components:
  * EvolutionParams   — mutable hyperparameters (mutation_rate, elitism, …)
  * FitnessFunction   — expected_kills − leak_penalty·leaked + time bonus
  * MutationOperator  — Gaussian perturbation clamped to safe bounds
  * SelectionOperator — elitist top-k selection
  * EvolvedScheduler  — runs generations, returns best_params + history
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from c_uas.engagement.scheduler import EngagementScheduler


@dataclass
class EvolutionParams:
    mutation_rate: float = 0.3
    elitism_count: int = 1
    population_size: int = 8
    generations: int = 5
    seed: Optional[int] = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.mutation_rate <= 1.0:
            raise ValueError("mutation_rate must be in [0, 1]")
        if self.elitism_count < 0:
            raise ValueError("elitism_count must be >= 0")
        if self.population_size <= 0:
            raise ValueError("population_size must be > 0")
        if self.generations <= 0:
            raise ValueError("generations must be > 0")
        if self.elitism_count > self.population_size:
            raise ValueError("elitism_count must be <= population_size")


@dataclass
class FitnessFunction:
    leak_penalty: float = 1.0
    time_bonus: bool = True

    def score(
        self,
        expected_kills: float,
        leaked: int,
        time_used: float,
        time_limit: float,
    ) -> float:
        """Fitness = expected_kills − leak_penalty·leaked + time_efficiency_bonus.

        Clamped to [0, ∞). Time bonus rewards finishing faster.
        """
        base = expected_kills - self.leak_penalty * leaked
        if self.time_bonus and time_limit > 0:
            efficiency = 1.0 - (time_used / time_limit)
            base += 0.5 * max(efficiency, 0.0)
        return max(base, 0.0)


@dataclass
class MutationOperator:
    mutation_rate: float = 0.3
    seed: Optional[int] = None

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    # Safe bounds for scheduler parameters
    _BOUNDS = {
        "dwell_s": (0.5, 20.0),
        "slew_s": (0.1, 10.0),
        "pk_base": (0.1, 1.0),
    }

    def mutate(self, params: Dict[str, float]) -> Dict[str, float]:
        """Return a mutated copy of params. mutation_rate=0.0 → unchanged."""
        if self._rng.random() > self.mutation_rate:
            return dict(params)
        mutated = dict(params)
        key = self._rng.choice(list(self._BOUNDS.keys()))
        lo, hi = self._BOUNDS[key]
        # Gaussian step scaled to range width, then clamp
        step = self._rng.gauss(0.0, (hi - lo) * 0.2)
        mutated[key] = min(hi, max(lo, mutated.get(key, lo) + step))
        return mutated


@dataclass
class SelectionOperator:
    elitism_count: int = 1

    def select(self, population: List[Dict[str, Any]], k: int) -> List[Dict[str, Any]]:
        """Return the top-k individuals by fitness (descending)."""
        k = min(k, len(population))
        sorted_pop = sorted(population, key=lambda ind: ind["fitness"], reverse=True)
        return sorted_pop[:k]


class EvolvedScheduler:
    """(μ + λ) evolutionary scheduler tuner.

    Each individual is a parameter set {dwell_s, slew_s, pk_base}. Fitness is
    computed by running EngagementScheduler.schedule() and scoring with
    FitnessFunction. Elitism guarantees non-decreasing best fitness across
    generations.
    """

    def __init__(
        self,
        population_size: int = 8,
        generations: int = 5,
        mutation_rate: float = 0.3,
        elitism_count: int = 1,
        dwell_s: float = 4.0,
        slew_s: float = 1.5,
        num_drones: int = 6,
        time_limit_s: float = 30.0,
        seed: Optional[int] = None,
    ) -> None:
        self.params = EvolutionParams(
            mutation_rate=mutation_rate,
            elitism_count=elitism_count,
            population_size=population_size,
            generations=generations,
            seed=seed,
        )
        self.dwell_s = dwell_s
        self.slew_s = slew_s
        self.num_drones = num_drones
        self.time_limit_s = time_limit_s
        self._rng = random.Random(seed)
        self.mutation = MutationOperator(mutation_rate, seed)
        self.selection = SelectionOperator(elitism_count)
        self.fitness = FitnessFunction()

    def _evaluate(self, param_set: Dict[str, float]) -> float:
        sched = EngagementScheduler(
            dwell_s=param_set["dwell_s"],
            slew_s=param_set["slew_s"],
        )
        plan = sched.schedule(
            num_drones=self.num_drones,
            time_limit_s=self.time_limit_s,
        )
        # pk_base influences expected_kills indirectly via scheduler; here we
        # pass it as a hint but the scheduler's synthetic tracks are random.
        # To make pk_base meaningful, we scale expected_kills by pk_base/0.8.
        pk_scale = param_set.get("pk_base", 0.8) / 0.8
        adjusted_kills = plan.expected_kills * pk_scale
        return self.fitness.score(
            expected_kills=adjusted_kills,
            leaked=plan.leaked_targets,
            time_used=plan.total_time_s,
            time_limit=self.time_limit_s,
        )

    def _random_params(self) -> Dict[str, float]:
        return {
            "dwell_s": round(self._rng.uniform(0.5, 20.0), 2),
            "slew_s": round(self._rng.uniform(0.1, 10.0), 2),
            "pk_base": round(self._rng.uniform(0.1, 1.0), 2),
        }

    def evolve(self) -> Dict[str, Any]:
        """Run the evolutionary loop. Returns best result + history."""
        # Initialize population
        population: List[Dict[str, Any]] = []
        for _ in range(self.params.population_size):
            pset = self._random_params()
            population.append({"params": pset, "fitness": self._evaluate(pset)})

        fitness_history: List[float] = []

        for _ in range(self.params.generations):
            # Elitism: carry forward the best
            elites = self.selection.select(population, self.params.elitism_count)
            best_fitness = elites[0]["fitness"]
            fitness_history.append(best_fitness)
            offspring: List[Dict[str, Any]] = list(elites)
            while len(offspring) < self.params.population_size:
                parent = self._rng.choice(population)
                child_params = self.mutation.mutate(parent["params"])
                child = {
                    "params": child_params,
                    "fitness": self._evaluate(child_params),
                }
                offspring.append(child)
            population = offspring

        # Final generation history
        best = self.selection.select(population, 1)[0]
        return {
            "best_params": best["params"],
            "best_fitness": round(best["fitness"], 4),
            "generations_run": self.params.generations,
            "fitness_history": [round(f, 4) for f in fitness_history],
            "population_size": self.params.population_size,
        }
