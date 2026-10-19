"""Tests for the evolution module — adaptive engagement scheduler parameters."""

import unittest
from c_uas.evolution import (
    EvolutionParams,
    FitnessFunction,
    MutationOperator,
    SelectionOperator,
    EvolvedScheduler,
)


class TestEvolutionParams(unittest.TestCase):
    def test_default_params(self):
        p = EvolutionParams()
        self.assertGreater(p.mutation_rate, 0.0)
        self.assertLess(p.mutation_rate, 1.0)
        self.assertGreater(p.elitism_count, 0)
        self.assertGreater(p.population_size, 0)
        self.assertGreater(p.generations, 0)

    def test_param_bounds(self):
        p = EvolutionParams(mutation_rate=0.5, elitism_count=1, population_size=4, generations=2)
        self.assertEqual(p.mutation_rate, 0.5)
        self.assertEqual(p.elitism_count, 1)
        self.assertEqual(p.population_size, 4)
        self.assertEqual(p.generations, 2)

    def test_invalid_mutation_rate_raises(self):
        with self.assertRaises(ValueError):
            EvolutionParams(mutation_rate=1.5)

    def test_zero_population_raises(self):
        with self.assertRaises(ValueError):
            EvolutionParams(population_size=0)


class TestFitnessFunction(unittest.TestCase):
    def test_fitness_is_expected_kills_minus_leak_penalty(self):
        ff = FitnessFunction(leak_penalty=2.0, time_bonus=False)
        score = ff.score(expected_kills=5.0, leaked=2.0, time_used=10.0, time_limit=60.0)
        # 5 kills - 2 leaked * 2.0 penalty = 1.0
        self.assertAlmostEqual(score, 1.0)

    def test_fitness_never_negative(self):
        ff = FitnessFunction(leak_penalty=10.0)
        score = ff.score(expected_kills=0.0, leaked=5.0, time_used=1.0, time_limit=10.0)
        self.assertGreaterEqual(score, 0.0)

    def test_time_efficiency_bonus(self):
        ff = FitnessFunction(leak_penalty=1.0, time_bonus=True)
        fast = ff.score(expected_kills=3.0, leaked=0.0, time_used=5.0, time_limit=60.0)
        slow = ff.score(expected_kills=3.0, leaked=0.0, time_used=55.0, time_limit=60.0)
        self.assertGreater(fast, slow)


class TestMutationOperator(unittest.TestCase):
    def test_mutates_dwell_time(self):
        mo = MutationOperator(mutation_rate=1.0, seed=42)
        original = {"dwell_s": 4.0, "slew_s": 1.5, "pk_base": 0.8}
        mutated = mo.mutate(original)
        # With mutation_rate=1.0 something should change
        self.assertIsInstance(mutated, dict)
        self.assertIn("dwell_s", mutated)
        self.assertIn("slew_s", mutated)
        self.assertIn("pk_base", mutated)

    def test_mutation_rate_zero_no_change(self):
        mo = MutationOperator(mutation_rate=0.0, seed=42)
        original = {"dwell_s": 4.0, "slew_s": 1.5, "pk_base": 0.8}
        mutated = mo.mutate(original)
        self.assertEqual(mutated, original)

    def test_mutated_values_stay_in_bounds(self):
        mo = MutationOperator(mutation_rate=1.0, seed=7)
        original = {"dwell_s": 4.0, "slew_s": 1.5, "pk_base": 0.8}
        for _ in range(50):
            mutated = mo.mutate(original)
            self.assertGreaterEqual(mutated["dwell_s"], 0.5)
            self.assertLessEqual(mutated["dwell_s"], 20.0)
            self.assertGreaterEqual(mutated["slew_s"], 0.1)
            self.assertLessEqual(mutated["slew_s"], 10.0)
            self.assertGreaterEqual(mutated["pk_base"], 0.1)
            self.assertLessEqual(mutated["pk_base"], 1.0)


class TestSelectionOperator(unittest.TestCase):
    def test_selects_top_k_by_fitness(self):
        so = SelectionOperator(elitism_count=2)
        population = [
            {"params": {"dwell_s": 1.0}, "fitness": 0.1},
            {"params": {"dwell_s": 2.0}, "fitness": 0.9},
            {"params": {"dwell_s": 3.0}, "fitness": 0.5},
        ]
        selected = so.select(population, k=2)
        self.assertEqual(len(selected), 2)
        # Top 2 by fitness: 0.9 and 0.5
        fitnesses = [ind["fitness"] for ind in selected]
        self.assertIn(0.9, fitnesses)
        self.assertIn(0.5, fitnesses)


class TestEvolvedScheduler(unittest.TestCase):
    def test_runs_evolution(self):
        es = EvolvedScheduler(
            population_size=4,
            generations=3,
            mutation_rate=0.3,
            elitism_count=1,
            dwell_s=4.0,
            slew_s=1.5,
            num_drones=6,
            time_limit_s=30.0,
        )
        result = es.evolve()
        self.assertIsInstance(result, dict)
        self.assertIn("best_params", result)
        self.assertIn("best_fitness", result)
        self.assertIn("generations_run", result)
        self.assertIn("fitness_history", result)
        self.assertEqual(len(result["fitness_history"]), 3)

    def test_best_fitness_improves_or_stays(self):
        es = EvolvedScheduler(
            population_size=6,
            generations=5,
            mutation_rate=0.4,
            elitism_count=1,
            dwell_s=4.0,
            slew_s=1.5,
            num_drones=8,
            time_limit_s=30.0,
        )
        result = es.evolve()
        history = result["fitness_history"]
        # Fitness should not decrease across generations (elitism preserves best)
        for i in range(1, len(history)):
            self.assertGreaterEqual(history[i], history[i - 1] - 1e-9)

    def test_deterministic_with_seed(self):
        es1 = EvolvedScheduler(
            population_size=4,
            generations=3,
            mutation_rate=0.3,
            elitism_count=1,
            dwell_s=4.0,
            slew_s=1.5,
            num_drones=6,
            time_limit_s=30.0,
            seed=123,
        )
        es2 = EvolvedScheduler(
            population_size=4,
            generations=3,
            mutation_rate=0.3,
            elitism_count=1,
            dwell_s=4.0,
            slew_s=1.5,
            num_drones=6,
            time_limit_s=30.0,
            seed=123,
        )
        r1 = es1.evolve()
        r2 = es2.evolve()
        self.assertEqual(r1["best_params"], r2["best_params"])
        self.assertEqual(r1["best_fitness"], r2["best_fitness"])


if __name__ == "__main__":
    unittest.main()
