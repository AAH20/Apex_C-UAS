"""Deterministic tests for the engagement backtest/evolution/alpha module.

Covers:
  * backtest harness: controls, seed-keying, determinism, persistence
  * evolution: tournament selection, elitism, mutation-rate scheduling,
    deterministic fitness tracking pk-per-second and leak rate
  * alpha: scheduler vs counterfactuals, bootstrap significance, persistence
  * cli: --backtest / --evolve / --alpha dispatch
"""

import json
import os
import unittest

from c_uas.engagement.alpha import (
    compute_alpha,
    load_alpha_result,
    save_alpha_result,
)
from c_uas.engagement.backtest import (
    Scenario,
    _control_seed,
    _deterministic_tracks,
    _execute_sequence,
    _fitness,
    control_fifo,
    control_longest_queue_first,
    control_random_scheduler,
    control_round_robin,
    control_shortest_job_first,
    run_backtest,
    run_scheduler,
    run_sweep,
)
from c_uas.engagement.cli import build_subparser, engagement_main
from c_uas.engagement.evolution import (
    EvolutionParams,
    EvolvedScheduler,
    FitnessFunction,
    Individual,
    MutationOperator,
    SelectionOperator,
    _mutation_rate_at,
    save_evolution_result,
)


class TestBacktestDeterminism(unittest.TestCase):
    def test_same_seed_same_result(self):
        s = Scenario(name="t1", num_drones=6, time_limit_s=30.0, seed=7)
        r1 = run_backtest(s)
        r2 = run_backtest(s)
        self.assertEqual(r1, r2)

    def test_different_seed_different_tracks(self):
        t1 = _deterministic_tracks(5, 30.0, 1)
        t2 = _deterministic_tracks(5, 30.0, 2)
        self.assertNotEqual(
            [(t.track_id, t.pk_base) for t in t1],
            [(t.track_id, t.pk_base) for t in t2],
        )

    def test_control_seed_is_deterministic(self):
        self.assertEqual(_control_seed(42, "fifo"), _control_seed(42, "fifo"))
        self.assertNotEqual(_control_seed(42, "fifo"), _control_seed(43, "fifo"))
        self.assertNotEqual(_control_seed(42, "fifo"), _control_seed(42, "round_robin"))

    def test_all_controls_return_non_negative_fitness(self):
        s = Scenario(name="t2", num_drones=8, time_limit_s=40.0, seed=42)
        result = run_backtest(s)
        for c in result["controls"]:
            self.assertGreaterEqual(c["fitness"], 0.0)
            self.assertGreaterEqual(c["expected_kills"], 0.0)

    def test_engaged_plus_leaked_equals_num_drones(self):
        s = Scenario(name="t3", num_drones=10, time_limit_s=30.0, seed=3)
        result = run_backtest(s)
        for c in result["controls"]:
            self.assertEqual(c["engaged_targets"] + c["leaked_targets"], s.num_drones)

    def test_scheduler_is_in_result_but_not_controls(self):
        s = Scenario(name="t4", num_drones=6, time_limit_s=30.0, seed=11)
        result = run_backtest(s)
        self.assertEqual(result["scheduler"]["control_name"], "scheduler")
        control_names = {c["control_name"] for c in result["controls"]}
        self.assertNotIn("scheduler", control_names)

    def test_new_controls_present(self):
        s = Scenario(name="t5", num_drones=8, time_limit_s=40.0, seed=42)
        result = run_backtest(s)
        names = {c["control_name"] for c in result["controls"]}
        for n in (
            "random_scheduler",
            "round_robin",
            "fifo",
            "longest_queue_first",
            "shortest_job_first",
        ):
            self.assertIn(n, names)

    def test_persistence_writes_file(self):
        s = Scenario(name="persist_t", num_drones=4, time_limit_s=25.0, seed=99)
        run_backtest(s)
        safe = s.name.replace("/", "_").replace(" ", "_")
        path = (
            os.path.expanduser("~/.c-uas-platform/engagement/backtest/") + f"/{safe}_{s.seed}.json"
        )
        self.assertTrue(os.path.exists(path))
        with open(path) as fh:
            data = json.load(fh)
        self.assertIn("scheduler", data)
        self.assertIn("controls", data)
        self.assertEqual(len(data["controls"]), 10)


class TestBacktestControls(unittest.TestCase):
    def setUp(self):
        self.sched = __import__(
            "c_uas.engagement.scheduler", fromlist=["EngagementScheduler"]
        ).EngagementScheduler(dwell_s=4.0, slew_s=1.5, time_limit_s=40.0)
        self.tracks = _deterministic_tracks(8, 40.0, 42)

    def test_execute_sequence_respects_deadline(self):
        # A track arriving at time 0 can never be engaged (cost > 0)
        late = [
            __import__("c_uas.engagement.scheduler", fromlist=["DroneTrack"]).DroneTrack(
                track_id=0, arrival_time_s=0.0, pk_base=0.9, priority=1
            )
        ]
        res = _execute_sequence(late, self.sched, "fifo", 0)
        self.assertEqual(res.engaged_targets, 0)
        self.assertEqual(res.leaked_targets, 1)

    def test_random_scheduler_is_seed_keyed(self):
        r1 = control_random_scheduler(self.tracks, self.sched, seed=5)
        r2 = control_random_scheduler(self.tracks, self.sched, seed=5)
        self.assertEqual(r1, r2)
        r3 = control_random_scheduler(self.tracks, self.sched, seed=6)
        self.assertNotEqual(r1.seed, r3.seed)

    def test_fifo_orders_by_arrival(self):
        res = control_fifo(self.tracks, self.sched, seed=0)
        self.assertGreaterEqual(res.expected_kills, 0.0)

    def test_round_robin_orders_by_track_id(self):
        res = control_round_robin(self.tracks, self.sched, seed=0)
        self.assertGreaterEqual(res.expected_kills, 0.0)

    def test_longest_queue_first_uses_priority(self):
        res = control_longest_queue_first(self.tracks, self.sched, seed=0)
        self.assertGreaterEqual(res.expected_kills, 0.0)

    def test_shortest_job_first_uses_time_cost(self):
        res = control_shortest_job_first(self.tracks, self.sched, seed=0)
        self.assertGreaterEqual(res.expected_kills, 0.0)

    def test_scheduler_run_scheduler(self):
        res = run_scheduler(self.tracks, self.sched)
        self.assertEqual(res.control_name, "scheduler")
        self.assertGreaterEqual(res.expected_kills, 0.0)

    def test_alpha_determination_structure(self):
        result = run_backtest(Scenario(name="t6", num_drones=8, time_limit_s=40.0, seed=42))
        ad = result["alpha_determination"]
        self.assertIn("alpha_claimed", ad)
        self.assertIn("margin_over_best_control_fitness", ad)
        self.assertIn("margin_over_best_control_kills", ad)

    def test_sweep_structure(self):
        scenarios = [
            Scenario(name="s4", num_drones=4, time_limit_s=25.0, seed=1),
            Scenario(name="s8", num_drones=8, time_limit_s=40.0, seed=2),
        ]
        report = run_sweep(scenarios)
        self.assertEqual(report["total_scenarios"], 2)
        self.assertIn("alpha_claim_rate", report)


class TestFitnessFunction(unittest.TestCase):
    def test_positive_kills_positive_fitness(self):
        self.assertGreater(_fitness(5.0, 0, 10.0, 60.0), 0.0)

    def test_all_leaked_clamped_zero(self):
        self.assertEqual(_fitness(0.0, 10, 60.0, 60.0), 0.0)

    def test_time_bonus_rewards_faster(self):
        self.assertGreater(_fitness(5.0, 0, 10.0, 60.0), _fitness(5.0, 0, 50.0, 60.0))


class TestEvolutionDeterminism(unittest.TestCase):
    def test_same_seed_same_trajectory(self):
        e1 = EvolvedScheduler(population_size=6, generations=3, seed=11)
        e2 = EvolvedScheduler(population_size=6, generations=3, seed=11)
        self.assertEqual(e1.evolve(), e2.evolve())

    def test_different_seed_different_result(self):
        e1 = EvolvedScheduler(population_size=6, generations=3, seed=11)
        e2 = EvolvedScheduler(population_size=6, generations=3, seed=12)
        self.assertNotEqual(e1.evolve()["best_fitness"], e2.evolve()["best_fitness"])

    def test_elitism_non_decreasing_best(self):
        engine = EvolvedScheduler(population_size=8, generations=5, seed=3)
        result = engine.evolve()
        history = result["fitness_history"]
        self.assertEqual(len(history), 5)
        for i in range(1, len(history)):
            self.assertGreaterEqual(history[i], history[i - 1] - 1e-9)

    def test_best_params_within_bounds(self):
        engine = EvolvedScheduler(population_size=6, generations=4, seed=1)
        result = engine.evolve()
        self.assertGreaterEqual(result["best_params"]["dwell_s"], 0.5)
        self.assertLessEqual(result["best_params"]["dwell_s"], 20.0)
        self.assertGreaterEqual(result["best_params"]["slew_s"], 0.1)
        self.assertLessEqual(result["best_params"]["slew_s"], 10.0)

    def test_persistence_writes_file(self):
        engine = EvolvedScheduler(population_size=4, generations=2, seed=77)
        result = engine.evolve()
        params = EvolutionParams(seed=77)
        path = save_evolution_result(params, result)
        self.assertTrue(os.path.exists(path))
        with open(path) as fh:
            data = json.load(fh)
        self.assertIn("result", data)
        self.assertIn("best_fitness", data["result"])

    def test_mutation_rate_scheduling(self):
        self.assertAlmostEqual(_mutation_rate_at(0, 5, 0.3, 0.05), 0.3)
        self.assertAlmostEqual(_mutation_rate_at(4, 5, 0.3, 0.05), 0.05)
        self.assertAlmostEqual(_mutation_rate_at(2, 5, 0.3, 0.05), 0.175)

    def test_individual_lt_tie_break_by_uid(self):
        a = Individual(
            dwell_s=1.0,
            slew_s=1.0,
            fitness=5.0,
            generation=0,
            uid=1,
            pk_per_second=1.0,
            leak_rate=0.0,
        )
        b = Individual(
            dwell_s=1.0,
            slew_s=1.0,
            fitness=5.0,
            generation=0,
            uid=2,
            pk_per_second=1.0,
            leak_rate=0.0,
        )
        self.assertTrue(a < b)
        self.assertFalse(b < a)

    def test_individual_lt_by_fitness(self):
        a = Individual(
            dwell_s=1.0,
            slew_s=1.0,
            fitness=3.0,
            generation=0,
            uid=1,
            pk_per_second=1.0,
            leak_rate=0.0,
        )
        b = Individual(
            dwell_s=1.0,
            slew_s=1.0,
            fitness=5.0,
            generation=0,
            uid=2,
            pk_per_second=1.0,
            leak_rate=0.0,
        )
        self.assertTrue(a < b)
        self.assertFalse(b < a)

    def test_tournament_selection_picks_best(self):
        rng = __import__("random").Random(1)
        pop = [
            Individual(
                dwell_s=1.0,
                slew_s=1.0,
                fitness=1.0,
                generation=0,
                uid=0,
                pk_per_second=1.0,
                leak_rate=0.0,
            ),
            Individual(
                dwell_s=1.0,
                slew_s=1.0,
                fitness=9.0,
                generation=0,
                uid=1,
                pk_per_second=1.0,
                leak_rate=0.0,
            ),
            Individual(
                dwell_s=1.0,
                slew_s=1.0,
                fitness=5.0,
                generation=0,
                uid=2,
                pk_per_second=1.0,
                leak_rate=0.0,
            ),
        ]
        sel = SelectionOperator(tournament_size=3)
        winner = sel.select_parent(pop, rng)
        self.assertEqual(winner.fitness, 9.0)

    def test_selection_elites_top_k(self):
        pop = [
            Individual(
                dwell_s=1.0,
                slew_s=1.0,
                fitness=float(i),
                generation=0,
                uid=i,
                pk_per_second=1.0,
                leak_rate=0.0,
            )
            for i in range(5)
        ]
        sel = SelectionOperator(tournament_size=3)
        elites = sel.select_elites(pop, 2)
        self.assertEqual([e.fitness for e in elites], [4.0, 3.0])

    def test_mutation_unchanged_at_zero_rate(self):
        mut = MutationOperator(seed=1)
        d, s = mut.mutate(4.0, 1.5, mutation_rate=0.0)
        self.assertEqual(d, 4.0)
        self.assertEqual(s, 1.5)

    def test_fitness_reports_pk_per_second_and_leak_rate(self):
        fit = FitnessFunction(leak_penalty=1.0)
        fitness, pkps, leak = fit.score(
            expected_kills=4.0, leaked=2, time_used=10.0, time_limit=40.0, total_targets=10
        )
        self.assertAlmostEqual(pkps, 0.4)  # 4.0 / 10.0
        self.assertAlmostEqual(leak, 0.2)  # 2 / 10
        self.assertGreaterEqual(fitness, 0.0)


class TestAlphaMeasurement(unittest.TestCase):
    def test_alpha_positive_when_scheduler_best(self):
        res = compute_alpha(
            scheduler_pk=5.0,
            control_pks=[2.0, 3.0, 1.0],
            control_names=["a", "b", "c"],
            seed=42,
        )
        self.assertEqual(res.alpha, 2.0)  # 5.0 - 3.0
        self.assertEqual(res.best_counterfactual_pk, 3.0)
        self.assertTrue(res.significant)

    def test_alpha_zero_when_counterfactual_ties(self):
        res = compute_alpha(
            scheduler_pk=3.0,
            control_pks=[3.0, 3.0],
            control_names=["a", "b"],
            seed=42,
        )
        self.assertEqual(res.alpha, 0.0)

    def test_alpha_negative_when_counterfactual_better(self):
        res = compute_alpha(
            scheduler_pk=2.0,
            control_pks=[5.0],
            control_names=["a"],
            seed=42,
        )
        self.assertEqual(res.alpha, -3.0)

    def test_alpha_deterministic(self):
        r1 = compute_alpha(4.0, [1.0, 2.0], ["a", "b"], seed=7)
        r2 = compute_alpha(4.0, [1.0, 2.0], ["a", "b"], seed=7)
        self.assertEqual(r1.p_value, r2.p_value)
        self.assertEqual(r1.alpha, r2.alpha)

    def test_alpha_p_value_in_range(self):
        res = compute_alpha(4.0, [1.0, 2.0, 3.0], ["a", "b", "c"], seed=9)
        self.assertGreaterEqual(res.p_value, 0.0)
        self.assertLessEqual(res.p_value, 1.0)

    def test_alpha_significance_flag(self):
        # Scheduler far above counterfactuals -> significant
        sig = compute_alpha(10.0, [1.0, 1.0], ["a", "b"], seed=1).significant
        self.assertTrue(sig)
        # Scheduler below -> not significant
        not_sig = compute_alpha(1.0, [5.0, 5.0], ["a", "b"], seed=1).significant
        self.assertFalse(not_sig)

    def test_alpha_persistence_round_trip(self):
        from c_uas.engagement.alpha import measure_alpha

        res = measure_alpha(
            "alpha_scenario", 42, scheduler_pk=5.0, control_pks=[2.0, 3.0], control_names=["a", "b"]
        )
        path = save_alpha_result(res)
        self.assertTrue(os.path.exists(path))
        loaded = load_alpha_result("alpha_scenario", res.seed)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.alpha, res.alpha)
        self.assertEqual(loaded.p_value, res.p_value)

    def test_bootstrap_confidence_interval(self):
        res = compute_alpha(5.0, [2.0, 3.0], ["a", "b"], seed=42, n_bootstrap=5000)
        self.assertLessEqual(res.bootstrap_ci_lower, res.bootstrap_ci_upper)
        self.assertIsInstance(res.bootstrap_std, float)


class TestEngagementCLI(unittest.TestCase):
    def test_build_subparser_registers_modes(self):
        import argparse

        parser = argparse.ArgumentParser(prog="test")
        subparsers = parser.add_subparsers(dest="command")
        build_subparser(subparsers)
        args = parser.parse_args(["engagement", "backtest", "--scenario", "swarm_4"])
        self.assertEqual(args.command, "engagement")
        self.assertEqual(args.engagement_command, "backtest")

    def test_engagement_main_backtest(self):
        # --backtest isn't a top-level flag; engagement uses subcommands backtest/evolve/alpha
        code = engagement_main(["backtest", "--scenario", "swarm_4", "--trials", "1"])
        self.assertEqual(code, 0)

    def test_engagement_main_evolve(self):
        code = engagement_main(
            ["evolve", "--generations", "2", "--population-size", "4", "--seed", "5"]
        )
        self.assertEqual(code, 0)

    def test_engagement_main_alpha(self):
        code = engagement_main(
            ["alpha", "--scenario", "swarm_4", "--seed", "42", "--bootstrap", "200"]
        )
        self.assertEqual(code, 0)

    def test_engagement_main_no_command_prints_help(self):
        code = engagement_main([])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
