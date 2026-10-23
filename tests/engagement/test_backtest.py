"""Tests for the engagement scheduler backtest harness."""

import unittest

from c_uas.engagement.backtest import (
    Scenario,
    _deterministic_tracks,
    _fitness,
    run_backtest,
    run_sweep,
)


class TestDeterministicTracks(unittest.TestCase):
    def test_deterministic_same_seed(self):
        t1 = _deterministic_tracks(5, 30.0, 42)
        t2 = _deterministic_tracks(5, 30.0, 42)
        self.assertEqual(
            [(t.track_id, t.arrival_time_s, t.pk_base) for t in t1],
            [(t.track_id, t.arrival_time_s, t.pk_base) for t in t2],
        )

    def test_different_seed_different_tracks(self):
        t1 = _deterministic_tracks(5, 30.0, 1)
        t2 = _deterministic_tracks(5, 30.0, 2)
        self.assertNotEqual(
            [(t.track_id, t.arrival_time_s, t.pk_base) for t in t1],
            [(t.track_id, t.arrival_time_s, t.pk_base) for t in t2],
        )

    def test_track_count(self):
        tracks = _deterministic_tracks(10, 30.0, 42)
        self.assertEqual(len(tracks), 10)

    def test_arrival_within_limit(self):
        tracks = _deterministic_tracks(10, 30.0, 42)
        for t in tracks:
            self.assertGreaterEqual(t.arrival_time_s, 5.0)
            self.assertLessEqual(t.arrival_time_s, 30.0)

    def test_pk_in_range(self):
        tracks = _deterministic_tracks(10, 30.0, 42)
        for t in tracks:
            self.assertGreaterEqual(t.pk_base, 0.6)
            self.assertLessEqual(t.pk_base, 0.95)


class TestFitnessFunction(unittest.TestCase):
    def test_positive_kills_positive_fitness(self):
        f = _fitness(5.0, 0, 10.0, 60.0)
        self.assertGreater(f, 0.0)

    def test_all_leaked_zero_fitness(self):
        f = _fitness(0.0, 10, 60.0, 60.0)
        self.assertEqual(f, 0.0)

    def test_clamped_at_zero(self):
        f = _fitness(1.0, 10, 60.0, 60.0)
        self.assertEqual(f, 0.0)

    def test_time_bonus_rewards_faster(self):
        f_fast = _fitness(5.0, 0, 10.0, 60.0)
        f_slow = _fitness(5.0, 0, 50.0, 60.0)
        self.assertGreater(f_fast, f_slow)


class TestBacktestHarness(unittest.TestCase):
    def setUp(self):
        self.scenario = Scenario(name="swarm_8", num_drones=8, time_limit_s=40.0, seed=42)

    def test_backtest_returns_result(self):
        result = run_backtest(self.scenario)
        self.assertIn("scheduler", result)
        self.assertIn("controls", result)
        self.assertIn("alpha_determination", result)
        self.assertIn("scenario", result)

    def test_scheduler_has_expected_kills(self):
        result = run_backtest(self.scenario)
        self.assertGreater(result["scheduler"]["expected_kills"], 0.0)

    def test_scheduler_has_controls(self):
        result = run_backtest(self.scenario)
        self.assertEqual(len(result["controls"]), 5)
        control_names = {c["control_name"] for c in result["controls"]}
        self.assertEqual(
            control_names,
            {
                "scheduler",
                "random_entry",
                "shortest_hold_first",
                "greedy_pk_only",
                "deadline_first",
                "direction_flip",
            }
            - {"scheduler"},
        )  # controls don't include scheduler itself

    def test_alpha_determination_structure(self):
        result = run_backtest(self.scenario)
        ad = result["alpha_determination"]
        self.assertIn("alpha_claimed", ad)
        self.assertIn("scheduler_beats_every_control_on_fitness", ad)
        self.assertIn("scheduler_beats_every_control_on_kills", ad)
        self.assertIn("margin_over_best_control_fitness", ad)
        self.assertIn("margin_over_best_control_kills", ad)

    def test_scheduler_beats_random_entry(self):
        result = run_backtest(self.scenario)
        sched = result["scheduler"]
        random_ctrl = next(c for c in result["controls"] if c["control_name"] == "random_entry")
        self.assertGreaterEqual(sched["expected_kills"], random_ctrl["expected_kills"])
        self.assertGreaterEqual(sched["fitness"], random_ctrl["fitness"])

    def test_scheduler_beats_direction_flip(self):
        result = run_backtest(self.scenario)
        sched = result["scheduler"]
        flip_ctrl = next(c for c in result["controls"] if c["control_name"] == "direction_flip")
        self.assertGreaterEqual(sched["expected_kills"], flip_ctrl["expected_kills"])
        self.assertGreaterEqual(sched["fitness"], flip_ctrl["fitness"])

    def test_sweep_structure(self):
        scenarios = [
            Scenario(name="s4", num_drones=4, time_limit_s=25.0, seed=1),
            Scenario(name="s8", num_drones=8, time_limit_s=40.0, seed=2),
        ]
        report = run_sweep(scenarios)
        self.assertEqual(report["total_scenarios"], 2)
        self.assertIn("alpha_claim_rate", report)
        self.assertIn("avg_fitness_margin", report)
        self.assertIn("results", report)
        self.assertEqual(len(report["results"]), 2)


if __name__ == "__main__":
    unittest.main()
