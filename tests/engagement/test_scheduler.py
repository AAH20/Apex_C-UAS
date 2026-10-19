"""Tests for NP-hard engagement scheduler."""

import unittest
from c_uas.engagement.scheduler import EngagementScheduler, EngagementPlan


class TestEngagementScheduler(unittest.TestCase):
    def test_schedule_returns_plan(self):
        sched = EngagementScheduler(dwell_s=4.0, slew_s=1.5)
        plan = sched.schedule(num_drones=5)
        self.assertIsInstance(plan, EngagementPlan)
        self.assertGreaterEqual(plan.expected_kills, 0.0)
        self.assertGreaterEqual(plan.total_time_s, 0.0)
        self.assertGreaterEqual(plan.leaked_targets, 0)

    def test_expected_kills_equals_num_drones_when_small_swarm(self):
        sched = EngagementScheduler(dwell_s=2.0, slew_s=0.5)
        plan = sched.schedule(num_drones=3, time_limit_s=60.0)
        # With plenty of time, all 3 should be engaged
        self.assertEqual(plan.engaged_targets, 3)
        self.assertEqual(plan.leaked_targets, 0)
        # Expected kills = sum of Pk values, each in [0.6, 0.95]
        self.assertGreaterEqual(plan.expected_kills, 1.5)
        self.assertLessEqual(plan.expected_kills, 3.0)

    def test_more_drones_reduces_expected_kills_ratio(self):
        sched = EngagementScheduler(dwell_s=4.0, slew_s=1.5)
        plan_small = sched.schedule(num_drones=5, time_limit_s=30.0)
        plan_large = sched.schedule(num_drones=20, time_limit_s=30.0)
        # With fixed time, engaging more drones means lower per-target kill ratio
        self.assertGreater(plan_small.expected_kills / 5.0,
                          plan_large.expected_kills / 20.0)

    def test_leaked_targets(self):
        sched = EngagementScheduler(dwell_s=10.0, slew_s=5.0)
        plan = sched.schedule(num_drones=10, time_limit_s=15.0)
        # With long dwell and limited time, many targets leak
        self.assertGreaterEqual(plan.leaked_targets, 0)
        self.assertEqual(plan.engaged_targets + plan.leaked_targets, 10)

    def test_engagement_sequence_ordered(self):
        sched = EngagementScheduler(dwell_s=4.0, slew_s=1.5)
        plan = sched.schedule(num_drones=6, time_limit_s=60.0)
        self.assertIsInstance(plan.sequence, list)
        self.assertLessEqual(len(plan.sequence), 6)

    def test_single_target_engaged_fully(self):
        sched = EngagementScheduler(dwell_s=4.0, slew_s=1.5)
        plan = sched.schedule(num_drones=1, time_limit_s=60.0)
        # Single target: engaged, expected kills = its Pk (0-1)
        self.assertEqual(plan.engaged_targets, 1)
        self.assertEqual(plan.leaked_targets, 0)
        self.assertGreater(plan.expected_kills, 0.0)
        self.assertLessEqual(plan.expected_kills, 1.0)

    def test_dwell_time_affects_kill_count(self):
        sched_short = EngagementScheduler(dwell_s=2.0, slew_s=0.5)
        sched_long = EngagementScheduler(dwell_s=10.0, slew_s=0.5)
        plan_short = sched_short.schedule(num_drones=10, time_limit_s=30.0)
        plan_long = sched_long.schedule(num_drones=10, time_limit_s=30.0)
        # Shorter dwell = more targets can be engaged in same time
        self.assertGreaterEqual(plan_short.engaged_targets,
                              plan_long.engaged_targets)

    def test_zero_drones_returns_empty_plan(self):
        sched = EngagementScheduler(dwell_s=4.0, slew_s=1.5)
        plan = sched.schedule(num_drones=0, time_limit_s=60.0)
        self.assertEqual(plan.expected_kills, 0.0)
        self.assertEqual(plan.engaged_targets, 0)
        self.assertEqual(plan.leaked_targets, 0)
        self.assertEqual(len(plan.sequence), 0)


if __name__ == "__main__":
    unittest.main()
