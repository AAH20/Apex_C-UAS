"""Tests for the performance benchmark suite."""

import unittest

from c_uas.benchmarks.performance import BenchmarkSuite


class TestBenchmarkSuite(unittest.TestCase):
    def setUp(self):
        self.suite = BenchmarkSuite()

    def test_scheduler_benchmark_structure(self):
        results = self.suite.benchmark_scheduler(drone_counts=[4, 8, 16])
        self.assertEqual(len(results), 3)
        for r in results:
            self.assertIsInstance(r.num_drones, int)
            self.assertGreaterEqual(r.scheduler_seconds, 0.0)
            self.assertGreaterEqual(r.expected_kills, 0.0)
            self.assertGreaterEqual(r.drones_per_second, 0.0)

    def test_scheduler_scales_linear_or_better(self):
        # Scheduler should be fast: under 1 second for 128 drones
        results = self.suite.benchmark_scheduler(drone_counts=[128])
        self.assertEqual(len(results), 1)
        self.assertLess(results[0].scheduler_seconds, 1.0)

    def test_ekf_benchmark_structure(self):
        result = self.suite.benchmark_ekf()
        self.assertGreaterEqual(result.position_error_m, 0.0)
        self.assertGreaterEqual(result.velocity_error_mps, 0.0)
        self.assertGreaterEqual(result.compute_seconds, 0.0)
        self.assertEqual(result.num_measurements, 50)
        self.assertEqual(result.horizon_s, 2.0)

    def test_ekf_accuracy(self):
        # EKF alpha-beta filter tracks with realistic error under +/-1m measurement noise
        result = self.suite.benchmark_ekf(num_measurements=100)
        self.assertLess(result.position_error_m, 25.0)

    def test_end_to_end_benchmark(self):
        result = self.suite.benchmark_end_to_end()
        self.assertEqual(result.pipeline_stages, 7)
        self.assertGreaterEqual(result.total_seconds, 0.0)
        self.assertGreaterEqual(result.per_stage_ms, 0.0)
        self.assertTrue(result.dossier_generated)

    def test_swarm_saturation(self):
        saturation = self.suite.benchmark_swarm_saturation(drone_counts=[8, 16, 32])
        self.assertEqual(len(saturation), 3)
        for _count, leak_rate in saturation.items():
            self.assertGreaterEqual(leak_rate, 0.0)
            self.assertLessEqual(leak_rate, 1.0)

    def test_run_all(self):
        result = self.suite.run_all()
        self.assertGreaterEqual(len(result.scheduler_results), 1)
        self.assertIsNotNone(result.ekf_result)
        self.assertIsNotNone(result.end_to_end_result)
        self.assertGreaterEqual(len(result.swarm_saturation), 1)


if __name__ == "__main__":
    unittest.main()
