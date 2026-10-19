"""Tests for EKF trajectory predictor."""

import unittest
from c_uas.tracking.ekf_interceptor import EKFTrajectoryPredictor, DroneState3D


class TestEKFTrajectoryPredictor(unittest.TestCase):
    def test_initial_state_is_zero(self):
        ekf = EKFTrajectoryPredictor(dt=0.1)
        self.assertEqual(ekf.state.x, 0.0)
        self.assertEqual(ekf.state.y, 0.0)
        self.assertEqual(ekf.state.z, 0.0)
        self.assertFalse(ekf.initialized)

    def test_update_sets_initial_position(self):
        ekf = EKFTrajectoryPredictor(dt=0.1)
        ekf.update_measurement(10.0, 20.0, 30.0)
        self.assertTrue(ekf.initialized)
        self.assertEqual(ekf.state.x, 10.0)
        self.assertEqual(ekf.state.y, 20.0)
        self.assertEqual(ekf.state.z, 30.0)

    def test_converges_to_constant_velocity(self):
        ekf = EKFTrajectoryPredictor(dt=0.1)
        # Constant velocity along X: 20 m/s (2.0m every 0.1s)
        for i in range(20):
            ekf.update_measurement(10.0 + i * 2.0, 0.0, 100.0)
        # Velocity should converge near 20 m/s
        self.assertGreater(ekf.state.vx, 15.0)
        self.assertLess(ekf.state.vx, 25.0)

    def test_predict_intercept_moves_forward(self):
        ekf = EKFTrajectoryPredictor(dt=0.1)
        for i in range(15):
            ekf.update_measurement(10.0 + i * 2.0, 0.0, 100.0)
        start_x = ekf.state.x
        ix, iy, iz = ekf.predict_intercept(1.0)
        # Predicted intercept X should be greater than current state X
        self.assertGreater(ix, start_x)
        # Y and Z should stay approximately constant
        self.assertAlmostEqual(iy, 0.0, places=1)
        self.assertAlmostEqual(iz, 100.0, places=1)

    def test_predict_intercept_horizon_scales(self):
        ekf = EKFTrajectoryPredictor(dt=0.1)
        for i in range(15):
            ekf.update_measurement(10.0 + i * 2.0, 0.0, 100.0)
        ix_1, _, _ = ekf.predict_intercept(1.0)
        ix_2, _, _ = ekf.predict_intercept(2.0)
        # Longer horizon = further intercept
        self.assertGreater(ix_2, ix_1)

    def test_drone_state_dataclass_fields(self):
        state = DroneState3D(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 0.1, 0.2, 0.3)
        self.assertEqual(state.x, 1.0)
        self.assertEqual(state.y, 2.0)
        self.assertEqual(state.z, 3.0)
        self.assertEqual(state.vx, 4.0)
        self.assertEqual(state.vy, 5.0)
        self.assertEqual(state.vz, 6.0)
        self.assertEqual(state.ax, 0.1)
        self.assertEqual(state.ay, 0.2)
        self.assertEqual(state.az, 0.3)

    def test_returns_rounded_coordinates(self):
        ekf = EKFTrajectoryPredictor(dt=0.1)
        ekf.update_measurement(10.0, 20.0, 30.0)
        ix, iy, iz = ekf.predict_intercept(0.5)
        # Coordinates rounded to 2 decimal places
        self.assertEqual(ix, round(ix, 2))
        self.assertEqual(iy, round(iy, 2))
        self.assertEqual(iz, round(iz, 2))


if __name__ == "__main__":
    unittest.main()
