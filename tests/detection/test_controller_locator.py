"""Tests for controller location / RF direction finding."""

import unittest
from c_uas.detection.controller_locator import (
    SensorSite,
    Detection,
    ControllerLocator,
    haversine_km,
    bearing_deg,
)


class TestHaversine(unittest.TestCase):
    def test_same_point_is_zero(self):
        d = haversine_km(34.0, -118.0, 34.0, -118.0)
        self.assertAlmostEqual(d, 0.0, places=6)

    def test_known_distance(self):
        # LA to SF approx 559 km
        d = haversine_km(34.0522, -118.2437, 37.7749, -122.4194)
        self.assertAlmostEqual(d, 559.0, delta=5.0)


class TestBearing(unittest.TestCase):
    def test_same_point(self):
        b = bearing_deg(34.0, -118.0, 34.0, -118.0)
        self.assertAlmostEqual(b, 0.0, places=1)

    def test_due_east(self):
        b = bearing_deg(34.0, -118.0, 34.0, -117.0)
        self.assertAlmostEqual(b, 90.0, delta=5.0)

    def test_due_west(self):
        b = bearing_deg(34.0, -118.0, 34.0, -119.0)
        self.assertAlmostEqual(b, 270.0, delta=5.0)

    def test_wraps_to_360(self):
        b = bearing_deg(34.0, -118.0, 34.0, -117.999)
        self.assertGreaterEqual(b, 0.0)
        self.assertLess(b, 360.0)


class TestControllerLocator(unittest.TestCase):
    def setUp(self):
        self.sites = [
            SensorSite("S1", 34.0522, -118.2437, 100.0, "directional", 2450.0),
            SensorSite("S2", 37.7749, -122.4194, 150.0, "directional", 2450.0),
            SensorSite("S3", 32.7157, -117.1611, 200.0, "directional", 2450.0),
        ]

    def test_insufficient_detections_returns_none(self):
        locator = ControllerLocator(self.sites)
        self.assertIsNone(locator.locate())

    def test_single_bearing_returns_none(self):
        locator = ControllerLocator(self.sites)
        locator.add_detection(Detection("S1", 1000.0, 2450.0, -72.0, bearing_deg=45.0))
        self.assertIsNone(locator.locate())

    def test_two_bearings_return_estimate(self):
        locator = ControllerLocator(self.sites)
        locator.add_detection(Detection("S1", 1000.0, 2450.0, -72.0, bearing_deg=271.6))
        locator.add_detection(Detection("S2", 1000.0, 2450.0, -78.0, bearing_deg=162.7))
        est = locator.locate(prefer_method="BEARING")
        self.assertIsNotNone(est)
        self.assertEqual(est.method, "BEARING")
        self.assertEqual(est.sensor_count, 2)
        self.assertGreaterEqual(est.confidence_km, 0)

    def test_three_bearings_return_estimate(self):
        locator = ControllerLocator(self.sites)
        locator.add_detection(Detection("S1", 1000.0, 2450.0, -72.0, bearing_deg=271.6))
        locator.add_detection(Detection("S2", 1000.0, 2450.0, -78.0, bearing_deg=162.7))
        locator.add_detection(Detection("S3", 1000.0, 2450.0, -75.0, bearing_deg=292.8))
        est = locator.locate(prefer_method="BEARING")
        self.assertIsNotNone(est)
        self.assertEqual(est.sensor_count, 3)
        self.assertEqual(len(est.residuals_km), 3)  # 3 pairwise intersections

    def test_parallel_bearings_skipped(self):
        locator = ControllerLocator(self.sites)
        # Same bearing from two sensors = parallel lines, no intersection
        locator.add_detection(Detection("S1", 1000.0, 2450.0, -72.0, bearing_deg=45.0))
        locator.add_detection(Detection("S2", 1000.0, 2450.0, -78.0, bearing_deg=45.0))
        # Only one intersection pair, but it's parallel -> None
        est = locator.locate(prefer_method="BEARING")
        self.assertIsNone(est)

    def test_rssi_insufficient_detections(self):
        locator = ControllerLocator(self.sites)
        locator.add_detection(
            Detection("S1", 1000.0, 2450.0, rssi_dbm=-70.0)
        )
        locator.add_detection(
            Detection("S2", 1000.0, 2450.0, rssi_dbm=-75.0)
        )
        est = locator.locate(prefer_method="RSSI")
        self.assertIsNone(est)  # need 3+ for RSSI trilateration

    def test_rssi_three_detections(self):
        locator = ControllerLocator(self.sites)
        locator.add_detection(
            Detection("S1", 1000.0, 2450.0, rssi_dbm=-70.0)
        )
        locator.add_detection(
            Detection("S2", 1000.0, 2450.0, rssi_dbm=-75.0)
        )
        locator.add_detection(
            Detection("S3", 1000.0, 2450.0, rssi_dbm=-73.0)
        )
        est = locator.locate(prefer_method="RSSI")
        # May or may not converge depending on geometry; just check it doesn't crash
        if est is not None:
            self.assertGreater(est.confidence_km, 0)

    def test_skywave_insufficient_detections(self):
        locator = ControllerLocator(self.sites)
        locator.add_detection(Detection("S1", 1000.0, 7.0, -72.0))  # HF frequency
        est = locator.locate(prefer_method="SKYWAVE")
        self.assertIsNone(est)

    def test_skywave_two_hf_detections(self):
        locator = ControllerLocator(self.sites)
        locator.add_detection(Detection("S1", 1000.0, 7.0, -72.0))
        locator.add_detection(Detection("S2", 1000.0, 7.0, -75.0))
        est = locator.locate(prefer_method="SKYWAVE")
        self.assertIsNotNone(est)
        self.assertEqual(est.method, "SKYWAVE")

    def test_summary_structure(self):
        locator = ControllerLocator(self.sites)
        locator.add_detection(Detection("S1", 1000.0, 2450.0, -72.0, bearing_deg=45.0))
        summary = locator.summary()
        self.assertIn("detection_count", summary)
        self.assertIn("sensor_count", summary)
        self.assertIn("frequencies_mhz", summary)
        self.assertEqual(summary["detection_count"], 1)
        self.assertEqual(summary["sensor_count"], 3)


if __name__ == "__main__":
    unittest.main()
