"""Tests for GNSS spoofing detector."""

import unittest

from c_uas.detection.spoof_detector import GNSSMeasurement, GNSSSpoofDetector


class TestGNSSSpoofDetector(unittest.TestCase):
    def test_nominal_gnss_not_spoofed(self):
        detector = GNSSSpoofDetector()
        measurement = GNSSMeasurement(
            carrier_to_noise_db_hz=42.0,
            pseudorange_rate_mps=10.0,
            clock_drift_ppm=0.05,
            num_satellites=10,
        )
        res = detector.evaluate_telemetry(measurement)
        self.assertFalse(res["spoof_detected"])
        self.assertEqual(res["threat_level"], "NOMINAL")
        self.assertEqual(res["anomaly_flags"], [])

    def test_high_rf_power_detected_as_spoof(self):
        detector = GNSSSpoofDetector()
        measurement = GNSSMeasurement(
            carrier_to_noise_db_hz=60.0,
            pseudorange_rate_mps=0.0,
            clock_drift_ppm=0.1,
            num_satellites=12,
        )
        res = detector.evaluate_telemetry(measurement)
        self.assertTrue(res["spoof_detected"])
        self.assertEqual(res["threat_level"], "CRITICAL")
        self.assertIn("ANOMALOUS_HIGH_RF_POWER_SPOOF", res["anomaly_flags"])

    def test_clock_drift_step_detected(self):
        detector = GNSSSpoofDetector()
        m1 = GNSSMeasurement(42.0, 10.0, 0.05, 10)
        detector.evaluate_telemetry(m1)
        m2 = GNSSMeasurement(42.0, 10.0, 3.0, 10)  # 2.95 ppm jump > 2.5 threshold
        res = detector.evaluate_telemetry(m2)
        self.assertTrue(res["spoof_detected"])
        self.assertIn("UNREALISTIC_CLOCK_DRIFT_STEP", res["anomaly_flags"])

    def test_insufficient_constellation_flagged(self):
        detector = GNSSSpoofDetector()
        measurement = GNSSMeasurement(
            carrier_to_noise_db_hz=42.0,
            pseudorange_rate_mps=10.0,
            clock_drift_ppm=0.1,
            num_satellites=2,
        )
        res = detector.evaluate_telemetry(measurement)
        self.assertFalse(res["spoof_detected"])  # alone not enough for spoof
        self.assertIn("INSUFFICIENT_CONSTELLATION_LOCK", res["anomaly_flags"])

    def test_combined_spoof_indicators_critical(self):
        detector = GNSSSpoofDetector()
        m1 = GNSSMeasurement(42.0, 10.0, 0.05, 10)
        detector.evaluate_telemetry(m1)
        # High power + clock drift jump + few satellites
        m2 = GNSSMeasurement(60.0, 0.0, 3.0, 2)
        res = detector.evaluate_telemetry(m2)
        self.assertTrue(res["spoof_detected"])
        self.assertEqual(res["threat_level"], "CRITICAL")
        self.assertGreaterEqual(len(res["anomaly_flags"]), 2)

    def test_cn0_threshold_configurable(self):
        detector = GNSSSpoofDetector(cn0_max_threshold=50.0)
        measurement = GNSSMeasurement(
            carrier_to_noise_db_hz=55.0,
            pseudorange_rate_mps=0.0,
            clock_drift_ppm=0.1,
            num_satellites=12,
        )
        res = detector.evaluate_telemetry(measurement)
        self.assertTrue(res["spoof_detected"])


if __name__ == "__main__":
    unittest.main()
