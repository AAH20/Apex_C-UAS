"""Tests for RF signal classifier."""

import unittest
from c_uas.detection.rf_classifier import RFSignalClassifier


class TestRFSignalClassifier(unittest.TestCase):
    def test_classifies_dji_ocusync(self):
        res = RFSignalClassifier.classify_frequency(2450.0, 20.0)
        self.assertTrue(res["matched"])
        self.assertEqual(res["protocol"], "DJI_OCUSYNC_4")
        self.assertEqual(res["threat_category"], "HIGH_END_CONSUMER_OR_RECON")

    def test_classifies_mavlink_telemetry(self):
        res = RFSignalClassifier.classify_frequency(920.0, 0.5)
        self.assertTrue(res["matched"])
        self.assertEqual(res["protocol"], "MAVLINK_TELEMETRY_SIK")
        self.assertEqual(res["threat_category"], "CUSTOM_AUTONOMOUS_UAV")

    def test_classifies_expresslrs(self):
        res = RFSignalClassifier.classify_frequency(869.0, 1.0)
        self.assertTrue(res["matched"])
        self.assertEqual(res["protocol"], "EXPRESS_LRS_LONG_RANGE")
        self.assertEqual(res["threat_category"], "HIGH_SPEED_FPV_INTERCEPT")

    def test_classifies_lora_telemetry(self):
        res = RFSignalClassifier.classify_frequency(433.5, 0.125)
        self.assertTrue(res["matched"])
        self.assertEqual(res["protocol"], "LORA_TELEMETRY_UAV")
        self.assertEqual(res["threat_category"], "LONG_RANGE_AUTONOMOUS_LOITER")

    def test_unknown_emitter_returns_unmatched(self):
        res = RFSignalClassifier.classify_frequency(5000.0, 10.0)
        self.assertFalse(res["matched"])
        self.assertEqual(res["protocol"], "UNKNOWN_RF_EMITTER")
        self.assertEqual(res["threat_category"], "UNIDENTIFIED")

    def test_returns_bandwidth_in_result(self):
        res = RFSignalClassifier.classify_frequency(2450.0, 40.0)
        self.assertEqual(res["bandwidth_mhz"], 40.0)
        self.assertEqual(res["frequency_mhz"], 2450.0)

    def test_boundary_frequencies(self):
        # Lower bound of DJI band
        res = RFSignalClassifier.classify_frequency(2400.0, 20.0)
        self.assertTrue(res["matched"])
        # Upper bound of DJI band
        res = RFSignalClassifier.classify_frequency(2483.0, 20.0)
        self.assertTrue(res["matched"])
        # Just outside DJI band
        res = RFSignalClassifier.classify_frequency(2484.0, 20.0)
        self.assertFalse(res["matched"])


if __name__ == "__main__":
    unittest.main()
