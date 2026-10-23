"""Tests for airspace intrusion forensic dossier."""

import unittest

from c_uas.forensics.airspace_dossier import AirspaceIntrusionDossier, SignedDossier


class TestAirspaceIntrusionDossier(unittest.TestCase):
    def test_generate_signed_dossier_returns_dict(self):
        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-ROGUE-44",
            protocol="DJI_OCUSYNC_4",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 100.0, "y": 200.0, "z": 50.0}],
            rf_anomalies=["SPOOFED_BROADCAST_ID"],
        )
        self.assertIsInstance(dossier, dict)
        self.assertIn("dossier_id", dossier)
        self.assertIn("signature", dossier)
        self.assertIn("admissibility", dossier)
        self.assertIn("timestamp_utc", dossier)
        self.assertIn("target_id", dossier)
        self.assertIn("rf_protocol", dossier)
        self.assertIn("threat_classification", dossier)
        self.assertIn("anomalies_detected", dossier)
        self.assertIn("trajectory_points", dossier)

    def test_dossier_id_format(self):
        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-001",
            protocol="MAVLINK_TELEMETRY_SIK",
            threat_level="HIGH",
            coordinates_path=[],
            rf_anomalies=[],
        )
        self.assertTrue(dossier["dossier_id"].startswith("C-UAS-"))
        self.assertIn("UAV-001", dossier["dossier_id"])

    def test_admissibility_is_legal_defense_grade(self):
        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-001",
            protocol="DJI_OCUSYNC_4",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 1.0, "y": 2.0, "z": 3.0}],
            rf_anomalies=["GPS_SPOOF_DETECTED"],
        )
        self.assertEqual(dossier["admissibility"], "LEGAL_DEFENSE_GRADE")

    def test_signature_is_ed25519(self):
        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-001",
            protocol="EXPRESS_LRS_LONG_RANGE",
            threat_level="MEDIUM",
            coordinates_path=[{"x": 10.0, "y": 20.0, "z": 30.0}],
            rf_anomalies=["SIGNAL_ANOMALY"],
        )
        # Ed25519 signatures are 64 bytes = 128 hex chars
        sig = dossier["signature"]
        self.assertEqual(len(sig), 128)
        # All hex characters
        int(sig, 16)

    def test_compliance_standards_present(self):
        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-001",
            protocol="DJI_OCUSYNC_4",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 1.0, "y": 2.0, "z": 3.0}],
            rf_anomalies=[],
        )
        self.assertIn("compliance_standards", dossier)
        standards = dossier["compliance_standards"]
        self.assertTrue(any("FAA" in s for s in standards))
        self.assertTrue(any("DOD" in s for s in standards))

    def test_deterministic_for_same_input(self):
        # Same input should produce same dossier content (except timestamp)
        d1 = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-001",
            protocol="DJI_OCUSYNC_4",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 1.0, "y": 2.0, "z": 3.0}],
            rf_anomalies=["SPOOF"],
        )
        d2 = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-001",
            protocol="DJI_OCUSYNC_4",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 1.0, "y": 2.0, "z": 3.0}],
            rf_anomalies=["SPOOF"],
        )
        # Different timestamps, but same signature content structure
        self.assertEqual(d1["target_id"], d2["target_id"])
        self.assertEqual(d1["rf_protocol"], d2["rf_protocol"])
        self.assertEqual(d1["threat_classification"], d2["threat_classification"])

    def test_signed_dossier_dataclass(self):
        sd = SignedDossier(
            dossier_id="C-UAS-123-UAV-001",
            signature="a" * 128,
            admissibility="LEGAL_DEFENSE_GRADE",
        )
        self.assertEqual(sd.dossier_id, "C-UAS-123-UAV-001")
        self.assertEqual(len(sd.signature), 128)
        self.assertEqual(sd.admissibility, "LEGAL_DEFENSE_GRADE")

    def test_tamper_evident_hash_changes_with_content(self):
        d1 = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-001",
            protocol="DJI_OCUSYNC_4",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 1.0, "y": 2.0, "z": 3.0}],
            rf_anomalies=["SPOOF"],
        )
        d2 = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-002",  # Different target
            protocol="DJI_OCUSYNC_4",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 1.0, "y": 2.0, "z": 3.0}],
            rf_anomalies=["SPOOF"],
        )
        # Different content = different hash
        self.assertNotEqual(d1["tamper_evident_hash"], d2["tamper_evident_hash"])


if __name__ == "__main__":
    unittest.main()
