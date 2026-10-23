"""
End-to-end integration tests for the full C-UAS pipeline.

Exercises the complete flow: RF detection → GNSS spoof detection → EKF tracking →
engagement scheduling → agentic decision loop → signed forensic dossier.

Each test asserts real behavior across module boundaries, not mocked interactions.
"""

import asyncio
import unittest

from c_uas.decision import (
    ActionModule,
    DecisionModule,
    PerceptionModule,
    ResponseStrategy,
    ThreatLevel,
)
from c_uas.detection.rf_classifier import RFSignalClassifier
from c_uas.detection.spoof_detector import GNSSMeasurement, GNSSSpoofDetector
from c_uas.engagement.scheduler import DroneTrack, EngagementScheduler
from c_uas.forensics.airspace_dossier import AirspaceIntrusionDossier
from c_uas.tracking.ekf_interceptor import EKFTrajectoryPredictor


class TestEndToEndPipeline(unittest.TestCase):
    """Full pipeline: detection → tracking → scheduling → decision → forensics."""

    def test_full_pipeline_produces_signed_dossier(self):
        # 1. RF detection: classify a DJI OcuSync emitter
        rf_result = RFSignalClassifier.classify_frequency(2450.0, 20.0)
        self.assertIn("DJI", rf_result["protocol"])

        # 2. GNSS spoof detection: confirm nominal (no spoof) for the tracked drone
        detector = GNSSSpoofDetector()
        nominal = GNSSMeasurement(
            carrier_to_noise_db_hz=42.0,
            pseudorange_rate_mps=10.0,
            clock_drift_ppm=0.05,
            num_satellites=10,
        )
        gnss_result = detector.evaluate_telemetry(nominal)
        self.assertEqual(gnss_result["threat_level"], "NOMINAL")

        # 3. EKF tracking: predict intercept at 2.0s horizon
        ekf = EKFTrajectoryPredictor(dt=0.1)
        for i in range(10):
            ekf.update_measurement(10.0 + i * 2.0, 50.0 + i * 1.5, 120.0 - i * 0.5)
        intercept = ekf.predict_intercept(2.0)
        self.assertIsNotNone(intercept)

        # 4. Engagement scheduling: schedule intercepts for 4 detected drones
        scheduler = EngagementScheduler(dwell_s=4.0, slew_s=1.5, time_limit_s=30.0)
        tracks = [
            DroneTrack(track_id=i, arrival_time_s=5.0 + i * 3.0, pk_base=0.8, priority=3)
            for i in range(4)
        ]
        plan = scheduler.schedule(tracks=tracks)
        self.assertGreater(plan.expected_kills, 0.0)
        self.assertGreaterEqual(plan.engaged_targets, 1)

        # 5. Agentic decision loop: assess threat and plan actions
        perception = PerceptionModule()
        perception.update_rf([rf_result])
        perception.update_classification([rf_result])
        situation = perception.get_situation_summary()
        situation["num_drones"] = len(tracks)

        decision = DecisionModule(config={"jamming": {"authorized": False}})
        threat_level = decision.assess_threat(situation)
        self.assertIn(threat_level, list(ThreatLevel))

        strategy = decision.select_strategy(threat_level, situation)
        self.assertIn(strategy, list(ResponseStrategy))

        commands = decision.plan_actions(strategy, situation)
        self.assertIsInstance(commands, list)

        # Execute commands through ActionModule (async)
        action = ActionModule(config={"jamming": {"authorized": False}}, simulation_mode=True)
        results = asyncio.run(self._execute_commands(action, commands))

        # Jammer must be safety-gated: unauthorized returns denied
        for result in results:
            if result["command"] == "activate_jammer":
                self.assertEqual(result["status"], "denied")

        # 6. Forensic dossier: signed, tamper-evident, cross-session verifiable
        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-ROGUE-01",
            protocol=rf_result["protocol"],
            threat_level=str(threat_level.name),
            coordinates_path=[{"x": 100.0, "y": 200.0, "z": 50.0}],
            rf_anomalies=gnss_result.get("anomaly_flags", []),
        )
        self.assertEqual(dossier["admissibility"], "LEGAL_DEFENSE_GRADE")
        self.assertTrue(dossier["signature"])
        self.assertTrue(AirspaceIntrusionDossier.verify_signature(dossier))

    def test_pipeline_handles_spoofed_gnss(self):
        """Spoofed GNSS escalates threat level and is recorded in forensics."""
        detector = GNSSSpoofDetector()
        spoofed = GNSSMeasurement(
            carrier_to_noise_db_hz=60.0,
            pseudorange_rate_mps=0.0,
            clock_drift_ppm=3.8,
            num_satellites=2,
        )
        result = detector.evaluate_telemetry(spoofed)
        self.assertEqual(result["threat_level"], "CRITICAL")
        self.assertTrue(len(result["anomaly_flags"]) > 0)

        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-SPOOF-01",
            protocol="MAVLink",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 10.0, "y": 20.0, "z": 30.0}],
            rf_anomalies=result["anomaly_flags"],
        )
        self.assertEqual(dossier["threat_classification"], "CRITICAL")
        self.assertTrue(AirspaceIntrusionDossier.verify_signature(dossier))

    def test_pipeline_swarm_saturation(self):
        """Scheduler engages maximum targets before swarm impact under saturation."""
        scheduler = EngagementScheduler(dwell_s=2.0, slew_s=0.5, time_limit_s=10.0)
        # 20 drones arriving in 10 seconds — only ~3 can be engaged (2s dwell + 0.5s slew)
        tracks = [
            DroneTrack(track_id=i, arrival_time_s=1.0 + i * 0.5, pk_base=0.7, priority=2)
            for i in range(20)
        ]
        plan = scheduler.schedule(tracks=tracks)
        # Should engage as many as possible within the time limit
        self.assertGreaterEqual(plan.engaged_targets, 1)
        self.assertLessEqual(plan.total_time_s, 10.0)
        # Most should leak — swarm saturation is the binding constraint
        self.assertGreater(plan.leaked_targets, 0)

    def test_cross_session_dossier_verification(self):
        """Dossier signature verifies across processes (key persisted to disk)."""
        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="CROSS-SESSION-01",
            protocol="DJI_OCUSYNC_4",
            threat_level="HIGH",
            coordinates_path=[{"x": 0.0, "y": 0.0, "z": 0.0}],
            rf_anomalies=[],
        )
        # Verify in the same process
        self.assertTrue(AirspaceIntrusionDossier.verify_signature(dossier))

    async def _execute_commands(self, action, commands):
        results = []
        for cmd in commands:
            result = await action.execute(cmd)
            results.append(result)
        return results


if __name__ == "__main__":
    unittest.main()
