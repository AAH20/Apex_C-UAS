"""
C-UAS Platform CLI: Counter-UAS detection, tracking, engagement scheduling,
and forensic evidence generation.
"""

import argparse
import sys
from typing import Optional


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="c-uas",
        description="C-UAS Platform: Autonomous Counter-UAS Detection, Tracking, "
                    "Engagement Scheduling, and Airspace Forensics.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan-rf
    rf_p = subparsers.add_parser("scan-rf", help="Classify RF emitter protocol")
    rf_p.add_argument("--freq", type=float, default=2440.0, help="Frequency in MHz")
    rf_p.add_argument("--bw", type=float, default=20.0, help="Bandwidth in MHz")

    # detect-spoof
    subparsers.add_parser("detect-spoof", help="Evaluate GNSS telemetry for spoofing / meaconing")

    # track
    track_p = subparsers.add_parser("track", help="Predict drone intercept trajectory (EKF)")
    track_p.add_argument("--horizon", type=float, default=2.0, help="Prediction horizon in seconds")

    # schedule-engagement
    sched_p = subparsers.add_parser("schedule", help="Compute optimal engagement sequence")
    sched_p.add_argument("--num-drones", type=int, default=5, help="Number of detected drones")
    sched_p.add_argument("--dwell-s", type=float, default=4.0, help="Dwell seconds per target")
    sched_p.add_argument("--slew-s", type=float, default=1.5, help="Slew + reacquire seconds per hand-off")

    # generate-dossier
    doss_p = subparsers.add_parser("dossier", help="Generate signed airspace intrusion dossier")
    doss_p.add_argument("--target-id", type=str, default="UAV-ROGUE-00", help="Target identifier")
    doss_p.add_argument("--threat", type=str, default="CRITICAL", help="Threat classification")

    args = parser.parse_args(argv)

    if args.command == "scan-rf":
        from c_uas.detection.rf_classifier import RFSignalClassifier
        res = RFSignalClassifier.classify_frequency(args.freq, args.bw)
        print(f"[C-UAS] RF Classification for {args.freq} MHz:")
        print(f"  Protocol        : {res['protocol']}")
        print(f"  Threat Category : {res['threat_category']}")
        return 0

    elif args.command == "detect-spoof":
        from c_uas.detection.spoof_detector import GNSSSpoofDetector, GNSSMeasurement
        detector = GNSSSpoofDetector()
        nominal = GNSSMeasurement(carrier_to_noise_db_hz=42.0, pseudorange_rate_mps=10.0,
                                  clock_drift_ppm=0.05, num_satellites=10)
        r1 = detector.evaluate_telemetry(nominal)
        print(f"[C-UAS] Nominal GNSS: Threat={r1['threat_level']}, Flags={r1['anomaly_flags']}")
        spoofed = GNSSMeasurement(carrier_to_noise_db_hz=60.0, pseudorange_rate_mps=0.0,
                                  clock_drift_ppm=3.8, num_satellites=2)
        r2 = detector.evaluate_telemetry(spoofed)
        print(f"[C-UAS] Spoofed GNSS: Threat={r2['threat_level']}, Flags={r2['anomaly_flags']}")
        return 0

    elif args.command == "track":
        from c_uas.tracking.ekf_interceptor import EKFTrajectoryPredictor
        ekf = EKFTrajectoryPredictor(dt=0.1)
        for i in range(10):
            ekf.update_measurement(10.0 + i * 2.0, 50.0 + i * 1.5, 120.0 - i * 0.5)
        pred = ekf.predict_intercept(args.horizon)
        print(f"[C-UAS] EKF Drone State: Pos=({ekf.state.x:.1f}, {ekf.state.y:.1f}, {ekf.state.z:.1f})")
        print(f"[C-UAS] Predicted Intercept at T+{args.horizon}s: {pred}")
        return 0

    elif args.command == "schedule":
        from c_uas.engagement.scheduler import EngagementScheduler
        sched = EngagementScheduler(dwell_s=args.dwell_s, slew_s=args.slew_s)
        plan = sched.schedule(num_drones=args.num_drones)
        print(f"[C-UAS] Engagement Schedule: {args.num_drones} drones")
        print(f"  Expected kills : {plan.expected_kills:.1f}")
        print(f"  Total time     : {plan.total_time_s:.1f}s")
        print(f"  Leaked targets : {plan.leaked_targets}")
        return 0

    elif args.command == "dossier":
        from c_uas.forensics.airspace_dossier import AirspaceIntrusionDossier
        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id=args.target_id,
            protocol="DJI_OCUSYNC_4",
            threat_level=args.threat,
            coordinates_path=[{"x": 100.0, "y": 200.0, "z": 50.0}],
            rf_anomalies=["SPOOFED_BROADCAST_ID"],
        )
        print(f"[C-UAS] Dossier {dossier['dossier_id']}")
        print(f"  Admissibility : {dossier['admissibility']}")
        print(f"  Signature     : {dossier['signature'][:40]}...")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
