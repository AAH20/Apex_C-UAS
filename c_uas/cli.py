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
    subparsers.add_parser(
        "detect-spoof", help="Evaluate GNSS telemetry for spoofing / meaconing"
    )

    # track
    track_p = subparsers.add_parser(
        "track", help="Predict drone intercept trajectory (EKF)"
    )
    track_p.add_argument("--horizon", type=float, default=2.0, help="Prediction horizon in seconds")

    # schedule-engagement
    sched_p = subparsers.add_parser(
        "schedule", help="Compute optimal engagement sequence"
    )
    sched_p.add_argument("--num-drones", type=int, default=5, help="Number of detected drones")
    sched_p.add_argument("--dwell-s", type=float, default=4.0, help="Dwell seconds per target")
    sched_p.add_argument(
        "--slew-s", type=float, default=1.5, help="Slew + reacquire seconds per hand-off"
    )

    # generate-dossier
    doss_p = subparsers.add_parser(
        "dossier", help="Generate signed airspace intrusion dossier"
    )
    doss_p.add_argument(
        "--target-id", type=str, default="UAV-ROGUE-00", help="Target identifier"
    )
    doss_p.add_argument(
        "--threat", type=str, default="CRITICAL", help="Threat classification"
    )

    # mavlink-vulns
    mv_p = subparsers.add_parser(
        "mavlink-vulns", help="List MAVLink protocol vulnerabilities"
    )
    mv_p.add_argument(
        "--severity",
        type=str,
        default=None,
        help="Filter by severity (LOW/MEDIUM/HIGH/CRITICAL)",
    )
    mv_p.add_argument(
        "--version",
        type=str,
        default=None,
        help="Filter by MAVLink version (1.0/2.0/both)",
    )

    # locate-controller
    lc_p = subparsers.add_parser(
        "locate-controller",
        help="Estimate controller geolocation from RF detections",
    )
    lc_p.add_argument(
        "--method",
        type=str,
        default=None,
        help="Location method (TDOA/BEARING/RSSI/SKYWAVE)",
    )

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
        nominal = GNSSMeasurement(
            carrier_to_noise_db_hz=42.0,
            pseudorange_rate_mps=10.0,
            clock_drift_ppm=0.05,
            num_satellites=10,
        )
        r1 = detector.evaluate_telemetry(nominal)
        print(
            f"[C-UAS] Nominal GNSS: Threat={r1['threat_level']}, Flags={r1['anomaly_flags']}"
        )
        spoofed = GNSSMeasurement(
            carrier_to_noise_db_hz=60.0,
            pseudorange_rate_mps=0.0,
            clock_drift_ppm=3.8,
            num_satellites=2,
        )
        r2 = detector.evaluate_telemetry(spoofed)
        print(
            f"[C-UAS] Spoofed GNSS: Threat={r2['threat_level']}, Flags={r2['anomaly_flags']}"
        )
        return 0

    elif args.command == "track":
        from c_uas.tracking.ekf_interceptor import EKFTrajectoryPredictor

        ekf = EKFTrajectoryPredictor(dt=0.1)
        for i in range(10):
            ekf.update_measurement(10.0 + i * 2.0, 50.0 + i * 1.5, 120.0 - i * 0.5)
        pred = ekf.predict_intercept(args.horizon)
        print(
            f"[C-UAS] EKF Drone State: Pos=({ekf.state.x:.1f}, {ekf.state.y:.1f}, {ekf.state.z:.1f})"
        )
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

    elif args.command == "mavlink-vulns":
        from c_uas.detection.mavlink_vulns import MavlinkVulnerabilityDatabase

        db = MavlinkVulnerabilityDatabase()
        vulns = db.list_all()
        if args.severity:
            vulns = db.list_by_severity(args.severity.upper())
        if args.version:
            vulns = db.list_by_version(args.version.lower())
        print(f"[C-UAS] MAVLink Vulnerabilities ({len(vulns)} entries):")
        for v in vulns:
            print(f"  {v.cve or 'N/A'}  [{v.severity}]  MAVLink {v.mavlink_version}")
            print(f"    {v.title}")
            print(f"    Messages: {', '.join(v.affected_messages)}")
            print(f"    Detection: {v.detection_signature[:80]}...")
            print()
        return 0

    elif args.command == "locate-controller":
        from c_uas.detection.controller_locator import (
            ControllerLocator,
            SensorSite,
            Detection,
        )

        # Example sensor deployment (geographically separated sites across California)
        sites = [
            SensorSite("S1", 34.0522, -118.2437, 100.0, "directional", 2450.0),  # Los Angeles
            SensorSite("S2", 37.7749, -122.4194, 150.0, "directional", 2450.0),  # San Francisco
            SensorSite("S3", 32.7157, -117.1611, 200.0, "directional", 2450.0),  # San Diego
        ]
        locator = ControllerLocator(sites)

        # Example detections: bearings converge on (34.0, -121.0)
        # Bearings computed from each sensor site to that target point.
        locator.add_detection(
            Detection("S1", 1000.0, 2450.0, -72.0, bearing_deg=271.6, snr_db=18.0)
        )
        locator.add_detection(
            Detection("S2", 1000.0, 2450.0, -78.0, bearing_deg=162.7, snr_db=15.0)
        )
        locator.add_detection(
            Detection("S3", 1000.0, 2450.0, -75.0, bearing_deg=292.8, snr_db=16.0)
        )

        est = locator.locate(prefer_method=args.method or "BEARING")
        if est:
            print(f"[C-UAS] Controller Location Estimate:")
            print(f"  Latitude    : {est.latitude_deg} deg")
            print(f"  Longitude   : {est.longitude_deg} deg")
            print(f"  Confidence  : +/- {est.confidence_km} km")
            print(f"  Method      : {est.method}")
            print(f"  Sensors     : {est.sensor_count}")
        else:
            print("[C-UAS] Insufficient detections for controller localization.")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
