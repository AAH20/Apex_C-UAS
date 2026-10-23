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

    # competitive-landscape
    cl_p = subparsers.add_parser(
        "competitive-landscape",
        help="List global deployed counter-UAS systems with unit economics",
    )
    cl_p.add_argument(
        "--origin",
        type=str,
        default=None,
        help="Filter by origin country",
    )
    cl_p.add_argument(
        "--type",
        type=str,
        default=None,
        help="Filter by system type (directed_energy_laser, kinetic_missile, rf_jamming, rf_detection)",
    )

    # unit-economics
    ue_p = subparsers.add_parser(
        "unit-economics",
        help="Compute unit economics for C-UAS engagement types",
    )
    ue_p.add_argument(
        "--type",
        type=str,
        default="all",
        help="System type (directed_energy_laser, kinetic_missile, rf_jamming, software_only, all)",
    )

    # swarm
    sw_p = subparsers.add_parser(
        "swarm",
        help="Simulate a drone swarm and test scheduler saturation",
    )
    sw_p.add_argument(
        "--num-drones", type=int, default=16, help="Number of drones in swarm"
    )
    sw_p.add_argument(
        "--spread-s", type=float, default=10.0, help="Arrival spread in seconds"
    )
    sw_p.add_argument(
        "--speed-mps", type=float, default=30.0, help="Drone speed in m/s"
    )
    sw_p.add_argument(
        "--evasion", type=float, default=0.3, help="Evasion probability (0.0-1.0)"
    )
    sw_p.add_argument(
        "--seed", type=int, default=42, help="RNG seed"
    )

    # benchmarks
    bm_p = subparsers.add_parser(
        "benchmarks",
        help="Run performance benchmarks (scheduler, EKF, end-to-end, swarm saturation)",
    )
    bm_p.add_argument(
        "--max-drones", type=int, default=128, help="Max drone count for scheduler benchmark"
    )

    # governance
    gov_p = subparsers.add_parser(
        "governance",
        help="ISO 42001 AI governance for C-UAS systems",
    )
    gov_p.add_argument(
        "--action",
        type=str,
        default="report",
        help="Governance action: register-system, assess-risk, implement-control, log-evidence, record-incident, compliance-report",
    )
    gov_p.add_argument(
        "--name", type=str, default=None, help="AI system name (for register-system)"
    )
    gov_p.add_argument(
        "--module", type=str, default=None, help="Module path (for register-system)"
    )
    gov_p.add_argument(
        "--stage", type=str, default="operation", help="Lifecycle stage (for register-system)"
    )
    gov_p.add_argument(
        "--risk-level", type=str, default="medium", help="Risk level (for register-system)"
    )
    gov_p.add_argument(
        "--system-id", type=str, default=None, help="AI system ID (for risk/incident/evidence)"
    )
    gov_p.add_argument(
        "--description", type=str, default=None, help="Risk/incident description"
    )
    gov_p.add_argument(
        "--likelihood", type=str, default="medium", help="Risk likelihood: low/medium/high"
    )
    gov_p.add_argument(
        "--impact", type=str, default="medium", help="Risk impact: low/medium/high"
    )
    gov_p.add_argument(
        "--control-id", type=str, default=None, help="Annex A control ID (for implement-control)"
    )
    gov_p.add_argument(
        "--evidence", type=str, default=None, help="Evidence pointer (for implement-control/log-evidence)"
    )
    gov_p.add_argument(
        "--severity", type=str, default="medium", help="Incident severity: low/medium/high/critical"
    )

    # dew
    dew_p = subparsers.add_parser(
        "dew",
        help="Directed-energy beam modeling with atmospheric attenuation",
    )
    dew_p.add_argument(
        "--laser", type=str, default="fiber_50kw",
        help="Laser spec: fiber_50kw, fiber_100kw, solid_state_150kw, chemical_100kw",
    )
    dew_p.add_argument(
        "--range-m", type=float, default=3000.0, help="Range to target in meters"
    )
    dew_p.add_argument(
        "--material", type=str, default="aluminum",
        help="Target material: aluminum, carbon_fiber, plastic, composite",
    )
    dew_p.add_argument(
        "--rain-mm-hr", type=float, default=0.0, help="Rain rate in mm/hr"
    )
    dew_p.add_argument(
        "--visibility-km", type=float, default=20.0, help="Visibility in km"
    )

    # opendew
    od_p = subparsers.add_parser(
        "opendew",
        help="OpenDEW neural network signal classifier",
    )
    od_p.add_argument(
        "--samples", type=int, default=100,
        help="Number of IQ samples to classify"
    )

    # contract-readiness
    cr_p = subparsers.add_parser(
        "contract-readiness",
        help="Contract readiness: burn rate, CAC:LTV, MVP scope",
    )

    # api
    api_p = subparsers.add_parser(
        "api",
        help="Run the REST API server",
    )
    api_p.add_argument(
        "--host", type=str, default="127.0.0.1", help="Bind host"
    )
    api_p.add_argument(
        "--port", type=int, default=8000, help="Bind port"
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
            bearing_deg,
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

    elif args.command == "competitive-landscape":
        from c_uas.competitive_landscape import CUASDatabase

        db = CUASDatabase()
        systems = db.list_all()
        if args.origin:
            systems = db.list_by_origin(args.origin)
        if args.type:
            systems = db.list_by_type(args.type)
        summary = db.summary()
        print(f"[C-UAS] Global Counter-UAS Systems ({summary['total']} total, {summary['fielded']} fielded):")
        for s in systems:
            fielded_marker = " [FIELDED]" if s.is_fielded else " [demo]"
            print(f"  {s.name}{fielded_marker}")
            print(f"    Origin/Developer: {s.origin} — {s.developer}")
            print(f"    Type: {s.system_type} | Power: {s.power_class}")
            print(f"    Range: {s.effective_range_km if s.effective_range_km else 'n.d.'} km | Role: {s.role}")
            print(f"    Status: {s.public_status} | Crew: {s.operator_crew} | Power: {s.power_draw_class}")
            print()
        return 0

    elif args.command == "unit-economics":
        from c_uas.unit_economics import UnitEconomicsModel

        model = UnitEconomicsModel()
        if args.type == "all":
            results = model.compare_all()
            print(f"[C-UAS] Unit Economics Comparison (attacker drone cost: ${model.attacker_drone_cost_usd:,}):")
            for sys_type, econ in results.items():
                print(f"  {sys_type}:")
                print(f"    CPE: ${econ.total_cost_per_engagement_usd:,} per engagement")
                print(f"    Capital amortized: ${econ.capital_amortized_per_engagement_usd:,}")
                print(f"    Marginal: ${econ.marginal_cost_per_engagement_usd:,}")
                print(f"    Cost-exchange ratio vs drone: {econ.cost_exchange_ratio_vs_drone}x")
                print()
        else:
            method_map = {
                "directed_energy_laser": model.directed_energy_laser,
                "kinetic_missile": model.kinetic_missile,
                "rf_jamming": model.rf_jamming,
                "software_only": model.software_only,
            }
            if args.type not in method_map:
                print(f"[C-UAS] Unknown type: {args.type}")
                return 1
            econ = method_map[args.type]()
            print(f"[C-UAS] Unit Economics: {econ.system_type}")
            print(f"  CPE: ${econ.total_cost_per_engagement_usd:,} per engagement")
            print(f"  Capital amortized: ${econ.capital_amortized_per_engagement_usd:,}")
            print(f"  Marginal: ${econ.marginal_cost_per_engagement_usd:,}")
            print(f"  Cost-exchange ratio vs drone: {econ.cost_exchange_ratio_vs_drone}x")
            print(f"  Annual cost: ${econ.annual_cost_usd:,}")
            print(f"  Lifetime cost: ${econ.lifetime_cost_usd:,}")
        return 0

    elif args.command == "swarm":
        from c_uas.swarm import SwarmSimulator, SwarmConfig, saturate_scheduler
        from c_uas.engagement.scheduler import EngagementScheduler

        config = SwarmConfig(
            num_drones=args.num_drones,
            arrival_spread_s=args.spread_s,
            speed_mps=args.speed_mps,
            start_distance_km=2.0,
            evasion_probability=args.evasion,
            seed=args.seed,
        )
        sim = SwarmSimulator(config)
        tracks = sim.generate_tracks()
        summary = sim.summary()
        print(f"[C-UAS] Swarm Simulation ({summary['num_drones']} drones)")
        print(f"  Arrival spread   : {summary['arrival_spread_s']}s")
        print(f"  Speed            : {summary['speed_mps']} m/s")
        print(f"  Evasion prob     : {summary['evasion_probability']}")
        print(f"  Swarm density    : {summary['swarm_density_drones_per_s']} drones/s")
        print(f"  Seed             : {summary['seed']}")
        print(f"  Tracks generated : {len(tracks)}")
        print()

        # Run scheduler against the swarm
        scheduler = EngagementScheduler(dwell_s=4.0, slew_s=1.5, time_limit_s=40.0)
        from c_uas.engagement.scheduler import DroneTrack
        drone_tracks = [
            DroneTrack(
                track_id=t.track_id,
                arrival_time_s=t.arrival_time_s,
                pk_base=t.pk_base,
                priority=t.priority,
            )
            for t in tracks
        ]
        plan = scheduler.schedule(tracks=drone_tracks)
        print(f"[C-UAS] Engagement Results:")
        print(f"  Expected kills   : {plan.expected_kills:.2f}")
        print(f"  Engaged targets  : {plan.engaged_targets}")
        print(f"  Leaked targets   : {plan.leaked_targets}")
        print(f"  Leak rate        : {plan.leaked_targets / len(tracks):.1%}")
        print(f"  Total time       : {plan.total_time_s:.1f}s")
        return 0

    if args.command == "benchmarks":
        from c_uas.benchmarks.performance import BenchmarkSuite

        suite = BenchmarkSuite()
        result = suite.run_all()

        print(f"[C-UAS] Performance Benchmarks (max {args.max_drones} drones)")
        print()

        print("Scheduler (wall-clock time vs drone count):")
        for r in result.scheduler_results:
            print(f"  {r.num_drones:4d} drones: {r.scheduler_seconds*1000:6.2f}ms, "
                  f"kills={r.expected_kills:5.2f}, engaged={r.engaged_targets:3d}, "
                  f"leaked={r.leaked_targets:3d}, {r.drones_per_second:9.0f} drones/s")

        print()
        print(f"EKF tracking (horizon={result.ekf_result.horizon_s}s, "
              f"measurements={result.ekf_result.num_measurements}):")
        print(f"  Position error : {result.ekf_result.position_error_m:.2f}m")
        print(f"  Velocity error : {result.ekf_result.velocity_error_mps:.2f} m/s")
        print(f"  Compute time   : {result.ekf_result.compute_seconds*1000:.3f}ms")

        print()
        print(f"End-to-end pipeline ({result.end_to_end_result.pipeline_stages} stages):")
        print(f"  Total time   : {result.end_to_end_result.total_seconds*1000:.2f}ms")
        print(f"  Per stage    : {result.end_to_end_result.per_stage_ms:.2f}ms")
        print(f"  Dossier signed: {result.end_to_end_result.dossier_generated}")

        print()
        print("Swarm saturation (leak rate vs swarm size):")
        for count in sorted(result.swarm_saturation.keys()):
            print(f"  {count:4d} drones: {result.swarm_saturation[count]:.1%} leak rate")
        return 0

    if args.command == "governance":
        from c_uas.governance import (
            AISystemRegistry,
            AuditEvidenceChain,
            ComplianceReporter,
            ControlImplementation,
            IncidentManager,
            RiskAssessment,
        )

        reg = AISystemRegistry()
        assessor = RiskAssessment()
        controller = ControlImplementation()
        chain = AuditEvidenceChain()
        mgr = IncidentManager()

        action = args.action or "report"

        if action == "register-system":
            if not args.name or not args.module:
                print("[C-UAS] --name and --module required for register-system")
                return 1
            sid = reg.register(
                args.name,
                args.module,
                args.stage,
                args.risk_level,
            )
            print(f"[C-UAS] Registered AI system: {sid}")
            print(f"  Name        : {args.name}")
            print(f"  Module      : {args.module}")
            print(f"  Stage       : {args.stage}")
            print(f"  Risk level  : {args.risk_level}")
            return 0

        elif action == "assess-risk":
            if not args.system_id or not args.description:
                print("[C-UAS] --system-id and --description required for assess-risk")
                return 1
            risk = assessor.assess(
                args.system_id,
                args.description,
                args.likelihood,
                args.impact,
            )
            print(f"[C-UAS] Risk assessed: {risk.risk_id}")
            print(f"  System ID  : {risk.system_id}")
            print(f"  Description: {risk.description}")
            print(f"  Likelihood : {risk.likelihood}")
            print(f"  Impact     : {risk.impact}")
            print(f"  Risk level : {risk.risk_level}")
            print(f"  Status     : {risk.status}")
            chain.log("risk_assessment", {"risk_id": risk.risk_id}, args.system_id)
            return 0

        elif action == "implement-control":
            if not args.control_id or not args.evidence:
                print("[C-UAS] --control-id and --evidence required for implement-control")
                return 1
            ctrl = controller.implement(args.control_id, args.evidence)
            if ctrl is None:
                print(f"[C-UAS] Unknown control: {args.control_id}")
                return 1
            print(f"[C-UAS] Control implemented: {ctrl.control_id}")
            print(f"  Title     : {ctrl.title}")
            print(f"  Evidence  : {ctrl.implementation_evidence}")
            chain.log("control_implementation", {"control_id": ctrl.control_id}, None)
            return 0

        elif action == "log-evidence":
            if not args.evidence:
                print("[C-UAS] --evidence required for log-evidence")
                return 1
            entry = chain.log("manual_entry", {"note": args.evidence}, args.system_id)
            print(f"[C-UAS] Evidence logged: {entry.entry_id}")
            print(f"  Type       : manual_entry")
            print(f"  System ID  : {args.system_id or '(none)'}")
            print(f"  Entry hash : {entry.entry_hash[:16]}...")
            print(f"  Chain valid: {chain.verify_chain()}")
            return 0

        elif action == "record-incident":
            if not args.description:
                print("[C-UAS] --description required for record-incident")
                return 1
            inc = mgr.record(
                args.description,
                args.description,
                args.severity,
                args.system_id,
            )
            print(f"[C-UAS] Incident recorded: {inc.incident_id}")
            print(f"  Title     : {inc.title}")
            print(f"  Severity  : {inc.severity}")
            print(f"  Status    : {inc.status}")
            chain.log("incident", {"incident_id": inc.incident_id}, args.system_id)
            return 0

        elif action == "compliance-report":
            reporter = ComplianceReporter(reg, assessor, controller, chain, mgr)
            report = reporter.generate()
            print(f"[C-UAS] ISO 42001 Compliance Report")
            print(f"  Generated       : {report.generated_at:.0f}")
            print(f"  AI systems      : {report.total_ai_systems}")
            print(f"  Total risks     : {report.total_risks}")
            print(f"  Open risks      : {report.open_risks}")
            print(f"  Total controls  : {report.total_controls}")
            print(f"  Implemented     : {report.implemented_controls}")
            print(f"  Total incidents : {report.total_incidents}")
            print(f"  Open incidents  : {report.open_incidents}")
            print(f"  Compliance %    : {report.compliance_percentage}%")
            print(f"  Overall status  : {report.overall_status}")
            return 0

        else:
            print(f"[C-UAS] Unknown governance action: {action}")
            return 1

    if args.command == "dew":
        from c_uas.dew.atmospheric import (
            LASER_SPECS, AtmosphericConditions,
            time_to_kill_with_attenuation,
        )

        laser_name = args.laser
        if laser_name not in LASER_SPECS:
            print(f"[C-UAS] Unknown laser: {laser_name}")
            print(f"  Available: {', '.join(LASER_SPECS.keys())}")
            return 1

        spec = LASER_SPECS[laser_name]
        conditions = AtmosphericConditions(
            rainfall_mm_hr=args.rain_mm_hr,
            aerosol_visibility_km=args.visibility_km,
        )
        result = time_to_kill_with_attenuation(
            spec, range_m=args.range_m, target_material=args.material,
            conditions=conditions,
        )
        print(f"[C-UAS] DEW Time-to-Kill: {spec.name}")
        print(f"  Range         : {result['range_m']} m")
        print(f"  Material      : {result['material']}")
        print(f"  Dwell time    : {result['dwell_s']} s")
        print(f"  Fluence       : {result['fluence_j_cm2']} J/cm^2")
        print(f"  Required      : {result['required_fluence_j_cm2']} J/cm^2")
        print(f"  Transmission  : {result['transmission']}")
        print(f"  Attenuation   : {result['attenuation_db_km']} dB/km")
        print(f"  Spot size     : {result['spot_cm']} cm")
        return 0

    if args.command == "opendew":
        from c_uas.detection.opendew_classifier import (
            get_opendew_classifier,
        )
        import random

        clf = get_opendew_classifier()
        # Generate random IQ samples for testing
        samples = [random.uniform(-1.0, 1.0) for _ in range(args.samples)]
        result = clf.classify_iq(samples)
        print(f"[C-UAS] OpenDEW Signal Classification")
        print(f"  Available   : {result['available']}")
        print(f"  Method      : {result['method']}")
        print(f"  Predicted   : {result['predicted_class']}")
        print(f"  Confidence  : {result['confidence']}")
        if result["probabilities"]:
            print(f"  Probabilities:")
            for cls, prob in sorted(
                result["probabilities"].items(),
                key=lambda x: -x[1]
            )[:5]:
                print(f"    {cls}: {prob}")
        return 0

    if args.command == "contract-readiness":
        from c_uas.contract_readiness import ContractReadinessModel

        model = ContractReadinessModel()
        analysis = model.full_analysis()
        burn = analysis["burn_rate"]
        cac = analysis["cac_ltv"]
        frc = analysis["fastest_route_to_contract"]
        print(f"[C-UAS] Contract Readiness Analysis")
        print(f"  Burn rate     : ${burn['monthly_burn_usd']:,.0f}/month, "
              f"${burn['annual_burn_usd']:,.0f}/year")
        print(f"  Runway        : {burn['runway_months']} months, "
              f"${burn['total_runway_usd']:,.0f} total")
        print(f"  CAC           : ${cac['cac_usd']:,.0f}")
        print(f"  LTV           : ${cac['ltv_usd']:,.0f}")
        print(f"  CAC:LTV       : {cac['cac_ltv_ratio']:.4f} (viable: {cac['viable']})")
        print(f"  Payback       : {cac['payback_months']} months")
        print(f"  MVP build     : {analysis['mvp_scope']['total_weeks']} weeks")
        print(f"  Earliest contract: month {frc['earliest_contract_month']}")
        return 0

    if args.command == "api":
        import uvicorn  # type: ignore

        from c_uas.api.server import app

        print(f"[C-UAS] Starting API server on {args.host}:{args.port}")
        print(f"  Docs: http://{args.host}:{args.port}/docs")
        print(f"  ReDoc: http://{args.host}:{args.port}/redoc")
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    parser.print_help()
    return 1

if __name__ == "__main__":
    sys.exit(main())
