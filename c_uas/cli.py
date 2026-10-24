"""
C-UAS Platform CLI: Counter-UAS detection, tracking, engagement scheduling,
and forensic evidence generation.
"""

import argparse
import sys
from typing import Dict, Optional


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
    sched_p.add_argument(
        "--slew-s", type=float, default=1.5, help="Slew + reacquire seconds per hand-off"
    )

    # generate-dossier
    doss_p = subparsers.add_parser("dossier", help="Generate signed airspace intrusion dossier")
    doss_p.add_argument("--target-id", type=str, default="UAV-ROGUE-00", help="Target identifier")
    doss_p.add_argument("--threat", type=str, default="CRITICAL", help="Threat classification")

    # mavlink-vulns
    mv_p = subparsers.add_parser("mavlink-vulns", help="List MAVLink protocol vulnerabilities")
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
        help=(
            "Filter by system type "
            "(directed_energy_laser, kinetic_missile, rf_jamming, rf_detection)"
        ),
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
    sw_p.add_argument("--num-drones", type=int, default=16, help="Number of drones in swarm")
    sw_p.add_argument("--spread-s", type=float, default=10.0, help="Arrival spread in seconds")
    sw_p.add_argument("--speed-mps", type=float, default=30.0, help="Drone speed in m/s")
    sw_p.add_argument("--evasion", type=float, default=0.3, help="Evasion probability (0.0-1.0)")
    sw_p.add_argument("--seed", type=int, default=42, help="RNG seed")

    # benchmarks
    bm_p = subparsers.add_parser(
        "benchmarks",
        help="Run performance benchmarks (scheduler, EKF, end-to-end, swarm saturation)",
    )
    bm_p.add_argument(
        "--max-drones", type=int, default=128, help="Max drone count for scheduler benchmark"
    )

    # chaos
    chaos_p = subparsers.add_parser(
        "chaos",
        help="Chaos / resilience testing: fault injection and resilience validation",
    )
    chaos_p.add_argument(
        "--scenario",
        action="store_true",
        help="List chaos scenarios (or show one with --scenario-name)",
    )
    chaos_p.add_argument(
        "--run",
        action="store_true",
        help="Run a chaos scenario against the platform",
    )
    chaos_p.add_argument(
        "--report",
        action="store_true",
        help="Generate a resilience report with pass/fail and remediation",
    )
    chaos_p.add_argument(
        "--scenario-name",
        type=str,
        default=None,
        help="Scenario ID to run/report/show (default: all scenarios)",
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
        help=(
            "Governance action: register-system, assess-risk, "
            "implement-control, log-evidence, record-incident, "
            "compliance-report"
        ),
    )
    gov_p.add_argument(
        "--name", type=str, default=None, help="AI system name (for register-system)"
    )
    gov_p.add_argument("--module", type=str, default=None, help="Module path (for register-system)")
    gov_p.add_argument(
        "--stage", type=str, default="operation", help="Lifecycle stage (for register-system)"
    )
    gov_p.add_argument(
        "--risk-level", type=str, default="medium", help="Risk level (for register-system)"
    )
    gov_p.add_argument(
        "--system-id", type=str, default=None, help="AI system ID (for risk/incident/evidence)"
    )
    gov_p.add_argument("--description", type=str, default=None, help="Risk/incident description")
    gov_p.add_argument(
        "--likelihood", type=str, default="medium", help="Risk likelihood: low/medium/high"
    )
    gov_p.add_argument("--impact", type=str, default="medium", help="Risk impact: low/medium/high")
    gov_p.add_argument(
        "--control-id", type=str, default=None, help="Annex A control ID (for implement-control)"
    )
    gov_p.add_argument(
        "--evidence",
        type=str,
        default=None,
        help="Evidence pointer (for implement-control/log-evidence)",
    )
    gov_p.add_argument(
        "--severity", type=str, default="medium", help="Incident severity: low/medium/high/critical"
    )

    # grc-clab: agentic ISO 42001 governance engine
    grc_p = subparsers.add_parser(
        "grc-clab",
        help="Agentic ISO 42001 governance engine "
        "(AutonomousAgent, EvidenceAutoLogger, ComplianceMonitor, RemediationPlanner)",
    )
    grc_p.add_argument(
        "--action",
        type=str,
        default="report",
        help="GRC_Clab action: monitor, report, remediate, autolog",
    )
    grc_p.add_argument(
        "--event-type",
        type=str,
        default="detection",
        help="Event type for autolog: detection, tracking, engagement, forensics",
    )
    grc_p.add_argument(
        "--system-id", type=str, default=None, help="AI system ID (for autolog/remediate context)"
    )
    grc_p.add_argument(
        "--source", type=str, default="c_uas.grc_clab.cli", help="Event source (for autolog)"
    )
    grc_p.add_argument(
        "--description",
        type=str,
        default=None,
        help="Event description / payload note (for autolog)",
    )
    grc_p.add_argument(
        "--interval-s",
        type=float,
        default=300,
        help="Scan interval in seconds for the autonomous agent",
    )

    # dew
    dew_p = subparsers.add_parser(
        "dew",
        help="Directed-energy beam modeling with atmospheric attenuation",
    )
    dew_p.add_argument(
        "--laser",
        type=str,
        default="fiber_50kw",
        help="Laser spec: fiber_50kw, fiber_100kw, solid_state_150kw, chemical_100kw",
    )
    dew_p.add_argument("--range-m", type=float, default=3000.0, help="Range to target in meters")
    dew_p.add_argument(
        "--material",
        type=str,
        default="aluminum",
        help="Target material: aluminum, carbon_fiber, plastic, composite",
    )
    dew_p.add_argument("--rain-mm-hr", type=float, default=0.0, help="Rain rate in mm/hr")
    dew_p.add_argument("--visibility-km", type=float, default=20.0, help="Visibility in km")

    # opendew
    od_p = subparsers.add_parser(
        "opendew",
        help="OpenDEW neural network signal classifier",
    )
    od_p.add_argument("--samples", type=int, default=100, help="Number of IQ samples to classify")

    # contract-readiness
    _cr_p = subparsers.add_parser(
        "contract-readiness",
        help="Contract readiness: burn rate, CAC:LTV, MVP scope",
    )

    # api
    api_p = subparsers.add_parser(
        "api",
        help="Run the REST API server",
    )
    api_p.add_argument("--host", type=str, default="127.0.0.1", help="Bind host")
    api_p.add_argument("--port", type=int, default=8000, help="Bind port")

    # deploy
    dep_p = subparsers.add_parser(
        "deploy",
        help="Deploy the platform: Docker, Kubernetes, or config check",
    )
    dep_p.add_argument(
        "--docker",
        action="store_true",
        help="Build and run the API via Docker Compose",
    )
    dep_p.add_argument(
        "--k8s",
        action="store_true",
        help="Print Kubernetes deployment guidance",
    )
    dep_p.add_argument(
        "--config-check",
        action="store_true",
        help="Validate deployment configuration without deploying",
    )

    # dashboard
    db_p = subparsers.add_parser(
        "dashboard",
        help="Serve the SOC dashboard web interface",
    )
    db_p.add_argument("--host", type=str, default="127.0.0.1", help="Bind host")
    db_p.add_argument("--port", type=int, default=8080, help="Bind port")
    db_p.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the browser",
    )

    # orchestrate
    orch_p = subparsers.add_parser(
        "orchestrate",
        help="Run multi-site C-UAS orchestration round",
    )
    orch_p.add_argument("--sites", type=int, default=3, help="Number of federation sites")
    orch_p.add_argument("--drones", type=int, default=16, help="Number of drones in swarm")

    # agent-eval
    ae_p = subparsers.add_parser(
        "agent-eval",
        help="Run agent reliability evaluation harness",
    )
    ae_p.add_argument("--sites", type=int, default=3, help="Number of federation sites")
    ae_p.add_argument("--drones", type=int, default=16, help="Number of drones in swarm")

    # threat-intel
    ti_p = subparsers.add_parser(
        "threat-intel",
        help="STIX/TAXII threat intelligence export and alerting",
    )
    ti_p.add_argument(
        "--export",
        action="store_true",
        help="Build a STIX 2.1 bundle and print it",
    )
    ti_p.add_argument(
        "--serve",
        action="store_true",
        help="Run the TAXII 2.1 server",
    )
    ti_p.add_argument(
        "--alert",
        action="store_true",
        help="Run the alert engine on sample critical events",
    )
    ti_p.add_argument(
        "--test",
        action="store_true",
        help="Run a self-test of export, alerting, and TAXII routes",
    )

    # broker channel OS
    bk_p = subparsers.add_parser(
        "broker",
        help="Broker Channel OS: multi-tenant broker management, agent slots, campaigns",
    )
    bk_p.add_argument(
        "--action",
        type=str,
        required=True,
        help="register|allocate|revoke|campaign|analytics|list-tenants",
    )
    bk_p.add_argument("--name", type=str, default=None, help="Broker name (for register)")
    bk_p.add_argument(
        "--region", type=str, default=None, help="Broker region, e.g. UAE/KSA/MENA (for register)"
    )
    bk_p.add_argument(
        "--contact-email", type=str, default=None, help="Broker contact email (for register)"
    )
    bk_p.add_argument(
        "--whatsapp-number", type=str, default=None, help="WhatsApp number (for register)"
    )
    bk_p.add_argument(
        "--facebook-page-id",
        type=str,
        default=None,
        help="Facebook page ID (for register)",
    )
    bk_p.add_argument(
        "--max-agent-slots", type=int, default=330, help="Max agent slots per broker (for register)"
    )
    bk_p.add_argument(
        "--broker-id",
        type=str,
        default=None,
        help="Broker ID (for allocate/revoke/campaign/analytics)",
    )
    bk_p.add_argument("--slots", type=int, default=1, help="Agent slots to allocate or revoke")
    bk_p.add_argument(
        "--channel", type=str, default=None, help="facebook|whatsapp|sms|email (for campaign)"
    )
    bk_p.add_argument("--target-region", type=str, default=None, help="Campaign target region")
    bk_p.add_argument(
        "--message-template", type=str, default=None, help="Campaign message template"
    )
    bk_p.add_argument("--recipient-count", type=int, default=None, help="Campaign recipient count")
    bk_p.add_argument(
        "--campaign-id",
        type=str,
        default=None,
        help="Campaign ID (for campaign dispatch/analytics)",
    )

    # hardware
    hw_p = subparsers.add_parser(
        "hardware",
        help=(
            "Hardware abstraction layer: SDR, radar, camera sensors "
            "with simulation mode and track fusion"
        ),
    )
    hw_p.add_argument("--list", action="store_true", help="List sensors and capabilities")
    hw_p.add_argument("--scan", action="store_true", help="Run detection on all sensors")
    hw_p.add_argument("--fuse", action="store_true", help="Fuse detections into tracks")
    hw_p.add_argument("--status", action="store_true", help="Health-check all sensors")
    hw_p.add_argument("--seed", type=int, default=42, help="Deterministic RNG seed")

    # edge
    edge_p = subparsers.add_parser(
        "edge",
        help="Deploy and operate C-UAS edge nodes: local detection/tracking and edge-to-cloud sync",
    )
    edge_p.add_argument(
        "--deploy",
        action="store_true",
        help="Deploy edge node and run the first local detection cycle",
    )
    edge_p.add_argument(
        "--status", action="store_true", help="Show edge node health and sync state"
    )
    edge_p.add_argument(
        "--sync",
        action="store_true",
        help="Sync queued detections to the cloud endpoint",
    )
    edge_p.add_argument("--node-id", type=str, default=None, help="Edge node identifier")
    edge_p.add_argument(
        "--location",
        type=str,
        default=None,
        help="Site location (required for --deploy)",
    )
    edge_p.add_argument(
        "--sensors",
        type=str,
        default="sdr,radar,camera",
        help="Comma-separated sensor list (sdr, radar, camera)",
    )
    edge_p.add_argument(
        "--sync-interval",
        type=float,
        default=300.0,
        help="Cloud sync interval in seconds",
    )
    edge_p.add_argument("--cloud-endpoint", type=str, default=None, help="Cloud API base URL")
    edge_p.add_argument(
        "--offline",
        action="store_true",
        help="Run in offline mode (no cloud sync attempts)",
    )
    edge_p.add_argument("--seed", type=int, default=42, help="Deterministic RNG seed")

    # red-team
    rt_p = subparsers.add_parser(
        "red-team",
        help="Red team adversarial testing framework (GNSS spoofing, RF jamming, "
        "swarm saturation, coordinated attacks, controller hijacking)",
    )
    rt_p.add_argument(
        "--scenario",
        action="store_true",
        help="List adversarial scenarios (or show one with --scenario-name)",
    )
    rt_p.add_argument(
        "--run",
        action="store_true",
        help="Run an adversarial scenario against the platform",
    )
    rt_p.add_argument(
        "--report",
        action="store_true",
        help="Generate an adversarial test report with pass/fail and remediation",
    )
    rt_p.add_argument(
        "--scenario-name",
        type=str,
        default=None,
        help="Scenario ID to run/report/show (default: all scenarios)",
    )

    # performance
    perf_p = subparsers.add_parser(
        "performance",
        help="Performance optimization engine: baselines, bottlenecks, capacity "
        "planning, optimization recommendations",
    )
    perf_p.add_argument(
        "--baseline",
        action="store_true",
        help="Establish baseline performance metrics from real measured data",
    )
    perf_p.add_argument(
        "--bottlenecks",
        action="store_true",
        help="Detect performance bottlenecks and recommend optimizations",
    )
    perf_p.add_argument(
        "--capacity",
        action="store_true",
        help="Model scaling scenarios and predict resource requirements",
    )
    perf_p.add_argument(
        "--optimize",
        action="store_true",
        help="Generate actionable optimization recommendations",
    )
    perf_p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic RNG seed",
    )
    perf_p.add_argument(
        "--sites",
        type=int,
        default=4,
        help="Number of sites for capacity planning",
    )
    perf_p.add_argument(
        "--drones-per-site",
        type=int,
        default=16,
        help="Drones per site for capacity planning",
    )
    perf_p.add_argument(
        "--brokers",
        type=int,
        default=2,
        help="Number of brokers for capacity planning",
    )

    # perf
    perf_p = subparsers.add_parser(
        "perf",
        help="Production performance & scalability: benchmark, profile, SLA tracking",
    )
    perf_p.add_argument(
        "--benchmark",
        action="store_true",
        help="Run deterministic optimization kernels (A*, set cover, local search)",
    )
    perf_p.add_argument(
        "--profile",
        action="store_true",
        help="Profile per-endpoint latency/throughput and detect bottlenecks",
    )
    perf_p.add_argument(
        "--sla",
        action="store_true",
        help="Assess SLA compliance (p50/p95/p99 latency, error budget, recovery)",
    )
    perf_p.add_argument(
        "--module",
        type=str,
        default="default",
        help="Target module id for benchmark/profile/SLA (default: default)",
    )
    perf_p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic RNG seed",
    )

    # compliance
    cp_p = subparsers.add_parser(
        "compliance",
        help="Automated compliance evidence collection for ISO 42001 audits",
    )
    cp_p.add_argument(
        "--collect",
        action="store_true",
        help="Collect evidence from all platform components",
    )
    cp_p.add_argument(
        "--package",
        action="store_true",
        help="Package collected evidence into a signed EvidencePackage",
    )
    cp_p.add_argument(
        "--export",
        action="store_true",
        help="Export the latest signed package (requires --package or existing package)",
    )
    cp_p.add_argument(
        "--report",
        action="store_true",
        help="Generate ISO 42001 Annex A compliance report",
    )
    cp_p.add_argument(
        "--format",
        type=str,
        default="json",
        help="Export format: json or zip (default: json)",
    )
    cp_p.add_argument(
        "--out",
        type=str,
        default=None,
        help="Output path for exported package (default: stdout for json)",
    )

    # gateway
    gw_p = subparsers.add_parser(
        "gateway",
        help="API Gateway: multi-backend routing with health checks and circuit breakers",
    )
    gw_p.add_argument(
        "--status",
        action="store_true",
        help="Show gateway and backend status",
    )
    gw_p.add_argument(
        "--route",
        action="store_true",
        help="Resolve a routing decision",
    )
    gw_p.add_argument(
        "--health",
        action="store_true",
        help="Probe backend health",
    )
    gw_p.add_argument(
        "--backend",
        type=str,
        default=None,
        help="Backend ID or role (detection/tracking/engagement)",
    )
    gw_p.add_argument(
        "--strategy",
        type=str,
        default=None,
        help="round_robin | least_latency | failover",
    )
    gw_p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Deterministic seed",
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
        from c_uas.detection.spoof_detector import GNSSMeasurement, GNSSSpoofDetector

        detector = GNSSSpoofDetector()
        nominal = GNSSMeasurement(
            carrier_to_noise_db_hz=42.0,
            pseudorange_rate_mps=10.0,
            clock_drift_ppm=0.05,
            num_satellites=10,
        )
        r1 = detector.evaluate_telemetry(nominal)
        print(f"[C-UAS] Nominal GNSS: Threat={r1['threat_level']}, Flags={r1['anomaly_flags']}")
        spoofed = GNSSMeasurement(
            carrier_to_noise_db_hz=60.0,
            pseudorange_rate_mps=0.0,
            clock_drift_ppm=3.8,
            num_satellites=2,
        )
        r2 = detector.evaluate_telemetry(spoofed)
        print(f"[C-UAS] Spoofed GNSS: Threat={r2['threat_level']}, Flags={r2['anomaly_flags']}")
        return 0

    elif args.command == "track":
        from c_uas.tracking.ekf_interceptor import EKFTrajectoryPredictor

        ekf = EKFTrajectoryPredictor(dt=0.1)
        for i in range(10):
            ekf.update_measurement(10.0 + i * 2.0, 50.0 + i * 1.5, 120.0 - i * 0.5)
        pred = ekf.predict_intercept(args.horizon)
        print(
            "[C-UAS] EKF Drone State: "
            f"Pos=({ekf.state.x:.1f}, {ekf.state.y:.1f}, {ekf.state.z:.1f})"
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
            Detection,
            SensorSite,
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
            print("[C-UAS] Controller Location Estimate:")
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

        db = CUASDatabase()  # type: ignore[assignment]
        systems = db.list_all()  # type: ignore[attr-defined]
        if args.origin:
            systems = db.list_by_origin(args.origin)  # type: ignore[attr-defined]
        if args.type:
            systems = db.list_by_type(args.type)  # type: ignore[attr-defined]
        summary = db.summary()  # type: ignore[attr-defined]
        print(
            "[C-UAS] Global Counter-UAS Systems "
            f"({summary['total']} total, {summary['fielded']} fielded):"
        )
        for s in systems:  # type: ignore[attr-defined]
            fielded_marker = " [FIELDED]" if s.is_fielded else " [demo]"  # type: ignore[attr-defined]
            print(f"  {s.name}{fielded_marker}")  # type: ignore[attr-defined]
            print(f"    Origin/Developer: {s.origin} — {s.developer}")  # type: ignore[attr-defined]
            print(f"    Type: {s.system_type} | Power: {s.power_class}")  # type: ignore[attr-defined]
            print(
                "    Range: "
                f"{s.effective_range_km if s.effective_range_km else 'n.d.'} km "  # type: ignore[attr-defined]
                f"| Role: {s.role}"  # type: ignore[attr-defined]
            )
            print(
                "    Status: "
                f"{s.public_status} | Crew: {s.operator_crew} | "  # type: ignore[attr-defined]
                f"Power: {s.power_draw_class}"  # type: ignore[attr-defined]
            )
            print()
        return 0

    elif args.command == "unit-economics":
        from c_uas.unit_economics import UnitEconomicsModel

        model = UnitEconomicsModel()
        if args.type == "all":
            results = model.compare_all()
            print(
                f"[C-UAS] Unit Economics Comparison "
                f"(attacker drone cost: ${model.attacker_drone_cost_usd:,}):"
            )
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
        from c_uas.engagement.scheduler import EngagementScheduler
        from c_uas.swarm import SwarmConfig, SwarmSimulator

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
        print("[C-UAS] Engagement Results:")
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
            print(
                f"  {r.num_drones:4d} drones: {r.scheduler_seconds * 1000:6.2f}ms, "
                f"kills={r.expected_kills:5.2f}, engaged={r.engaged_targets:3d}, "
                f"leaked={r.leaked_targets:3d}, {r.drones_per_second:9.0f} drones/s"
            )

        print()
        print(
            f"EKF tracking (horizon={result.ekf_result.horizon_s}s, "
            f"measurements={result.ekf_result.num_measurements}):"
        )
        print(f"  Position error : {result.ekf_result.position_error_m:.2f}m")
        print(f"  Velocity error : {result.ekf_result.velocity_error_mps:.2f} m/s")
        print(f"  Compute time   : {result.ekf_result.compute_seconds * 1000:.3f}ms")

        print()
        print(f"End-to-end pipeline ({result.end_to_end_result.pipeline_stages} stages):")
        print(f"  Total time   : {result.end_to_end_result.total_seconds * 1000:.2f}ms")
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
            print("  Type       : manual_entry")
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
            print("[C-UAS] ISO 42001 Compliance Report")
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

    if args.command == "grc-clab":
        from c_uas.governance import (
            AISystemRegistry,
            AuditEvidenceChain,
            ComplianceReporter,
            ControlImplementation,
            IncidentManager,
            RiskAssessment,
        )
        from c_uas.grc_clab import (
            DEFAULT_SCAN_INTERVAL_S,
            ComplianceMonitor,
            EvidenceAutoLogger,
            GRCClabEngine,
            RemediationPlanner,
        )

        reg = AISystemRegistry()
        assessor = RiskAssessment()
        controller = ControlImplementation()
        chain = AuditEvidenceChain()
        mgr = IncidentManager()
        reporter = ComplianceReporter(reg, assessor, controller, chain, mgr)

        action = args.action or "report"
        _interval_s = args.interval_s or DEFAULT_SCAN_INTERVAL_S

        if action == "monitor":
            monitor = ComplianceMonitor(reporter)
            report, drift_delta, alerts = monitor.score()
            print("[C-UAS] GRC_Clab Compliance Monitor")
            print(f"  Compliance % : {report.compliance_percentage}%")
            print(f"  Status       : {report.overall_status}")
            print(f"  Open risks   : {report.open_risks}")
            print(f"  Open incidents: {report.open_incidents}")
            print(
                "  Controls     : "
                f"{report.implemented_controls}/{report.total_controls} implemented"
            )
            print(f"  Drift delta  : {drift_delta:+.1f} points")
            print(f"  Drift alerts : {len(alerts)}")
            for alert in alerts:
                print(f"    - {alert.severity.upper()}: {alert.description}")
            return 0

        if action == "report":
            engine = GRCClabEngine()
            engine.scheduled_report()
            report = reporter.generate()
            print("[C-UAS] GRC_Clab Scheduled Compliance Report")
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

        if action == "remediate":
            planner = RemediationPlanner(assessor, controller)
            plans = planner.plan_for_open_risks()  # type: ignore[assignment]
            print("[C-UAS] GRC_Clab Remediation Planner")
            if not plans:
                print(
                    "  No remediation plans proposed "
                    "(all open risks covered or controls implemented)."
                )
            for plan in plans:  # type: ignore[assignment]
                print(f"  Plan {plan.plan_id}:")  # type: ignore[attr-defined]
                print(f"    Risk ID   : {plan.risk_id}")  # type: ignore[attr-defined]
                print(f"    Control   : {plan.control_id}")  # type: ignore[attr-defined]
                print(f"    Rationale : {plan.rationale}")  # type: ignore[attr-defined]
                print(f"    Status    : {plan.status}")  # type: ignore[attr-defined]
            return 0

        if action == "autolog":
            logger = EvidenceAutoLogger(chain)
            event_type = args.event_type or "detection"
            payload = {"note": args.description or "auto-logged via CLI"}
            entry = logger.log_event(  # type: ignore[assignment]
                event_type, args.system_id, args.source or "c_uas.cli", payload
            )
            print("[C-UAS] GRC_Clab Evidence Auto-Logger")
            print(f"  Entry ID          : {entry.entry_id}")
            print(f"  Event type        : {entry.event_type}")
            print(f"  System ID         : {entry.system_id or '(none)'}")
            print(f"  Source            : {entry.source}")  # type: ignore[attr-defined]
            print(f"  Governance entry  : {entry.governance_entry_id}")  # type: ignore[attr-defined]
            print(f"  Chain valid       : {logger.verify_chain()}")
            return 0

        if action == "cycle":
            engine = GRCClabEngine()
            summary = engine.run_cycle()  # type: ignore[assignment]
            print("[C-UAS] GRC_Clab Agentic Cycle")
            print(f"  Scan trigger     : {summary['scan']['trigger']}")  # type: ignore[index]
            print(f"  Systems scanned  : {summary['scan']['systems_scanned']}")  # type: ignore[index]
            print(f"  New risks        : {len(summary['scan']['new_risk_ids'])}")  # type: ignore[index]
            print(f"  Compliance %     : {summary['compliance']['compliance_percentage']}%")  # type: ignore[index]
            print(f"  Status           : {summary['compliance']['overall_status']}")  # type: ignore[index]
            print(f"  Drift delta      : {summary['drift']['drift_delta']:+.1f} points")  # type: ignore[index]
            print(f"  Drift alerts     : {len(summary['drift']['alerts'])}")  # type: ignore[index]
            print(f"  Proposed plans   : {len(summary['remediation']['proposed_plans'])}")  # type: ignore[index]
            return 0

        print(f"[C-UAS] Unknown grc-clab action: {action}")
        return 1

    if args.command == "dew":
        from c_uas.dew.atmospheric import (
            LASER_SPECS,
            AtmosphericConditions,
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
        result = time_to_kill_with_attenuation(  # type: ignore[assignment]
            spec,
            range_m=args.range_m,
            target_material=args.material,
            conditions=conditions,
        )
        print(f"[C-UAS] DEW Time-to-Kill: {spec.name}")
        print(f"  Range         : {result['range_m']} m")  # type: ignore[index]
        print(f"  Material      : {result['material']}")  # type: ignore[index]
        print(f"  Dwell time    : {result['dwell_s']} s")  # type: ignore[index]
        print(f"  Fluence       : {result['fluence_j_cm2']} J/cm^2")  # type: ignore[index]
        print(f"  Required      : {result['required_fluence_j_cm2']} J/cm^2")  # type: ignore[index]
        print(f"  Transmission  : {result['transmission']}")  # type: ignore[index]
        print(f"  Attenuation   : {result['attenuation_db_km']} dB/km")  # type: ignore[index]
        print(f"  Spot size     : {result['spot_cm']} cm")  # type: ignore[index]
        return 0

    if args.command == "opendew":
        import random

        from c_uas.detection.opendew_classifier import (
            get_opendew_classifier,
        )

        clf = get_opendew_classifier()
        # Generate random IQ samples for testing
        samples = [random.uniform(-1.0, 1.0) for _ in range(args.samples)]
        result = clf.classify_iq(samples)  # type: ignore[assignment]
        print("[C-UAS] OpenDEW Signal Classification")
        print(f"  Available   : {result['available']}")  # type: ignore[index]
        print(f"  Method      : {result['method']}")  # type: ignore[index]
        print(f"  Predicted   : {result['predicted_class']}")  # type: ignore[index]
        print(f"  Confidence  : {result['confidence']}")  # type: ignore[index]
        if result["probabilities"]:  # type: ignore[index]
            print("  Probabilities:")
            for cls, prob in sorted(result["probabilities"].items(), key=lambda x: -x[1])[:5]:  # type: ignore[index]
                print(f"    {cls}: {prob}")
        return 0

    if args.command == "contract-readiness":
        from c_uas.contract_readiness import ContractReadinessModel

        model = ContractReadinessModel()  # type: ignore[assignment]
        analysis = model.full_analysis()  # type: ignore[assignment, attr-defined]
        burn = analysis["burn_rate"]  # type: ignore[index]
        cac = analysis["cac_ltv"]  # type: ignore[index]
        frc = analysis["fastest_route_to_contract"]  # type: ignore[index]
        print("[C-UAS] Contract Readiness Analysis")
        print(
            f"  Burn rate     : ${burn['monthly_burn_usd']:,.0f}/month, "
            f"${burn['annual_burn_usd']:,.0f}/year"
        )
        print(
            f"  Runway        : {burn['runway_months']} months, "
            f"${burn['total_runway_usd']:,.0f} total"
        )
        print(f"  CAC           : ${cac['cac_usd']:,.0f}")
        print(f"  LTV           : ${cac['ltv_usd']:,.0f}")
        print(f"  CAC:LTV       : {cac['cac_ltv_ratio']:.4f} (viable: {cac['viable']})")
        print(f"  Payback       : {cac['payback_months']} months")
        print(f"  MVP build     : {analysis['mvp_scope']['total_weeks']} weeks")
        print(f"  Earliest contract: month {frc['earliest_contract_month']}")
        return 0

    if args.command == "api":
        from c_uas.deployment.server import create_app, run

        create_app()
        print(f"[C-UAS] Starting API server on {args.host}:{args.port}")
        print(f"  Docs: http://{args.host}:{args.port}/docs")
        print(f"  ReDoc: http://{args.host}:{args.port}/redoc")
        print(f"  Health: http://{args.host}:{args.port}/healthz")
        print(f"  Metrics: http://{args.host}:{args.port}/metrics")
        run(host=args.host, port=args.port)
        return 0

    if args.command == "deploy":
        from c_uas.deployment.cli import deploy

        return deploy(
            docker=args.docker,
            k8s=args.k8s,
            check_config=args.config_check,
        )

    if args.command == "dashboard":
        from c_uas.dashboard.server import open_dashboard

        open_dashboard(args.host, args.port)
        return 0

    if args.command == "orchestrate":
        from c_uas.orchestration import build_demo_federation
        from c_uas.swarm import SwarmConfig

        config = SwarmConfig(
            num_drones=args.drones,
            arrival_spread_s=10.0,
            speed_mps=30.0,
            start_distance_km=2.0,
            evasion_probability=0.3,
            seed=42,
        )
        fed = build_demo_federation(num_sites=args.sites)
        result = fed.run_round(config)  # type: ignore[assignment]
        print("[C-UAS] Multi-Site Orchestration Round")
        print(f"  Sites          : {result['sites']}")  # type: ignore[index]
        print(f"  Drones         : {args.drones}")
        print(f"  Detections     : {result['detections']}")  # type: ignore[index]
        print(f"  Fusion         : {result['fusion']['total_tracks_ingested']} tracks ingested")  # type: ignore[index]
        print(f"  Tracks/site    : {result['fusion']['tracks_per_site']}")  # type: ignore[index]
        for sid, plan in result["engagement_plans"].items():  # type: ignore[index]
            print(
                f"  {sid} engagement: kills={plan['expected_kills']:.2f}, "  # type: ignore[index]
                f"engaged={plan['engaged_targets']}, leaked={plan['leaked_targets']}, "  # type: ignore[index]
                f"leak_rate={plan['leak_rate']:.1%}"  # type: ignore[index]
            )
        print(
            f"  Deconfliction  : {result['deconfliction']['conflicts_detected']} conflicts, "  # type: ignore[index]
            f"{result['deconfliction']['conflicts_resolved']} resolved"  # type: ignore[index]
        )
        return 0

    if args.command == "agent-eval":
        from evals.agent_eval_harness import AgentEvalHarness

        harness = AgentEvalHarness()
        summary = harness.run_all(num_sites=args.sites, num_drones=args.drones)
        print("[C-UAS] Agent Evaluation Harness")
        print(f"  Total          : {summary['total']}")
        print(f"  Passed         : {summary['passed']}")
        print(f"  Failed         : {summary['failed']}")
        print(f"  Pass rate      : {summary['pass_rate']:.1%}")
        for r in summary["results"]:  # type: ignore[attr-defined]
            status = "PASS" if r["passed"] else "FAIL"
            print(
                f"  [{status}] {r['name']}: {r['value']} "
                f"(threshold: {r['threshold']}) — {r['detail']}"
            )
        return 0

    if args.command == "threat-intel":
        from c_uas.forensics.airspace_dossier import AirspaceIntrusionDossier
        from c_uas.threat_intel import (
            AlertEngine,
            ChannelConfig,
            CompetitiveIntelEntry,
            ConsoleChannel,
            DetectionEvent,
            EmailStubChannel,
            ForensicDossierRef,
            STIXBundleBuilder,
            app_factory,
            bundle_hash,
        )
        from c_uas.threat_intel.alert_engine import Channel
        from c_uas.threat_intel.store import ThreatIntelStore

        if args.export:
            store = ThreatIntelStore()
            builder = STIXBundleBuilder()

            # Sample detection events covering RF + spoofing sources.
            events = [
                DetectionEvent(
                    event_id="DET-001",
                    timestamp="2026-10-23T10:15:00Z",
                    source="rf_classifier",
                    target_id="UAV-ROGUE-01",
                    threat_level="CRITICAL",
                    protocol="DJI_OCUSYNC_4",
                    confidence=0.94,
                    latitude=34.0522,
                    longitude=-118.2437,
                    anomalies=("SPOOFED_BROADCAST_ID",),
                ),
                DetectionEvent(
                    event_id="DET-002",
                    timestamp="2026-10-23T10:16:00Z",
                    source="spoof_detector",
                    target_id="UAV-ROGUE-02",
                    threat_level="CRITICAL",
                    protocol="GPS_L1_CA",
                    confidence=0.99,
                    latitude=34.0,
                    longitude=-121.0,
                    anomalies=("C_N0_ANOMALY", "CLOCK_DRIFT_STEP"),
                ),
                DetectionEvent(
                    event_id="DET-003",
                    timestamp="2026-10-23T10:17:00Z",
                    source="controller_locator",
                    target_id="UAV-ROGUE-01",
                    threat_level="HIGH",
                    protocol="EXPRESS_LRS_LONG_RANGE",
                    confidence=0.72,
                    latitude=34.0,
                    longitude=-121.0,
                ),
            ]
            for event in events:
                builder.add_detection_event(event)

            # Forensic dossier as Ed25519-signed evidence.
            dossier = AirspaceIntrusionDossier.generate_signed_dossier(
                target_id="UAV-ROGUE-01",
                protocol="DJI_OCUSYNC_4",
                threat_level="CRITICAL",
                coordinates_path=[{"x": 100.0, "y": 200.0, "z": 50.0}],
                rf_anomalies=["SPOOFED_BROADCAST_ID"],
            )
            dossier_ref = ForensicDossierRef(
                dossier_id=dossier["dossier_id"],
                target_id=dossier["target_id"],
                threat_classification=dossier["threat_classification"],
                signature=dossier["signature"],
                public_key_pem=dossier["public_key_pem"],
                tamper_evident_hash=dossier["tamper_evident_hash"],
                timestamp_utc=dossier["timestamp_utc"],
            )
            builder.add_forensic_dossier(dossier_ref)

            # Competitive intel entries.
            comp_entries = [
                CompetitiveIntelEntry(
                    name="DragonFire",
                    origin="United Kingdom",
                    developer="Dstl / MBDA UK / Leonardo UK / QinetiQ",
                    system_type="directed_energy_laser",
                    power_class="~50 kW class",
                    effective_range_km=5.0,
                    role="C-UAS / air defense",
                    public_status="Demonstrator",
                    is_fielded=False,
                ),
                CompetitiveIntelEntry(
                    name="Iron Beam",
                    origin="Israel",
                    developer="Rafael / IMOD",
                    system_type="directed_energy_laser",
                    power_class="~100 kW class",
                    effective_range_km=10.0,
                    role="C-UAS / C-RAM",
                    public_status="In development",
                    is_fielded=False,
                ),
            ]
            for entry in comp_entries:  # type: ignore[assignment]
                builder.add_competitive_intel(entry)  # type: ignore[arg-type]

            bundle = builder.build()
            store.save_bundle(bundle)
            print("[C-UAS] STIX 2.1 bundle exported")
            print(f"  Bundle ID : {bundle['id']}")
            print(f"  Objects   : {len(bundle['objects'])}")
            print(f"  SHA-256   : {bundle_hash(bundle)}")
            print(builder.to_json())
            return 0

        if args.alert:
            engine = AlertEngine(  # type: ignore[assignment]
                channels=[
                    Channel(config=ChannelConfig(kind="console"), send=ConsoleChannel().send),
                    Channel(
                        config=ChannelConfig(kind="email", email_to="soc@a2zsoc.com"),
                        send=EmailStubChannel("soc@a2zsoc.com").send,
                    ),
                ]
            )
            sample_events = [
                DetectionEvent(
                    event_id="DET-ALERT-01",
                    timestamp="2026-10-23T10:20:00Z",
                    source="spoof_detector",
                    target_id="UAV-ROGUE-02",
                    threat_level="CRITICAL",
                    protocol="GPS_L1_CA",
                    confidence=0.99,
                    anomalies=("C_N0_ANOMALY", "CLOCK_DRIFT_STEP"),
                ),
                DetectionEvent(
                    event_id="DET-ALERT-02",
                    timestamp="2026-10-23T10:21:00Z",
                    source="rf_classifier",
                    target_id="UAV-ROGUE-03",
                    threat_level="HIGH",
                    protocol="DJI_OCUSYNC_4",
                    confidence=0.91,
                ),
                DetectionEvent(
                    event_id="DET-ALERT-03",
                    timestamp="2026-10-23T10:22:00Z",
                    source="rf_classifier",
                    target_id="UAV-ROGUE-04",
                    threat_level="MEDIUM",
                    protocol="MAVLINK_TELEMETRY_SIK",
                    confidence=0.6,
                ),
            ]
            total = 0
            for event in sample_events:
                total += len(engine.process_event(event))  # type: ignore[attr-defined]
            print(f"[C-UAS] Alert engine: {total} alert(s) dispatched")
            return 0

        if args.test:
            from fastapi.testclient import TestClient  # type: ignore

            # 1. Export produces a valid STIX 2.1 bundle.
            builder = STIXBundleBuilder()
            builder.add_detection_event(
                DetectionEvent(
                    event_id="DET-TEST-01",
                    timestamp="2026-10-23T11:00:00Z",
                    source="rf_classifier",
                    target_id="UAV-TEST-01",
                    threat_level="HIGH",
                    protocol="DJI_OCUSYNC_4",
                )
            )
            bundle = builder.build()
            assert bundle["type"] == "bundle"
            assert bundle["spec_version"] == "2.1"
            assert len(bundle["objects"]) >= 4  # 3 markings + actor + pattern + observed
            h = bundle_hash(bundle)
            assert len(h) == 64
            # Determinism: same inputs -> same bundle id/hash.
            builder2 = STIXBundleBuilder()
            builder2.add_detection_event(
                DetectionEvent(
                    event_id="DET-TEST-01",
                    timestamp="2026-10-23T11:00:00Z",
                    source="rf_classifier",
                    target_id="UAV-TEST-01",
                    threat_level="HIGH",
                    protocol="DJI_OCUSYNC_4",
                )
            )
            assert bundle_hash(builder2.build()) == h

            # 2. Alert engine dispatches on CRITICAL events.
            engine = AlertEngine(  # type: ignore[assignment]
                channels=[Channel(config=ChannelConfig(kind="console"), send=ConsoleChannel().send)]
            )
            alerts = engine.process_event(  # type: ignore[attr-defined]
                DetectionEvent(
                    event_id="DET-TEST-02",
                    timestamp="2026-10-23T11:01:00Z",
                    source="spoof_detector",
                    target_id="UAV-TEST-02",
                    threat_level="CRITICAL",
                )
            )
            assert len(alerts) == 1
            assert alerts[0].severity == "CRITICAL"

            # 3. TAXII routes mount and return bundles.
            client = TestClient(app_factory())
            disc = client.get("/taxii2/")
            assert disc.status_code == 200
            assert disc.json()["type"] == "discovery"
            colls = client.get("/taxii2/collections/")
            assert colls.status_code == 200
            objs = client.get("/taxii2/collections/cuas-detections/objects/")
            assert objs.status_code == 200
            assert objs.json()["type"] == "bundle"

            # 4. Persistence round-trip.
            store = ThreatIntelStore()
            store.save_bundle(bundle)
            assert len(store.list_bundles()) >= 1

            print("[C-UAS] threat-intel self-test: PASS")
            print(f"  Bundle objects : {len(bundle['objects'])}")
            print(f"  Bundle SHA-256 : {h}")
            print(f"  Alerts fired   : {len(alerts)}")
            return 0

        print("[C-UAS] threat-intel: specify --export, --serve, --alert, or --test")
        return 1

    if args.command == "broker":
        from c_uas.broker import (
            AgentSlotManager,
            BrokerTenantManager,
            CampaignAnalyticsEngine,
            CampaignManager,
            DistributionChannel,
        )

        action = (args.action or "").lower()
        mgr = BrokerTenantManager()  # type: ignore[assignment]
        slots_mgr = AgentSlotManager()
        camp_mgr = CampaignManager()
        analytics = CampaignAnalyticsEngine()

        try:
            if action == "register":
                if not args.name or not args.region or not args.contact_email:
                    print("[C-UAS] --name, --region and --contact-email required for register")
                    return 1
                tenant = mgr.register(  # type: ignore[attr-defined]
                    args.name,
                    args.region,
                    args.contact_email,
                    args.whatsapp_number or "",
                    args.facebook_page_id or "",
                    args.max_agent_slots,
                )
                print(f"[C-UAS] Broker registered: {tenant.broker_id}")
                print(f"  Name           : {tenant.name}")
                print(f"  Region         : {tenant.region}")
                print(f"  Contact email  : {tenant.contact_email}")
                print(f"  WhatsApp       : {tenant.whatsapp_number}")
                print(f"  Facebook page  : {tenant.facebook_page_id}")
                print(
                    f"  Slots          : {tenant.agent_slots_allocated} / {tenant.max_agent_slots}"
                )
                print(f"  Status         : {tenant.status}")
                print(f"  Created at     : {tenant.created_at}")
                return 0

            if action == "allocate":
                if not args.broker_id:
                    print("[C-UAS] --broker-id required for allocate")
                    return 1
                util = slots_mgr.allocate(args.broker_id, args.slots)
                print(f"[C-UAS] Slots allocated for broker {args.broker_id}")
                print(f"  Slots used     : {util.slots_used} / {util.max_slots}")
                print(f"  Slots free     : {util.slots_free}")
                print(f"  Utilization    : {util.utilization_ratio:.1%}")
                print(f"  Waitlisted     : {util.waitlisted}")
                return 0

            if action == "revoke":
                if not args.broker_id:
                    print("[C-UAS] --broker-id required for revoke")
                    return 1
                util = slots_mgr.revoke(args.broker_id, args.slots)
                print(f"[C-UAS] Slots revoked for broker {args.broker_id}")
                print(f"  Slots used     : {util.slots_used} / {util.max_slots}")
                print(f"  Slots free     : {util.slots_free}")
                print(f"  Utilization    : {util.utilization_ratio:.1%}")
                print(f"  Waitlisted     : {util.waitlisted}")
                return 0

            if action == "campaign":
                if (
                    not args.broker_id
                    or not args.channel
                    or not args.target_region
                    or not args.message_template
                    or args.recipient_count is None
                ):
                    print(
                        "[C-UAS] --broker-id, --channel, --target-region, --message-template, "
                        "--recipient-count required for campaign"
                    )
                    return 1
                if not DistributionChannel.has_value(args.channel):
                    print(
                        f"[C-UAS] Unknown channel: {args.channel} "
                        f"(expected {', '.join(c.value for c in DistributionChannel)})"
                    )
                    return 1
                campaign = camp_mgr.create_campaign(
                    args.broker_id,
                    DistributionChannel(args.channel),
                    args.target_region,
                    args.message_template,
                    args.recipient_count,
                )
                dispatched = camp_mgr.dispatch_campaign(campaign.campaign_id)
                print(f"[C-UAS] Campaign created and dispatched: {dispatched.campaign_id}")
                print(f"  Broker ID      : {dispatched.broker_id}")
                print(f"  Channel        : {dispatched.channel.value}")
                print(f"  Target region  : {dispatched.target_region}")
                print(f"  Recipients     : {dispatched.recipient_count}")
                print(f"  Status         : {dispatched.status}")
                print(f"  Sent           : {dispatched.sent_count}")
                print(f"  Delivered      : {dispatched.delivered_count}")
                print(f"  Read           : {dispatched.read_count}")
                print(f"  Created at     : {dispatched.created_at}")
                return 0

            if action == "analytics":
                if not args.campaign_id:
                    print("[C-UAS] --campaign-id required for analytics")
                    return 1
                report = analytics.analyze(args.campaign_id)  # type: ignore[assignment]
                print(f"[C-UAS] Campaign analytics: {report.campaign_id}")  # type: ignore[attr-defined]
                print(f"  Delivery rate  : {report.delivery_rate:.1%}")  # type: ignore[attr-defined]
                print(f"  Read rate      : {report.read_rate:.1%}")  # type: ignore[attr-defined]
                print(f"  Conversion rate: {report.conversion_rate:.4%} (illustrative)")  # type: ignore[attr-defined]
                print(f"  Cost per acq   : ${report.cost_per_acquisition_usd:.2f} (illustrative)")  # type: ignore[attr-defined]
                print(f"  Basis          : {report.basis}")  # type: ignore[attr-defined]
                return 0

            if action == "list-tenants":
                tenants = mgr.list_all()
                print(f"[C-UAS] Broker tenants ({len(tenants)}):")
                for t in tenants:
                    print(
                        f"  {t.broker_id}  {t.name}  {t.region}  "  # type: ignore[attr-defined]
                        f"{t.agent_slots_allocated}/{t.max_agent_slots} slots  {t.status}"  # type: ignore[attr-defined]
                    )
                return 0

            print(f"[C-UAS] Unknown broker action: {action}")
            return 1
        except KeyError as exc:
            print(f"[C-UAS] {exc}")
            return 1
        except ValueError as exc:
            print(f"[C-UAS] {exc}")
            return 1

    if args.command == "compliance":
        from c_uas.compliance import (
            AuditTrailGenerator,
            EvidenceCollector,
            EvidenceExport,
            EvidencePackageManager,
            _canonical,
        )
        from c_uas.compliance import (
            ComplianceReporter as CComplianceReporter,
        )

        if args.collect:
            collector = EvidenceCollector()
            records = collector.collect()
            print(f"[C-UAS] Compliance evidence collected: {len(records)} record(s)")
            by_source: Dict[str, int] = {}
            for rec in records:
                by_source[rec.source] = by_source.get(rec.source, 0) + 1
            for source in sorted(by_source):
                print(f"  {source}: {by_source[source]}")
            return 0

        if args.package:
            collector = EvidenceCollector()
            records = collector.collect()
            manager = EvidencePackageManager()
            package = manager.package(records)
            trail = AuditTrailGenerator().build(records)
            print(f"[C-UAS] Evidence package signed: {package.package_id}")
            print(f"  Evidence records : {package.evidence_count}")
            print(f"  Signature (Ed25519): {package.signature[:32]}...")
            print(f"  Public key       : {package.public_key_pem.splitlines()[1][:32]}...")
            print(f"  Audit trail steps: {len(trail)}")
            print(f"  Chain valid      : {manager.verify_package(package)}")
            return 0

        if args.export:
            manager = EvidencePackageManager()
            packages = manager.list_packages()
            if not packages:
                print("[C-UAS] No evidence package found. Run --package first.")
                return 1
            package = packages[-1]
            collector = EvidenceCollector()
            records = collector.list_collected()
            record_map = {r.evidence_id: r for r in records}
            bundled = [record_map[eid] for eid in package.evidence_ids if eid in record_map]
            exporter = EvidenceExport()
            fmt = (args.format or "json").lower()
            out = args.out
            if fmt == "json":
                path = exporter.to_json(package, out or "-")
                if out:
                    print(f"[C-UAS] Package exported (JSON): {path}")
                else:
                    print(_canonical(package.to_dict()))
            elif fmt == "zip":
                if not out:
                    print("[C-UAS] --out required for zip export")
                    return 1
                path = exporter.to_zip(package, bundled, out)
                print(f"[C-UAS] Package exported (ZIP): {path}")
            else:
                print(f"[C-UAS] Unknown export format: {args.format} (expected json or zip)")
                return 1
            return 0

        if args.report:
            collector = EvidenceCollector()
            records = collector.collect()
            reporter = CComplianceReporter()  # type: ignore[assignment]
            report = reporter.generate(records)  # type: ignore[call-arg]
            print("[C-UAS] ISO 42001 Compliance Report")
            print(f"  Total evidence   : {report.total_evidence}")  # type: ignore[attr-defined]
            print(f"  Controls         : {report.satisfied_controls}/{report.total_controls}")  # type: ignore[attr-defined]
            print(f"  Coverage         : {report.coverage_percentage}%")  # type: ignore[attr-defined]
            print(f"  Overall status   : {report.overall_status}")
            for ctrl in report.controls:  # type: ignore[attr-defined]
                marker = "OK " if ctrl.satisfied else "GAP"
                print(
                    f"  [{marker}] {ctrl.control_id} {ctrl.title} ({ctrl.evidence_count} evidence)"
                )
            return 0

        print("[C-UAS] compliance: specify --collect, --package, --export, or --report")
        return 1

    if args.command == "gateway":
        from c_uas.gateway.cli import main as gateway_main

        return gateway_main(args)

    if args.command == "hardware":
        from c_uas.hardware.cli import main as hardware_main

        source = argv if argv is not None else sys.argv[1:]  # type: ignore[assignment]
        return hardware_main([a for a in source if a != "hardware"])

    if args.command == "hardware":
        from c_uas.hardware.cli import main as hardware_main

        source = argv if argv is not None else sys.argv[1:]  # type: ignore[assignment]
        return hardware_main([a for a in source if a != "hardware"])

    if args.command == "red-team":
        from c_uas.red_team.cli import red_team_main

        return red_team_main(args)

    if args.command == "edge":
        from c_uas.edge.cli import main as edge_main

        source = argv if argv is not None else sys.argv[1:]  # type: ignore[assignment]
        return edge_main([a for a in source if a != "edge"])

    if args.command == "performance":
        from c_uas.performance.engine import (
            BottleneckDetector,
            CapacityPlanner,
            OptimizationRecommendations,
            PerformanceBaseline,
        )

        if args.baseline:
            baseline = PerformanceBaseline(seed=args.seed).establish()
            m = baseline.metrics
            print("[C-UAS] Performance Baseline")
            print(f"  Detection latency   : {m['detection_latency_ms'].value:.1f} ms")
            print(f"  Tracking accuracy   : {m['tracking_accuracy_m'].value:.2f} m")
            print(f"  Engagement success  : {m['engagement_success_rate'].value:.1%}")
            print(f"  API response time   : {m['api_response_time_ms'].value:.1f} ms")
            print(f"  Scheduler /100 drones: {m['scheduler_ms_per_100_drones'].value:.1f} ms")
            print(f"  Swarm leak @16      : {m['swarm_leak_rate_at_16'].value:.1%}")
            return 0

        if args.bottlenecks:
            baseline = PerformanceBaseline(seed=args.seed).establish()  # type: ignore[assignment]
            detector = BottleneckDetector(baseline=baseline)  # type: ignore[assignment]
            report = detector.detect()  # type: ignore[attr-defined]
            print("[C-UAS] Bottleneck Detection")
            print(f"  Bottlenecks found   : {len(report.bottlenecks)}")
            for b in report.bottlenecks:
                print(f"  - {b.component}: {b.category} ({b.severity})")
                print(f"    {b.recommendation}")
            return 0

        if args.capacity:
            baseline = PerformanceBaseline(seed=args.seed).establish()  # type: ignore[assignment]
            planner = CapacityPlanner(baseline=baseline)  # type: ignore[assignment]
            plan = planner.plan(  # type: ignore[attr-defined]
                sites=args.sites,
                drones_per_site=args.drones_per_site,
                brokers=args.brokers,
            )
            p = plan.predicted
            print("[C-UAS] Capacity Planning")
            print(f"  Sites               : {plan.scenario['sites']}")
            print(f"  Drones per site     : {plan.scenario['drones_per_site']}")
            print(f"  Total drones        : {plan.scenario['total_drones']}")
            print(f"  Brokers             : {plan.scenario['brokers']}")
            print(f"  Brokers needed      : {p['brokers_needed']}")
            print(f"  Agent slots required: {p['agent_slots_required']}")
            print(f"  CPU cores required  : {p['required_cores']}")
            print(f"  Memory required MB  : {p['memory_mb']}")
            print(f"  Scheduler seconds   : {p['scheduler_seconds']:.2f}")
            print(f"  Leak rate           : {p['leak_rate']:.1%}")
            print(f"  Under-provisioned   : {p['under_provisioned']}")
            print(f"  Provisioning        : {plan.provisioning}")
            return 0

        if args.optimize:
            baseline = PerformanceBaseline(seed=args.seed).establish()  # type: ignore[assignment]
            detector = BottleneckDetector(baseline=baseline)  # type: ignore[assignment]
            bottleneck_report = detector.detect()  # type: ignore[attr-defined]
            planner = CapacityPlanner(baseline=baseline)  # type: ignore[assignment]
            capacity_plan = planner.plan(  # type: ignore[attr-defined]
                sites=args.sites,
                drones_per_site=args.drones_per_site,
                brokers=args.brokers,
            )
            optimizer = OptimizationRecommendations(
                baseline=baseline,
                bottlenecks=bottleneck_report,
                capacity=capacity_plan,
            )
            report = optimizer.generate()  # type: ignore[assignment]
            print("[C-UAS] Optimization Recommendations")
            for r in report.recommendations:  # type: ignore[attr-defined]
                print(f"  [{r.priority.upper()}] {r.title}")
                print(f"    {r.action}")
                print(f"    Impact: {r.expected_impact}")
            return 0

        print("[C-UAS] performance: specify --baseline, --bottlenecks, --capacity, or --optimize")
        print("  c-uas performance --baseline")
        print("  c-uas performance --bottlenecks")
        print("  c-uas performance --capacity --sites 4 --drones-per-site 16 --brokers 2")
        print("  c-uas performance --optimize")
        return 1

    if args.command == "perf":
        from c_uas.performance.cli import perf_main

        return perf_main(args)

    if args.command == "chaos":
        from c_uas.chaos.cli import chaos_main

        return chaos_main(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
