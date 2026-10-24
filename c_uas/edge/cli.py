"""
CLI for C-UAS edge node deployment and multi-tenant edge operations.

    c-uas edge --deploy --node-id SITE-01 --location "Roof, Building A"
    c-uas edge --status --node-id SITE-01
    c-uas edge --sync --node-id SITE-01 --cloud-endpoint https://cloud.a2zsoc.com
    c-uas edge --tenant --register-tenant --tenant-id T-1 --name "Site One"
    --region us-east-1 --tier standard
    c-uas edge --tenant --list-tenants
    c-uas edge --fleet --register-node --node-id N-1 --tenant-id T-1 --location "Roof A"
    c-uas edge --fleet --heartbeat --node-id N-1
    c-uas edge --fleet --fleet-health
    c-uas edge --zero-trust --evaluate-policy --source node-A --dest node-B --port 443 --mtls
    c-uas edge --zero-trust --show-policy

Legacy ``--deploy``/``--status``/``--sync`` behavior is handled by
:func:`main` and is preserved unchanged. The new multi-tenant / zero-trust
modes are dispatched by :func:`edge_main`, which is registered on the
parent CLI via :func:`build_subparser`.

State persists under ~/.c-uas-platform/edge/ (outside the repo).

All output is deterministic: identical inputs produce identical CLI output.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional, Sequence

from .config import EdgeConfig
from .fleet import FleetManager
from .health import EdgeHealth
from .node import EdgeNode
from .state import load_json
from .sync import EdgeSync
from .tenancy import ResourceQuota, TenancyManager
from .zero_trust import NetworkPolicy, ZeroTrustManager


def _build_config(args: argparse.Namespace) -> EdgeConfig:
    sensors = (
        tuple(s.strip() for s in args.sensors.split(",") if s.strip())
        if args.sensors
        else ("sdr", "radar", "camera")
    )
    return EdgeConfig(
        node_id=args.node_id,
        location=args.location or "",
        sensors_enabled=sensors,
        sync_interval_s=args.sync_interval,
        cloud_endpoint=args.cloud_endpoint,
        offline_mode=args.offline,
        seed=args.seed,
    )


# --------------------------------------------------------------------------- #
# Argument builder (shared by build_subparser and edge_main)
# --------------------------------------------------------------------------- #


def _add_edge_arguments(parser: argparse.ArgumentParser) -> None:
    """Register every edge CLI flag on ``parser`` (legacy + multi-tenant)."""
    # -- legacy deployment mode -------------------------------------
    parser.add_argument(
        "--deploy",
        action="store_true",
        help="Deploy edge node and run the first local detection cycle",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show edge node health and sync state",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help="Sync queued detections to the cloud endpoint",
    )
    parser.add_argument(
        "--node-id",
        type=str,
        default=None,
        help="Edge node identifier (required)",
    )
    parser.add_argument(
        "--location",
        type=str,
        default=None,
        help="Site location (required for --deploy)",
    )
    parser.add_argument(
        "--sensors",
        type=str,
        default="sdr,radar,camera",
        help="Comma-separated sensor list (sdr, radar, camera)",
    )
    parser.add_argument(
        "--sync-interval",
        type=float,
        default=300.0,
        help="Cloud sync interval in seconds",
    )
    parser.add_argument(
        "--cloud-endpoint",
        type=str,
        default=None,
        help="Cloud API base URL",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run in offline mode (no cloud sync attempts)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic RNG seed",
    )
    # -- multi-tenant mode ------------------------------------------
    parser.add_argument(
        "--tenant",
        action="store_true",
        help="Tenant isolation mode (register/list/health/quota/isolation)",
    )
    parser.add_argument(
        "--register-tenant",
        action="store_true",
        help="Register a new tenant (with --tenant-id/--name/--region/--tier)",
    )
    parser.add_argument(
        "--list-tenants",
        action="store_true",
        help="List all registered tenants",
    )
    parser.add_argument(
        "--tenant-health",
        action="store_true",
        help="Show health report for --tenant-id",
    )
    parser.add_argument(
        "--set-quota",
        action="store_true",
        help="Set a tenant resource quota (--quota-key/--quota-value)",
    )
    parser.add_argument(
        "--check-isolation",
        action="store_true",
        help="Check cross-tenant access (--tenant-id source, --name target)",
    )
    parser.add_argument(
        "--tenant-id",
        type=str,
        default=None,
        help="Tenant identifier",
    )
    parser.add_argument(
        "--name",
        type=str,
        default=None,
        help="Tenant name (or target tenant for isolation check)",
    )
    parser.add_argument(
        "--region",
        type=str,
        default=None,
        help="Tenant region",
    )
    parser.add_argument(
        "--tier",
        type=str,
        default=None,
        help="Tenant tier (standard/premium/enterprise)",
    )
    parser.add_argument(
        "--quota-key",
        type=str,
        default=None,
        help="Quota key to set (nodes)",
    )
    parser.add_argument(
        "--quota-value",
        type=int,
        default=None,
        help="Quota value to set",
    )
    # -- fleet mode -------------------------------------------------
    parser.add_argument(
        "--fleet",
        action="store_true",
        help="Edge node fleet management mode",
    )
    parser.add_argument(
        "--register-node",
        action="store_true",
        help="Register a new edge node (--node-id/--tenant-id/--location)",
    )
    parser.add_argument(
        "--list-nodes",
        action="store_true",
        help="List all fleet nodes",
    )
    parser.add_argument(
        "--heartbeat",
        action="store_true",
        help="Record a heartbeat for --node-id",
    )
    parser.add_argument(
        "--fleet-health",
        action="store_true",
        help="Show aggregate fleet health score",
    )
    parser.add_argument(
        "--detect-offline",
        action="store_true",
        help="Detect offline fleet nodes",
    )
    parser.add_argument(
        "--decommission-node",
        action="store_true",
        help="Decommission --node-id",
    )
    parser.add_argument(
        "--heartbeat-interval-s",
        type=float,
        default=60.0,
        help="Node heartbeat interval in seconds",
    )
    parser.add_argument(
        "--offline-threshold-s",
        type=float,
        default=None,
        help="Offline detection threshold in seconds (default: 3x interval)",
    )
    # -- zero-trust mode --------------------------------------------
    parser.add_argument(
        "--zero-trust",
        action="store_true",
        help="Zero-trust network policy mode",
    )
    parser.add_argument(
        "--evaluate-policy",
        action="store_true",
        help="Evaluate an ingress flow against the zero-trust policy",
    )
    parser.add_argument(
        "--show-policy",
        action="store_true",
        help="Show the active zero-trust network policy",
    )
    parser.add_argument(
        "--set-policy",
        action="store_true",
        help="Set the zero-trust network policy flags",
    )
    parser.add_argument(
        "--source",
        type=str,
        default=None,
        help="Ingress source identity",
    )
    parser.add_argument(
        "--dest",
        type=str,
        default=None,
        help="Ingress destination identity",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Ingress destination port",
    )
    parser.add_argument(
        "--mtls",
        action="store_true",
        help="mTLS is present for the flow",
    )
    parser.add_argument(
        "--same-segment",
        action="store_true",
        help="Source and dest are in the same network segment",
    )
    parser.add_argument(
        "--authenticated",
        action="store_true",
        help="Service-to-service authentication is present",
    )
    parser.add_argument(
        "--default-deny-ingress",
        action="store_true",
        help="Enable default-deny ingress (for --set-policy)",
    )
    parser.add_argument(
        "--segmentation",
        action="store_true",
        help="Enable network segmentation (for --set-policy)",
    )
    parser.add_argument(
        "--service-auth",
        action="store_true",
        help="Require service-to-service auth (for --set-policy)",
    )


# --------------------------------------------------------------------------- #
# Multi-tenant handlers
# --------------------------------------------------------------------------- #


def _handle_tenant(args: argparse.Namespace) -> int:
    manager = TenancyManager()
    if args.register_tenant:
        if not args.tenant_id or not args.tenant_id.strip():
            print("[C-UAS] --tenant-id is required for --register-tenant")
            return 1
        if not args.name or not args.region or not args.tier:
            print("[C-UAS] --name, --region and --tier are required for --register-tenant")
            return 1
        quota = ResourceQuota(
            max_nodes=10,
            max_detections_per_hour=1000,
            max_sync_mb_per_day=100,
            max_concurrent_sensors=3,
        )
        record = manager.register_tenant(
            tenant_id=args.tenant_id,
            name=args.name,
            region=args.region,
            tier=args.tier,
            quota=quota,
        )
        print("[C-UAS] Tenant registered: {}".format(record.tenant_id))
        print("  Name     : {}".format(record.name))
        print("  Region   : {}".format(record.region))
        print("  Tier     : {}".format(record.tier))
        print("  Status   : {}".format(record.status))
        print("  Nodes    : {}".format(record.node_count))
        print("  Quota    : {} nodes".format(record.quota.max_nodes))
        return 0

    if args.list_tenants:
        tenants = manager.list_tenants()
        print("[C-UAS] Tenants ({})".format(len(tenants.tenants)))
        for t in tenants.tenants:
            print(
                "  {}  {}  {}  {}  {} nodes  {}".format(
                    t.tenant_id,
                    t.name,
                    t.region,
                    t.tier,
                    t.node_count,
                    t.status,
                )
            )
        return 0

    if args.tenant_health:
        if not args.tenant_id:
            print("[C-UAS] --tenant-id is required for --tenant-health")
            return 1
        health = manager.tenant_health(args.tenant_id)
        print("[C-UAS] Tenant health: {}".format(health.tenant_id))
        print("  Nodes        : {}".format(health.node_count))
        print("  Active nodes : {}".format(health.active_nodes))
        print("  Within quota : {}".format(health.within_quota))
        print("  Health score : {}".format(health.health_score))
        return 0

    if args.set_quota:
        if not args.tenant_id:
            print("[C-UAS] --tenant-id is required for --set-quota")
            return 1
        if args.quota_key is None or args.quota_value is None:
            print("[C-UAS] --quota-key and --quota-value are required for --set-quota")
            return 1
        tenant_record = manager.get_tenant(args.tenant_id)
        if tenant_record is None:
            print("[C-UAS] Unknown tenant: {}".format(args.tenant_id))
            return 1
        quota = tenant_record.quota
        if args.quota_key == "nodes":
            quota = ResourceQuota(
                max_nodes=args.quota_value,
                max_detections_per_hour=quota.max_detections_per_hour,
                max_sync_mb_per_day=quota.max_sync_mb_per_day,
                max_concurrent_sensors=quota.max_concurrent_sensors,
            )
        else:
            print("[C-UAS] Unknown quota key: {}".format(args.quota_key))
            return 1
        updated = manager.set_quota(args.tenant_id, quota)
        print("[C-UAS] Quota set for tenant: {}".format(updated.tenant_id))
        print("  Max nodes : {}".format(updated.quota.max_nodes))
        return 0

    if args.check_isolation:
        source = args.tenant_id
        target = args.name
        if not source or not target:
            print("[C-UAS] --tenant-id (source) and --name (target) required for --check-isolation")
            return 1
        allowed = TenancyManager.cross_tenant_access_allowed(source, target)
        print("[C-UAS] Cross-tenant access: {} -> {}".format(source, target))
        print("  Allowed : {}".format(allowed))
        print("  Policy  : deny-by-default (zero-trust isolation)")
        return 0

    print(
        "[C-UAS] tenant: specify --register-tenant, --list-tenants, "
        "--tenant-health, --set-quota, or --check-isolation"
    )
    return 1


def _handle_fleet(args: argparse.Namespace) -> int:
    manager = FleetManager()
    if args.register_node:
        if not args.node_id or not args.tenant_id or not args.location:
            print("[C-UAS] --node-id, --tenant-id and --location are required for --register-node")
            return 1
        record = manager.register_node(
            node_id=args.node_id,
            tenant_id=args.tenant_id,
            location=args.location,
            heartbeat_interval_s=args.heartbeat_interval_s,
        )
        print("[C-UAS] Node registered: {}".format(record.node_id))
        print("  Tenant         : {}".format(record.tenant_id))
        print("  Location       : {}".format(record.location))
        print("  Status         : {}".format(record.status))
        print("  Heartbeat int  : {}s".format(record.heartbeat_interval_s))
        print("  Health score   : {}".format(record.health_score))
        return 0

    if args.list_nodes:
        nodes = manager.list_nodes()
        print("[C-UAS] Fleet nodes ({})".format(len(nodes)))
        for n in nodes:
            print(
                "  {}  {}  {}  {}  last_seen={}  health={}".format(
                    n.node_id,
                    n.tenant_id,
                    n.location,
                    n.status,
                    int(n.last_seen),
                    n.health_score,
                )
            )
        return 0

    if args.heartbeat:
        if not args.node_id:
            print("[C-UAS] --node-id is required for --heartbeat")
            return 1
        try:
            record = manager.heartbeat(args.node_id)
        except KeyError as exc:
            print("[C-UAS] {}".format(exc))
            return 1
        print("[C-UAS] Heartbeat recorded: {}".format(record.node_id))
        print("  Last seen    : {}".format(int(record.last_seen)))
        print("  Status         : {}".format(record.status))
        print("  Health score   : {}".format(record.health_score))
        return 0

    if args.fleet_health:
        report = manager.fleet_health()
        print("[C-UAS] Fleet health")
        print("  Total nodes      : {}".format(report.total_nodes))
        print("  Active nodes     : {}".format(report.active_nodes))
        print("  Offline nodes    : {}".format(report.offline_nodes))
        print("  Decommissioned   : {}".format(report.decommissioned_nodes))
        print("  Avg health score : {}".format(report.average_health_score))
        print("  By tenant        : {}".format(report.by_tenant))
        return 0

    if args.detect_offline:
        offline = manager.detect_offline(threshold_s=args.offline_threshold_s)
        print("[C-UAS] Offline nodes ({})".format(len(offline)))
        for n in offline:
            print(
                "  {}  {}  {}  last_seen={}".format(
                    n.node_id, n.tenant_id, n.location, int(n.last_seen)
                )
            )
        return 0

    if args.decommission_node:
        if not args.node_id:
            print("[C-UAS] --node-id is required for --decommission-node")
            return 1
        try:
            record = manager.decommission_node(args.node_id)
        except KeyError as exc:
            print("[C-UAS] {}".format(exc))
            return 1
        print("[C-UAS] Node decommissioned: {}".format(record.node_id))
        print("  Tenant         : {}".format(record.tenant_id))
        print("  Status         : {}".format(record.status))
        print("  Health score   : {}".format(record.health_score))
        return 0

    print(
        "[C-UAS] fleet: specify --register-node, --list-nodes, --heartbeat, "
        "--fleet-health, --detect-offline, or --decommission-node"
    )
    return 1


def _handle_zero_trust(args: argparse.Namespace) -> int:
    manager = ZeroTrustManager()
    if args.set_policy:
        policy = NetworkPolicy(
            default_deny_ingress=args.default_deny_ingress,
            mTLS_enforced=args.mtls,
            network_segmentation=args.segmentation,
            service_to_service_auth=args.service_auth,
            allowed_segments=(),
        )
        manager.save_policy(policy)
        print("[C-UAS] Zero-trust policy saved")
        print("  Default-deny ingress : {}".format(policy.default_deny_ingress))
        print("  mTLS enforced        : {}".format(policy.mTLS_enforced))
        print("  Network segmentation : {}".format(policy.network_segmentation))
        print("  Service-to-service   : {}".format(policy.service_to_service_auth))
        return 0

    if args.show_policy:
        policy = manager.policy
        print("[C-UAS] Zero-trust network policy")
        print("  Default-deny ingress : {}".format(policy.default_deny_ingress))
        print("  mTLS enforced        : {}".format(policy.mTLS_enforced))
        print("  Network segmentation : {}".format(policy.network_segmentation))
        print("  Service-to-service   : {}".format(policy.service_to_service_auth))
        print("  Allowed segments     : {}".format(",".join(policy.allowed_segments) or "(none)"))
        return 0

    if args.evaluate_policy:
        if args.source is None or args.dest is None or args.port is None:
            print("[C-UAS] --source, --dest and --port are required for --evaluate-policy")
            return 1
        result = manager.evaluate_ingress(
            source=args.source,
            dest=args.dest,
            port=args.port,
            has_mtls=args.mtls,
            same_segment=args.same_segment,
            authenticated=args.authenticated,
        )
        print("[C-UAS] Ingress policy evaluation")
        print("  Flow       : {} -> {}:{}".format(args.source, args.dest, args.port))
        print("  Allowed    : {}".format(result.allowed))
        print("  Reason     : {}".format(result.reason))
        print("  Rules      : {}".format(", ".join(result.rules_checked)))
        print("  Matched    : {}".format(", ".join(result.matched_rules) or "(none)"))
        return 0

    print("[C-UAS] zero-trust: specify --evaluate-policy, --show-policy, or --set-policy")
    return 1


# --------------------------------------------------------------------------- #
# Legacy deployment mode (unchanged behavior)
# --------------------------------------------------------------------------- #


def _handle_legacy(args: argparse.Namespace) -> int:
    if not args.node_id or not args.node_id.strip():
        print("[C-UAS] --node-id is required for edge commands")
        return 1

    if args.deploy:
        if not args.location or not args.location.strip():
            print("[C-UAS] --location is required for --deploy")
            return 1
        try:
            config = _build_config(args)
        except ValueError as exc:
            print("[C-UAS] {}".format(exc))
            return 1
        report = EdgeNode(config).deploy()
        print("[C-UAS] Edge node deployed: {}".format(report.node_id))
        print("  Location       : {}".format(report.location))
        print("  State dir      : {}".format(report.state_dir))
        print("  Detections     : {}".format(report.detection_count))
        print("  Tracks         : {}".format(report.track_count))
        print("  Offline mode   : {}".format(report.offline_mode))
        print(
            "  CPU target     : {}% (within: {})".format(
                EdgeNode.CPU_TARGET_PERCENT, report.within_cpu_target
            )
        )
        print(
            "  Memory target  : {} MB (within: {})".format(
                EdgeNode.MEMORY_TARGET_MB, report.within_memory_target
            )
        )
        return 0

    if args.status:
        config = _build_config(args)
        health = EdgeHealth(config).check()
        queue = load_json(args.node_id, "sync_queue", default=[])
        print("[C-UAS] Edge node status: {}".format(args.node_id))
        print("  CPU            : {}%".format(health.cpu_percent))
        print("  Memory         : {} MB / {}%".format(health.memory_mb, health.memory_percent))
        print("  Disk           : {}%".format(health.disk_percent))
        print(
            "  Temperature    : {}".format(
                health.temperature_c if health.temperature_c is not None else "n/a"
            )
        )
        print("  Connectivity   : {}".format(health.connectivity))
        print("  Queued detections: {}".format(len(queue)))
        print("  Within CPU target: {}".format(health.within_cpu_target))
        print("  Within memory target: {}".format(health.within_memory_target))
        for sensor_id in sorted(health.sensors):
            online = health.sensors[sensor_id]
            print("  Sensor {}: {}".format(sensor_id, "online" if online else "offline"))
        return 0

    if args.sync:
        config = _build_config(args)
        sync_report = EdgeSync(config).sync()
        print("[C-UAS] Edge sync: {}".format(sync_report.node_id))
        print("  Reason          : {}".format(sync_report.reason))
        print("  Synced          : {}".format(sync_report.synced_count))
        print("  Delivered       : {}".format(sync_report.delivered_count))
        print("  Pending         : {}".format(sync_report.pending_count))
        print("  Conflicts resolved: {}".format(sync_report.conflicts_resolved))
        return 0

    print("[C-UAS] edge: specify --deploy, --status, --sync, --tenant, --fleet, or --zero-trust")
    return 1


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


def build_subparser(subparsers: Any) -> Any:
    """Register the ``edge`` subcommand on a parent parser (e.g. c_uas.cli)."""
    parser = subparsers.add_parser(
        "edge",
        help=(
            "Deploy and operate C-UAS edge nodes with multi-tenant isolation "
            "and zero-trust network policies"
        ),
    )
    _add_edge_arguments(parser)
    return parser


def edge_main(argv: Optional[Sequence[str]] = None) -> int:
    """Dispatch edge CLI modes: legacy --deploy/--status/--sync plus
    --tenant / --fleet / --zero-trust multi-tenant zero-trust operations."""
    parser = argparse.ArgumentParser(
        prog="c-uas edge",
        description=(
            "C-UAS edge node deployment with multi-tenant isolation and zero-trust network policies"
        ),
    )
    _add_edge_arguments(parser)
    args = parser.parse_args(argv)

    if args.tenant:
        return _handle_tenant(args)
    if args.fleet:
        return _handle_fleet(args)
    if args.zero_trust:
        return _handle_zero_trust(args)
    return _handle_legacy(args)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Legacy entry point: ``c-uas edge --deploy|--status|--sync``.

    Preserved unchanged for backward compatibility; :func:`edge_main` is the
    entry point used by ``c_uas.cli`` and supports the new --tenant/--fleet/
    --zero-trust modes.
    """
    parser = argparse.ArgumentParser(
        prog="c-uas edge",
        description=(
            "C-UAS edge node deployment: local detection and tracking on "
            "Raspberry Pi / NVIDIA Jetson hardware, with edge-to-cloud sync "
            "when connectivity is restored."
        ),
    )
    parser.add_argument(
        "--deploy",
        action="store_true",
        help="Deploy edge node and run the first local detection cycle",
    )
    parser.add_argument(
        "--status", action="store_true", help="Show edge node health and sync state"
    )
    parser.add_argument(
        "--sync", action="store_true", help="Sync queued detections to the cloud endpoint"
    )
    parser.add_argument("--node-id", type=str, default=None, help="Edge node identifier (required)")
    parser.add_argument(
        "--location",
        type=str,
        default=None,
        help="Site location (required for --deploy)",
    )
    parser.add_argument(
        "--sensors",
        type=str,
        default="sdr,radar,camera",
        help="Comma-separated sensor list (sdr, radar, camera)",
    )
    parser.add_argument(
        "--sync-interval",
        type=float,
        default=300.0,
        help="Cloud sync interval in seconds",
    )
    parser.add_argument(
        "--cloud-endpoint",
        type=str,
        default=None,
        help="Cloud API base URL",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run in offline mode (no cloud sync attempts)",
    )
    parser.add_argument("--seed", type=int, default=42, help="Deterministic RNG seed")
    args = parser.parse_args(argv)

    if not args.node_id or not args.node_id.strip():
        print("[C-UAS] --node-id is required for edge commands")
        return 1

    if args.deploy:
        if not args.location or not args.location.strip():
            print("[C-UAS] --location is required for --deploy")
            return 1
        try:
            config = _build_config(args)
        except ValueError as exc:
            print("[C-UAS] {}".format(exc))
            return 1
        report = EdgeNode(config).deploy()
        print("[C-UAS] Edge node deployed: {}".format(report.node_id))
        print("  Location       : {}".format(report.location))
        print("  State dir      : {}".format(report.state_dir))
        print("  Detections     : {}".format(report.detection_count))
        print("  Tracks         : {}".format(report.track_count))
        print("  Offline mode   : {}".format(report.offline_mode))
        print(
            "  CPU target     : {}% (within: {})".format(
                EdgeNode.CPU_TARGET_PERCENT, report.within_cpu_target
            )
        )
        print(
            "  Memory target  : {} MB (within: {})".format(
                EdgeNode.MEMORY_TARGET_MB, report.within_memory_target
            )
        )
        return 0

    if args.status:
        config = _build_config(args)
        health = EdgeHealth(config).check()
        queue = load_json(args.node_id, "sync_queue", default=[])
        print("[C-UAS] Edge node status: {}".format(args.node_id))
        print("  CPU            : {}%".format(health.cpu_percent))
        print("  Memory         : {} MB / {}%".format(health.memory_mb, health.memory_percent))
        print("  Disk           : {}%".format(health.disk_percent))
        print(
            "  Temperature    : {}".format(
                health.temperature_c if health.temperature_c is not None else "n/a"
            )
        )
        print("  Connectivity   : {}".format(health.connectivity))
        print("  Queued detections: {}".format(len(queue)))
        print("  Within CPU target: {}".format(health.within_cpu_target))
        print("  Within memory target: {}".format(health.within_memory_target))
        for sensor_id in sorted(health.sensors):
            online = health.sensors[sensor_id]
            print("  Sensor {}: {}".format(sensor_id, "online" if online else "offline"))
        return 0

    if args.sync:
        config = _build_config(args)
        sync_report = EdgeSync(config).sync()
        print("[C-UAS] Edge sync: {}".format(sync_report.node_id))
        print("  Reason          : {}".format(sync_report.reason))
        print("  Synced          : {}".format(sync_report.synced_count))
        print("  Delivered       : {}".format(sync_report.delivered_count))
        print("  Pending         : {}".format(sync_report.pending_count))
        print("  Conflicts resolved: {}".format(sync_report.conflicts_resolved))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
