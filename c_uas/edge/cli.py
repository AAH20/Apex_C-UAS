"""
CLI for C-UAS edge node deployment:

    c-uas edge --deploy --node-id SITE-01 --location "Roof, Building A"
    c-uas edge --status --node-id SITE-01
    c-uas edge --sync --node-id SITE-01 --cloud-endpoint https://cloud.a2zsoc.com
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from .config import EdgeConfig
from .health import EdgeHealth
from .node import EdgeNode
from .state import load_json
from .sync import EdgeSync


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


def main(argv: Optional[Sequence[str]] = None) -> int:
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
    parser.add_argument("--cloud-endpoint", type=str, default=None, help="Cloud API base URL")
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
