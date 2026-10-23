"""
CLI for the hardware abstraction layer:

    c-uas hardware --list     list sensors and capabilities
    c-uas hardware --scan     run detection on all sensors
    c-uas hardware --fuse     fuse detections into tracks
    c-uas hardware --status   health-check all sensors

All adapters run in deterministic simulation mode when no hardware is
present; output is fully determined by the --seed value.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .camera_adapter import CameraAdapter
from .radar_adapter import RadarAdapter
from .sensor_fusion import SensorFusion
from .sdr_adapter import SDRAdapter
from .state import save_detections, save_status, save_tracks


def _build_sensors(seed: int = 42) -> List:
    return [
        SDRAdapter(sensor_id="sdr-0", seed=seed, simulation=True),
        RadarAdapter(sensor_id="radar-0", seed=seed, simulation=True),
        CameraAdapter(sensor_id="camera-0", seed=seed, simulation=True),
    ]


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="c-uas hardware",
        description=(
            "C-UAS hardware abstraction layer: SDR, radar, and camera "
            "sensors with deterministic simulation mode and track fusion."
        ),
    )
    parser.add_argument(
        "--list", action="store_true", help="List sensors and capabilities"
    )
    parser.add_argument(
        "--scan", action="store_true", help="Run detection on all sensors"
    )
    parser.add_argument(
        "--fuse", action="store_true", help="Fuse detections into tracks"
    )
    parser.add_argument(
        "--status", action="store_true", help="Health-check all sensors"
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Deterministic RNG seed"
    )
    args = parser.parse_args(argv)

    sensors = _build_sensors(args.seed)

    if args.list or not any([args.scan, args.fuse, args.status]):
        print("[C-UAS] Hardware sensors:")
        for s in sensors:
            st = s.get_status()
            save_status(
                st.sensor_id,
                st.online,
                st.simulation_mode,
                st.message,
            )
            print(
                f"  {st.sensor_id}: {st.capability.value} | "
                f"simulation={st.simulation_mode} | online={st.online} | {st.message}"
            )
        if not any([args.scan, args.fuse, args.status]):
            return 0

    if args.status:
        print("[C-UAS] Sensor health check:")
        all_ok = True
        for s in sensors:
            ok = s.health_check()
            all_ok = all_ok and ok
            st = s.get_status()
            save_status(
                st.sensor_id,
                st.online,
                st.simulation_mode,
                st.message,
            )
            print(f"  {s.sensor_id}: {'OK' if ok else 'FAIL'}")
        return 0 if all_ok else 1

    if args.scan:
        all_detections = []
        for s in sensors:
            dets = s.detect()
            all_detections.extend(dets)
            save_detections(s.sensor_id, dets)
            print(f"[C-UAS] {s.sensor_id}: {len(dets)} detections")
            for d in dets:
                print(
                    f"    {d.source} @ ({d.x_m:.1f}, {d.y_m:.1f}, {d.z_m:.1f})m "
                    f"conf={d.confidence:.2f}"
                )
        return 0

    if args.fuse:
        fusion = SensorFusion(seed=args.seed)
        detections = []
        for s in sensors:
            detections.extend(s.detect())
        tracks = fusion.fuse(detections)
        save_tracks(tracks)
        print(
            f"[C-UAS] Fused {len(detections)} detections into {len(tracks)} tracks"
        )
        for t in tracks:
            print(
                f"  {t.track_id}: ({t.x_m:.1f}, {t.y_m:.1f}, {t.z_m:.1f})m "
                f"conf={t.confidence:.2f} sensors={','.join(t.sensors)} "
                f"sources={','.join(t.sources)}"
            )
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
