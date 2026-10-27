"""``c-uas forecast`` subcommand: deterministic time-series forecasts of
compute demand, drone track volume, and API traffic for capacity planning.

Usage:
    c-uas forecast --demand --horizon 30
    c-uas forecast --capacity --horizon 30
    c-uas forecast --demand --stream compute_demand --horizon 14

Integrates c_uas/forecasting/ (models, engine, capacity) into the platform CLI.
All output is deterministic: identical inputs produce identical output. State
persists under ~/.c-uas-platform/forecasting/ (outside the repo). Advisory
only -- no capacity is provisioned automatically.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import argparse
import math
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Tuple

from .capacity import (
    CapacityForecastInputs,
    ForecastCapacity,
    headroom_from_forecast_with_racks,
)
from .engine import (
    DEFAULT_STATE_DIR,
    ForecastIngestion,
    ingest,
    run_forecast,
    save_forecast,
)
from .models import (
    DEFAULT_MODEL_CONFIG,
    ForecastConfig,
    ForecastPoint,
    all_available_models,
)

# --------------------------------------------------------------------------- #
# Deterministic demo observation generators (pure functions)
# --------------------------------------------------------------------------- #


def _base_timestamps(count: int, step_hours: int = 1) -> List[str]:
    """Generate `count` deterministic hourly ISO timestamps ending at a fixed
    reference time (so output never depends on the wall clock)."""

    ref = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)
    return [
        (ref - timedelta(hours=step_hours * (count - 1 - i))).strftime("%Y-%m-%dT%H:%M:%SZ")
        for i in range(count)
    ]


def _demo_stream(stream_id: str, count: int = 168) -> List[ForecastPoint]:
    """Deterministic historical observations for a demand stream.

    Streams:
      compute_demand     : baseline + daily sine + linear growth
      drone_track_volume : baseline + weekly sine + noise-free jitter
      api_traffic        : baseline + hourly sine + step changes
    """

    ts = _base_timestamps(count)
    points: List[ForecastPoint] = []
    for i, t in enumerate(ts):
        hour = i % 24
        day = i // 24
        if stream_id == "compute_demand":
            value = 50.0 + 15.0 * math.sin(2 * math.pi * hour / 24.0) + 0.1 * day
        elif stream_id == "drone_track_volume":
            value = 30.0 + 8.0 * math.sin(2 * math.pi * day / 7.0) + 0.05 * i
        elif stream_id == "api_traffic":
            value = (
                120.0 + 40.0 * math.sin(2 * math.pi * hour / 24.0) + (5.0 if day % 2 == 1 else 0.0)
            )
        else:
            value = 40.0 + 5.0 * __import__("math").sin(2 * __import__("math").pi * i / 24.0)
        points.append(ForecastPoint(timestamp=t, value=round(value, 4)))
    return points


STREAM_IDS = ("compute_demand", "drone_track_volume", "api_traffic")


def _demo_rack_specs() -> Tuple:
    from c_uas.datacenter.capacity import RackSpec

    return (
        RackSpec(rack_id="RACK-01", max_power_kw=12.0, max_cooling_kw=10.0, max_rack_units=42),
        RackSpec(rack_id="RACK-02", max_power_kw=15.0, max_cooling_kw=12.5, max_rack_units=42),
        RackSpec(rack_id="RACK-03", max_power_kw=10.0, max_cooling_kw=9.0, max_rack_units=42),
    )


# --------------------------------------------------------------------------- #
# Subparser
# --------------------------------------------------------------------------- #


def build_subparser(subparsers: Any) -> Any:
    """Register the ``forecast`` subcommand on a parent parser."""

    parser = subparsers.add_parser(
        "forecast",
        help=(
            "Deterministic time-series forecasting of compute demand, drone "
            "track volume, and API traffic for capacity planning"
        ),
    )
    parser.add_argument(
        "--demand",
        action="store_true",
        help="Run a demand forecast for the selected stream",
    )
    parser.add_argument(
        "--capacity",
        action="store_true",
        help="Run a capacity forecast (headroom, overcommitment, rack additions)",
    )
    parser.add_argument(
        "--stream",
        type=str,
        default="compute_demand",
        help=f"Demand stream ({', '.join(STREAM_IDS)}; default: compute_demand)",
    )
    parser.add_argument(
        "--horizon",
        type=int,
        default=DEFAULT_MODEL_CONFIG.horizon,
        help="Forecast horizon in points (default: %d)" % DEFAULT_MODEL_CONFIG.horizon,
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help=(
            "Force a specific model (%s). Default: auto-select by holdout MAPE"
            % ", ".join(all_available_models())
        ),
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default=DEFAULT_STATE_DIR,
        help=("State directory for persisted forecasts (default: ~/.c-uas-platform/forecasting/)"),
    )
    return parser


# --------------------------------------------------------------------------- #
# Renderers (pure text, deterministic)
# --------------------------------------------------------------------------- #


def _render_forecast(stream_id: str, result, ingest: ForecastIngestion) -> str:
    lines: List[str] = []
    lines.append("[C-UAS] Demand Forecast: %s" % stream_id)
    lines.append("=" * 52)
    lines.append("Model        : %s" % result.model_name)
    lines.append("Horizon      : %d point(s)" % result.horizon)
    map_text = "n/a (insufficient data)" if result.mape is None else "%.2f%%" % result.mape
    lines.append("Holdout MAPE : %s" % map_text)
    lines.append("Observations : %d" % ingest.point_count)
    lines.append("Time span    : %.1f seconds" % ingest.time_span_seconds)
    lines.append("Config hash  : %s" % ingest.config_hash)
    lines.append("-" * 52)
    lines.append("Forecast points:")
    for p in result.points:
        lines.append("  %-20s %10.4f" % (p.timestamp, p.value))
    return "\n".join(lines)


def _render_capacity(cap: ForecastCapacity) -> str:
    lines: List[str] = []
    lines.append("[C-UAS] Capacity Forecast: %s" % cap.stream_id)
    lines.append("=" * 52)
    lines.append("Horizon              : %d point(s)" % cap.horizon)
    lines.append("Peak demand          : %.4f" % cap.peak_demand)
    lines.append("Mean demand          : %.4f" % cap.mean_demand)
    lines.append("Total capacity       : %.4f" % cap.total_capacity)
    lines.append("Headroom             : %.4f" % cap.headroom)
    lines.append("Headroom %%          : %.2f%%" % cap.headroom_pct)
    lines.append("Overcommitted        : %s" % cap.overcommitted)
    lines.append("Overcommitment risk  : %s" % cap.overcommitment_risk)
    lines.append("Limiting factor      : %s" % cap.limiting_factor)
    lines.append("Recommended racks    : %d" % cap.recommended_rack_additions)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #


def _build_config(args: argparse.Namespace) -> ForecastConfig:
    model_type = args.model or DEFAULT_MODEL_CONFIG.model_type
    return ForecastConfig(
        model_type=model_type,
        window=DEFAULT_MODEL_CONFIG.window,
        horizon=max(1, args.horizon),
        seasonal_period=DEFAULT_MODEL_CONFIG.seasonal_period,
        alpha=DEFAULT_MODEL_CONFIG.alpha,
    )


def handle_demand(args: argparse.Namespace, state_dir: str) -> str:
    stream_id = args.stream
    if stream_id not in STREAM_IDS:
        raise ValueError(
            "Unknown stream: %r (expected one of %s)" % (stream_id, ", ".join(STREAM_IDS))
        )
    observations = tuple(_demo_stream(stream_id))
    config = _build_config(args)
    ingest_record = ingest(stream_id, observations, config=config, state_dir=state_dir)
    result = run_forecast(observations, config=config)
    save_forecast(result, stream_id=stream_id, state_dir=state_dir)
    return _render_forecast(stream_id, result, ingest_record)


def handle_capacity(args: argparse.Namespace, state_dir: str) -> str:
    stream_id = args.stream
    if stream_id not in STREAM_IDS:
        raise ValueError(
            "Unknown stream: %r (expected one of %s)" % (stream_id, ", ".join(STREAM_IDS))
        )
    observations = tuple(_demo_stream(stream_id))
    config = _build_config(args)
    result = run_forecast(observations, config=config)

    # Also compute rack-level detail using real datacenter capacity math.
    rack_specs = _demo_rack_specs()
    current_loads = (6.0, 8.0, 4.0)
    inputs = CapacityForecastInputs(
        stream_id=stream_id,
        forecast_points=result.points,
        rack_specs=rack_specs,
        current_it_loads_kw=current_loads,
    )
    cap_full, headrooms, overcommitments = headroom_from_forecast_with_racks(inputs)

    # Persist the demand forecast too.
    ingest(stream_id, observations, config=config, state_dir=state_dir)
    save_forecast(result, stream_id=stream_id, state_dir=state_dir)

    lines: List[str] = []
    lines.append(_render_capacity(cap_full))
    lines.append("-" * 52)
    lines.append("Per-rack headroom (datacenter model):")
    for h in sorted(headrooms, key=lambda x: x.rack_id):
        lines.append(
            "  %-9s power=%5.1f%% cooling=%5.1f%% space=%5.1f%% -> %s"
            % (
                h.rack_id,
                h.headroom_power_pct,
                h.headroom_cooling_pct,
                h.headroom_units_pct,
                h.limiting_factor,
            )
        )
    lines.append("-" * 52)
    lines.append("Per-rack overcommitment:")
    for o in sorted(overcommitments, key=lambda x: x.rack_id):
        mark = "OVERCOMMITTED" if o.overcommitted else "ok"
        over_pct = max(
            o.power_overcommit_pct,
            o.cooling_overcommit_pct,
            o.space_overcommit_pct,
        )
        lines.append(
            "  %-9s risk=%-9s %.1f%% over physical  %s" % (o.rack_id, o.risk_level, over_pct, mark)
        )
    return "\n".join(lines)


def forecast_main(args: argparse.Namespace) -> int:
    state_dir = getattr(args, "state_dir", DEFAULT_STATE_DIR)
    if args.capacity:
        output = handle_capacity(args, state_dir=state_dir)
    elif args.demand:
        output = handle_demand(args, state_dir=state_dir)
    else:
        print("[C-UAS] forecast: specify --demand or --capacity")
        print("  c-uas forecast --demand --horizon 30")
        print("  c-uas forecast --capacity --horizon 30 --stream api_traffic")
        return 1
    print(output)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="c-uas forecast",
        description="Deterministic demand & capacity forecasting for the C-UAS platform.",
    )
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 1
    return forecast_main(args)


if __name__ == "__main__":
    import sys

    sys.exit(main())
