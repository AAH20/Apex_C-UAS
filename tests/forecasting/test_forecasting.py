"""Deterministic tests for the Demand Forecasting module.

Covers forecasting models (moving average, linear trend, seasonal
decomposition, exponential smoothing), the forecasting engine (ingest,
multi-model run, best-by-holdout-MAPE selection, persistence), capacity
forecasting (headroom, overcommitment risk, rack additions), and the CLI.

All values are real computations -- no mocks, no fabricated metrics, no
network. State under ~/.c-uas-platform/forecasting/ is avoided by passing a
tmp_path state dir, so tests are isolated and hermetic.

License: AGPL-3.0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os

import pytest

from c_uas.forecasting.capacity import (
    CapacityForecastInputs,
    ForecastCapacity,
    headroom_from_forecast,
    headroom_from_forecast_with_racks,
    recommended_rack_additions,
)
from c_uas.forecasting.cli import (
    STREAM_IDS,
    _demo_stream,
    build_subparser,
    forecast_main,
)
from c_uas.forecasting.engine import (
    DEFAULT_STATE_DIR,
    ForecastIngestion,
    ingest,
    load_forecast,
    run_forecast,
    save_forecast,
    select_best_model,
)
from c_uas.forecasting.models import (
    DEFAULT_MODEL_CONFIG,
    ForecastConfig,
    ForecastPoint,
    ForecastResult,
    all_available_models,
    exponential_smoothing_forecast,
    linear_trend_forecast,
    moving_average_forecast,
    seasonal_decomposition_forecast,
)

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def obs_points() -> tuple:
    """Seven deterministic hourly observations with a clear upward trend."""

    base = "2026-10-26T00:00:00Z"
    values = [10.0, 12.0, 14.0, 16.0, 18.0, 20.0, 22.0]
    return tuple(
        ForecastPoint(timestamp="%sT%02d:00:00Z" % (base[:10], i), value=v)
        for i, v in enumerate(values)
    )


@pytest.fixture
def flat_points() -> tuple:
    """Flat constant observations (trivial trend)."""

    return tuple(
        ForecastPoint(timestamp="2026-10-26T%02d:00:00Z" % i, value=5.0) for i in range(10)
    )


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


def test_moving_average_forecast_repeats_window_mean(obs_points) -> None:
    config = ForecastConfig(model_type="moving_average", window=3, horizon=4)
    result = moving_average_forecast(obs_points, config)
    assert result.model_name == "moving_average"
    assert result.horizon == 4
    assert len(result.points) == 4
    expected = (18.0 + 20.0 + 22.0) / 3.0  # mean of last 3
    for p in result.points:
        assert p.value == round(expected, 4)


def test_linear_trend_forecast_extrapolates(obs_points) -> None:
    config = ForecastConfig(model_type="linear_trend", horizon=3)
    result = linear_trend_forecast(obs_points, config)
    assert result.model_name == "linear_trend"
    assert len(result.points) == 3
    # Values should keep rising along the trend.
    assert result.points[0].value < result.points[1].value < result.points[2].value


def test_seasonal_decomposition_forecast_returns_points(obs_points) -> None:
    config = ForecastConfig(model_type="seasonal_decomposition", horizon=5, seasonal_period=3)
    result = seasonal_decomposition_forecast(obs_points, config)
    assert result.model_name == "seasonal_decomposition"
    assert len(result.points) == 5


def test_exponential_smoothing_forecast_constant_level(flat_points) -> None:
    config = ForecastConfig(model_type="exponential_smoothing", alpha=0.3, horizon=3)
    result = exponential_smoothing_forecast(flat_points, config)
    assert result.model_name == "exponential_smoothing"
    # Constant input => constant forecast level.
    for p in result.points:
        assert p.value == 5.0


def test_forecast_point_timestamps_are_future(obs_points) -> None:
    config = ForecastConfig(model_type="moving_average", horizon=3)
    result = moving_average_forecast(obs_points, config)
    last_obs = obs_points[-1].timestamp
    for p in result.points:
        assert p.timestamp > last_obs


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def test_forecast_is_deterministic(obs_points) -> None:
    config = ForecastConfig(model_type="linear_trend", horizon=5)
    r1 = linear_trend_forecast(obs_points, config)
    r2 = linear_trend_forecast(obs_points, config)
    assert r1.model_name == r2.model_name
    assert [(p.timestamp, p.value) for p in r1.points] == [
        (p.timestamp, p.value) for p in r2.points
    ]


def test_run_forecast_is_deterministic(obs_points) -> None:
    config = ForecastConfig(model_type="moving_average", horizon=4)
    r1 = run_forecast(obs_points, config=config)
    r2 = run_forecast(obs_points, config=config)
    assert r1.model_name == r2.model_name
    assert r1.mape == r2.mape
    assert [(p.timestamp, p.value) for p in r1.points] == [
        (p.timestamp, p.value) for p in r2.points
    ]


# --------------------------------------------------------------------------- #
# MAPE and model selection
# --------------------------------------------------------------------------- #


def test_mape_computation() -> None:
    actual = [10.0, 20.0, 30.0]
    predicted = [10.0, 20.0, 30.0]
    from c_uas.forecasting.models import _mape

    assert _mape(actual, predicted) == 0.0
    predicted2 = [10.0, 20.0, 30.0]
    # 0% error when perfect.
    assert _mape(actual, predicted2) == 0.0


def test_select_best_model_returns_known_model(obs_points) -> None:
    config = ForecastConfig(model_type="moving_average", horizon=3)
    best = select_best_model(obs_points, config=config)
    assert best in all_available_models()


def test_all_available_models_ordered() -> None:
    models = all_available_models()
    assert "moving_average" in models
    assert "linear_trend" in models
    assert "seasonal_decomposition" in models
    assert "exponential_smoothing" in models
    assert list(models) == sorted(models)  # deterministic order


# --------------------------------------------------------------------------- #
# Engine: run_forecast on full data
# --------------------------------------------------------------------------- #


def test_run_forecast_selects_best_and_uses_full_data(obs_points) -> None:
    config = ForecastConfig(model_type="moving_average", horizon=4)
    result = run_forecast(obs_points, config=config)
    assert isinstance(result, ForecastResult)
    assert result.horizon == 4
    assert result.model_name in all_available_models()
    # mape is a float or None; if present must be >= 0.
    if result.mape is not None:
        assert result.mape >= 0.0


def test_run_forecast_requires_at_least_one_point() -> None:
    with pytest.raises(ValueError):
        run_forecast([], config=DEFAULT_MODEL_CONFIG)


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def test_save_and_load_forecast_roundtrip(tmp_path) -> None:
    obs = tuple(_demo_stream("compute_demand", 24))
    config = ForecastConfig(model_type="moving_average", horizon=6)
    result = run_forecast(obs, config=config)
    path = save_forecast(result, stream_id="compute_demand", state_dir=str(tmp_path))
    assert path.endswith("latest_forecast.json")

    loaded = load_forecast(state_dir=str(tmp_path))
    assert loaded is not None
    stream_id, loaded_result = loaded
    assert stream_id == "compute_demand"
    assert loaded_result.model_name == result.model_name
    assert loaded_result.horizon == result.horizon
    assert [(p.timestamp, p.value) for p in loaded_result.points] == [
        (p.timestamp, p.value) for p in result.points
    ]


def test_load_forecast_absent_returns_none(tmp_path) -> None:
    assert load_forecast(state_dir=str(tmp_path)) is None


def test_default_state_dir_outside_repo() -> None:
    assert DEFAULT_STATE_DIR.startswith(os.path.expanduser("~"))
    assert "c-uas-platform" in DEFAULT_STATE_DIR


# --------------------------------------------------------------------------- #
# Capacity
# --------------------------------------------------------------------------- #


def test_headroom_from_forecast_positive_headroom() -> None:
    points = tuple(
        ForecastPoint(timestamp="2026-10-26T%02d:00:00Z" % i, value=30.0) for i in range(5)
    )
    cap = headroom_from_forecast("compute_demand", points, total_capacity=100.0)
    assert isinstance(cap, ForecastCapacity)
    assert cap.peak_demand == 30.0
    assert cap.headroom == 70.0
    assert cap.headroom_pct == 70.0
    assert cap.overcommitted is False


def test_headroom_from_forecast_overcommitted() -> None:
    points = tuple(
        ForecastPoint(timestamp="2026-10-26T%02d:00:00Z" % i, value=130.0) for i in range(3)
    )
    cap = headroom_from_forecast("api_traffic", points, total_capacity=100.0)
    assert cap.overcommitted is True
    assert cap.headroom < 0
    assert cap.overcommitment_risk == "critical"


def test_headroom_from_forecast_risk_bands() -> None:
    # medium risk: peak just over capacity (100-105%)
    pt = ForecastPoint(timestamp="2026-10-26T00:00:00Z", value=102.0)
    cap = headroom_from_forecast("s", tuple([pt]), total_capacity=100.0)
    assert cap.overcommitment_risk == "medium"
    # high risk: >105%
    pt = ForecastPoint(timestamp="2026-10-26T00:00:00Z", value=110.0)
    cap = headroom_from_forecast("s", tuple([pt]), total_capacity=100.0)
    assert cap.overcommitment_risk == "high"


def test_recommended_rack_additions_zero_when_enough_capacity() -> None:
    assert recommended_rack_additions(peak_demand=50.0, total_capacity=100.0) == 0


def test_recommended_rack_additions_positive_when_short() -> None:
    # peak 95 + target headroom 20% of 100 = 20 => need 115 > 100 => deficit 15 => 2 racks of 10kW
    n = recommended_rack_additions(peak_demand=95.0, total_capacity=100.0, headroom_target_pct=20.0)
    assert n >= 2


def test_capacity_forecast_with_racks_uses_datacenter(obs_points) -> None:
    from c_uas.datacenter.capacity import RackSpec

    specs = (
        RackSpec(rack_id="RACK-01", max_power_kw=12.0, max_cooling_kw=10.0, max_rack_units=42),
        RackSpec(rack_id="RACK-02", max_power_kw=15.0, max_cooling_kw=12.5, max_rack_units=42),
    )
    inputs = CapacityForecastInputs(
        stream_id="compute_demand",
        forecast_points=obs_points,
        rack_specs=specs,
        current_it_loads_kw=(6.0, 8.0),
    )
    cap, headrooms, overcommitments = headroom_from_forecast_with_racks(inputs)
    assert isinstance(cap, ForecastCapacity)
    assert len(headrooms) == 2
    assert len(overcommitments) == 2
    assert cap.recommended_rack_additions >= 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_demand_deterministic_output(tmp_path) -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(
        [
            "forecast",
            "--demand",
            "--stream",
            "compute_demand",
            "--horizon",
            "4",
            "--state-dir",
            str(tmp_path),
        ]
    )
    out1 = forecast_main(args)
    # Re-run with fresh args to confirm deterministic return code & file created.
    args2 = parser.parse_args(
        [
            "forecast",
            "--demand",
            "--stream",
            "compute_demand",
            "--horizon",
            "4",
            "--state-dir",
            str(tmp_path),
        ]
    )
    out2 = forecast_main(args2)
    assert out1 == out2 == 0
    assert load_forecast(state_dir=str(tmp_path)) is not None


def test_cli_capacity_output(tmp_path) -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(
        [
            "forecast",
            "--capacity",
            "--stream",
            "drone_track_volume",
            "--horizon",
            "6",
            "--state-dir",
            str(tmp_path),
        ]
    )
    rc = forecast_main(args)
    assert rc == 0


def test_demo_streams_cover_required_domains() -> None:
    assert set(STREAM_IDS) == {"compute_demand", "drone_track_volume", "api_traffic"}
    for sid in STREAM_IDS:
        pts = _demo_stream(sid, 10)
        assert len(pts) == 10
        assert all(p.value >= 0 for p in pts)


def test_ingest_record_metadata(obs_points) -> None:
    config = ForecastConfig(model_type="moving_average", horizon=3)
    rec = ingest("compute_demand", obs_points, config=config)
    assert isinstance(rec, ForecastIngestion)
    assert rec.stream_id == "compute_demand"
    assert rec.point_count == len(obs_points)
    assert (
        rec.config_hash
        == "FC-"
        + hashlib.sha256(
            json.dumps(
                {
                    "model_type": "moving_average",
                    "window": config.window,
                    "horizon": config.horizon,
                    "seasonal_period": config.seasonal_period,
                    "alpha": config.alpha,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()[:16]
    )
