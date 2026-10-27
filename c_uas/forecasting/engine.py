"""Forecasting engine: ingest historical observations, run multiple models,
select the best by deterministic MAPE on a holdout set, and persist results.

State is persisted under ~/.c-uas-platform/forecasting/ (outside the repo) as
JSON. All functions are pure except the explicit save/load IO operations.

License: AGPL-3.0.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple

from .models import (
    DEFAULT_MODEL_CONFIG,
    ForecastConfig,
    ForecastPoint,
    ForecastResult,
    all_available_models,
    evaluate_model_in_sample,
    forecast_with_model,
)

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "forecasting")
FORECAST_SUBDIR = "forecasts"
LATEST_FILENAME = "latest_forecast.json"


@dataclass(frozen=True)
class ForecastIngestion:
    """A recorded ingestion of historical observations for a demand stream."""

    stream_id: str  # e.g. "compute_demand", "drone_track_volume", "api_traffic"
    observations: Tuple[ForecastPoint, ...]
    ingested_at: str  # ISO-8601 UTC
    point_count: int
    time_span_seconds: float
    config_hash: str


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _config_hash(config: ForecastConfig) -> str:
    payload = {
        "model_type": config.model_type,
        "window": config.window,
        "horizon": config.horizon,
        "seasonal_period": config.seasonal_period,
        "alpha": config.alpha,
    }
    return "FC-" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def _observations_hash(stream_id: str, observations: Sequence[ForecastPoint]) -> str:
    payload = [
        {"stream_id": stream_id, "timestamp": o.timestamp, "value": o.value} for o in observations
    ]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def _span_seconds(observations: Sequence[ForecastPoint]) -> float:
    from .models import _to_epoch

    epochs = _to_epoch([o.timestamp for o in observations])
    if len(epochs) < 2:
        return 0.0
    return round(max(epochs) - min(epochs), 4)


# --------------------------------------------------------------------------- #
# Core forecast: run all models, select best by holdout MAPE
# --------------------------------------------------------------------------- #


def run_forecast(
    observations: Sequence[ForecastPoint],
    config: Optional[ForecastConfig] = None,
) -> ForecastResult:
    """Run every supported model on `observations` and return the best one.

    The best model is the one with the lowest deterministic holdout MAPE.
    Ties break in favor of the first model in the sorted model list. The
    returned result is re-run on the full observation set (not just the
    training split) so the forecast reflects all available data.
    """

    if config is None:
        config = DEFAULT_MODEL_CONFIG
    if len(observations) < 1:
        raise ValueError("observations must contain at least one point")

    models = all_available_models()
    best: Optional[ForecastResult] = None
    best_mape: Optional[float] = None

    for model_type in models:
        mape = evaluate_model_in_sample(model_type, observations, config)
        # A model with None MAPE (not enough data) is never preferred over one
        # with a numeric MAPE; lower MAPE wins.
        if mape is None:
            continue
        if best_mape is None or mape < best_mape:
            best_mape = mape
            best = forecast_with_model(model_type, observations, config)

    # Fallback: if no model could be evaluated (tiny dataset), use the first
    # model on the full data with mape=None.
    if best is None:
        best = forecast_with_model(models[0], observations, config)

    # Attach the holdout MAPE of the selected model to the result.
    selected_mape = evaluate_model_in_sample(best.model_name, observations, config)
    return ForecastResult(
        model_name=best.model_name,
        horizon=best.horizon,
        points=best.points,
        mape=selected_mape,
        config=best.config,
    )


def select_best_model(
    observations: Sequence[ForecastPoint],
    config: Optional[ForecastConfig] = None,
) -> str:
    """Return the model_type with the lowest holdout MAPE."""

    if config is None:
        config = DEFAULT_MODEL_CONFIG
    best_type: Optional[str] = None
    best_mape: Optional[float] = None
    for model_type in all_available_models():
        mape = evaluate_model_in_sample(model_type, observations, config)
        if mape is None:
            continue
        if best_mape is None or mape < best_mape:
            best_mape = mape
            best_type = model_type
    if best_type is None:
        return all_available_models()[0]
    return best_type


# --------------------------------------------------------------------------- #
# Ingestion
# --------------------------------------------------------------------------- #


def ingest(
    stream_id: str,
    observations: Sequence[ForecastPoint],
    config: Optional[ForecastConfig] = None,
    state_dir: str = DEFAULT_STATE_DIR,
) -> ForecastIngestion:
    """Record an ingestion of historical observations for a stream.

    Returns a ForecastIngestion metadata record (does not run the forecast;
    use run_forecast for that). Pure in computation; only the returned record
    is deterministic given the same inputs.
    """

    obs_tuple = tuple(observations)
    if config is None:
        config = DEFAULT_MODEL_CONFIG
    return ForecastIngestion(
        stream_id=stream_id,
        observations=obs_tuple,
        ingested_at=_utc_now_iso(),
        point_count=len(obs_tuple),
        time_span_seconds=_span_seconds(obs_tuple),
        config_hash=_config_hash(config),
    )


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def _forecast_dir(state_dir: str) -> str:
    return os.path.join(state_dir, FORECAST_SUBDIR)


def save_forecast(
    result: ForecastResult,
    stream_id: str,
    state_dir: str = DEFAULT_STATE_DIR,
) -> str:
    """Persist a ForecastResult to JSON; return the file path."""

    subdir = _forecast_dir(state_dir)
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, LATEST_FILENAME)
    payload = {
        "stream_id": stream_id,
        "saved_at": _utc_now_iso(),
        "model_name": result.model_name,
        "horizon": result.horizon,
        "mape": result.mape,
        "config": asdict(result.config),
        "points": [asdict(p) for p in result.points],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return path


def load_forecast(state_dir: str = DEFAULT_STATE_DIR) -> Optional[Tuple[str, ForecastResult]]:
    """Load the latest persisted forecast, or None if absent.

    Returns (stream_id, ForecastResult).
    """

    path = os.path.join(_forecast_dir(state_dir), LATEST_FILENAME)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    from .models import ForecastConfig

    config = ForecastConfig(**payload["config"])
    points = tuple(ForecastPoint(**p) for p in payload["points"])
    result = ForecastResult(
        model_name=payload["model_name"],
        horizon=payload["horizon"],
        points=points,
        mape=payload.get("mape"),
        config=config,
    )
    return payload.get("stream_id"), result


def list_persisted(state_dir: str = DEFAULT_STATE_DIR) -> List[str]:
    """List persisted forecast file paths (deterministic sorted order)."""

    subdir = _forecast_dir(state_dir)
    if not os.path.isdir(subdir):
        return []
    files = sorted(os.path.join(subdir, f) for f in os.listdir(subdir) if f.endswith(".json"))
    return files
