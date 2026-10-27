"""Deterministic forecasting models for compute demand, drone track volume,
and API traffic.

All models are pure functions: given the same observations and config they
always produce the same forecast. No randomness, no network, no system clock
(materialized timestamps are converted to epoch seconds and treated as pure
numbers).

License: AGPL-3.0.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple

DEFAULT_SEASONAL_PERIOD = 24  # hours of a daily cycle when data is hourly
DEFAULT_WINDOW = 7
DEFAULT_HORIZON = 7
DEFAULT_ALPHA = 0.3
MIN_POINTS_FOR_MODEL = 3
_EPSILON = 1e-9


@dataclass(frozen=True)
class ForecastPoint:
    """A single observed or forecasted value at a point in time."""

    timestamp: str  # ISO-8601 string (deterministic, timezone-naive UTC)
    value: float


@dataclass(frozen=True)
class ForecastResult:
    """Result of a single forecasting model run."""

    model_name: str
    horizon: int
    points: Tuple[ForecastPoint, ...]
    mape: Optional[float]  # holdout MAPE in percent; None if not evaluated
    config: "ForecastConfig"


@dataclass(frozen=True)
class ForecastConfig:
    """Shared configuration across all forecasting models."""

    model_type: str  # one of moving_average, linear_trend,
    # seasonal_decomposition, exponential_smoothing
    window: int = DEFAULT_WINDOW
    horizon: int = DEFAULT_HORIZON
    seasonal_period: int = DEFAULT_SEASONAL_PERIOD
    alpha: float = DEFAULT_ALPHA

    def __post_init__(self) -> None:
        if self.window < 1:
            raise ValueError("window must be >= 1")
        if self.horizon < 1:
            raise ValueError("horizon must be >= 1")
        if self.seasonal_period < 1:
            raise ValueError("seasonal_period must be >= 1")
        if not 0.0 < self.alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")


@dataclass(frozen=True)
class MovingAverageConfig:
    window: int = DEFAULT_WINDOW


@dataclass(frozen=True)
class LinearTrendConfig:
    pass


@dataclass(frozen=True)
class SeasonalDecompositionConfig:
    seasonal_period: int = DEFAULT_SEASONAL_PERIOD


@dataclass(frozen=True)
class ExponentialSmoothingConfig:
    alpha: float = DEFAULT_ALPHA


DEFAULT_MODEL_CONFIG = ForecastConfig(model_type="moving_average")


def _to_epoch(timestamps: Sequence[str]) -> List[float]:
    """Convert ISO-8601 timestamps to epoch seconds (pure float math)."""

    epochs: List[float] = []
    for ts in timestamps:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        epochs.append(dt.timestamp())
    return epochs


def _to_iso(epochs: Sequence[float]) -> List[str]:
    """Convert epoch seconds back to deterministic ISO-8601 UTC strings."""

    return [
        datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") for e in epochs
    ]


def _mape(actual: Sequence[float], predicted: Sequence[float]) -> Optional[float]:
    """Mean Absolute Percentage Error in percent. Returns None if no valid
    (non-zero actual) points can be scored."""

    if len(actual) != len(predicted) or len(actual) == 0:
        return None
    total = 0.0
    count = 0
    for a, p in zip(actual, predicted):
        if abs(a) < _EPSILON:
            continue  # cannot compute a meaningful percentage against zero
        total += abs((a - p) / a)
        count += 1
    if count == 0:
        return None
    return round((total / count) * 100.0, 4)


def _extend_timestamps(last_ts: str, count: int, step_seconds: float) -> List[str]:
    """Produce `count` future ISO timestamps after `last_ts` spaced by step."""

    dt = datetime.fromisoformat(last_ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    base = dt.timestamp()
    return _to_iso([base + step_seconds * (i + 1) for i in range(count)])


def _infer_step_seconds(timestamps: Sequence[str]) -> float:
    """Median gap between consecutive timestamps in seconds."""

    epochs = _to_epoch(list(timestamps))
    if len(epochs) < 2:
        return 3600.0  # default to 1 hour
    gaps = [epochs[i + 1] - epochs[i] for i in range(len(epochs) - 1)]
    gaps.sort()
    mid = len(gaps) // 2
    step = gaps[mid] if len(gaps) % 2 == 1 else (gaps[mid - 1] + gaps[mid]) / 2.0
    return step if step > 0 else 3600.0


# --------------------------------------------------------------------------- #
# Models (pure functions)
# --------------------------------------------------------------------------- #


def moving_average_forecast(
    observations: Sequence[ForecastPoint],
    config: ForecastConfig,
) -> ForecastResult:
    """Forecast by repeating the mean of the last `window` observed values."""

    values = [o.value for o in observations]
    timestamps = [o.timestamp for o in observations]
    window = max(1, min(config.window, len(values))) if values else 1

    if values:
        level = sum(values[-window:]) / window
    else:
        level = 0.0

    step = _infer_step_seconds(timestamps) if timestamps else 3600.0
    last_ts = timestamps[-1] if timestamps else "1970-01-01T00:00:00Z"
    future_ts = _extend_timestamps(last_ts, config.horizon, step)
    points = tuple(ForecastPoint(timestamp=t, value=round(level, 4)) for t in future_ts)

    return ForecastResult(
        model_name="moving_average",
        horizon=config.horizon,
        points=points,
        mape=None,
        config=config,
    )


def linear_trend_forecast(
    observations: Sequence[ForecastPoint],
    config: ForecastConfig,
) -> ForecastResult:
    """Forecast by least-squares linear regression on (epoch, value)."""

    values = [o.value for o in observations]
    timestamps = [o.timestamp for o in observations]
    epochs = _to_epoch(timestamps) if timestamps else []

    n = len(values)
    if n >= 2 and len(epochs) == n:
        x_mean = sum(epochs) / n
        y_mean = sum(values) / n
        num = sum((x - x_mean) * (y - y_mean) for x, y in zip(epochs, values))
        den = sum((x - x_mean) ** 2 for x in epochs)
        if abs(den) < _EPSILON:
            slope = 0.0
            intercept = y_mean
        else:
            slope = num / den
            intercept = y_mean - slope * x_mean
    else:
        slope = 0.0
        intercept = values[-1] if values else 0.0

    step = _infer_step_seconds(timestamps) if timestamps else 3600.0
    last_epoch = epochs[-1] if epochs else 0.0
    future_epochs = [last_epoch + step * (i + 1) for i in range(config.horizon)]
    future_ts = _to_iso(future_epochs)
    points = tuple(
        ForecastPoint(timestamp=t, value=round(intercept + slope * e, 4))
        for t, e in zip(future_ts, future_epochs)
    )

    return ForecastResult(
        model_name="linear_trend",
        horizon=config.horizon,
        points=points,
        mape=None,
        config=config,
    )


def seasonal_decomposition_forecast(
    observations: Sequence[ForecastPoint],
    config: ForecastConfig,
) -> ForecastResult:
    """Additive seasonal decomposition: value = trend + seasonal + residual.

    Trend is a centered moving average with window = seasonal_period.
    Seasonal indices are the average detrended value per period position.
    The forecast extrapolates the last trend level and repeats the seasonal
    pattern.
    """

    values = [o.value for o in observations]
    timestamps = [o.timestamp for o in observations]
    epochs = _to_epoch(timestamps) if timestamps else []
    n = len(values)
    period = max(1, config.seasonal_period)

    if n >= period * 2:
        # Trend via simple moving average with the seasonal period window.
        trend: List[float] = []
        half = period // 2
        for i in range(n):
            lo = max(0, i - half)
            hi = min(n, i + half + 1)
            window_vals = values[lo:hi]
            trend.append(sum(window_vals) / len(window_vals))

        # Detrend and compute seasonal indices by period position.
        detrended = [v - t for v, t in zip(values, trend)]
        seasonal_sums = [0.0] * period
        seasonal_counts = [0] * period
        for i, d in enumerate(detrended):
            pos = i % period
            seasonal_sums[pos] += d
            seasonal_counts[pos] += 1
        seasonal = [
            (seasonal_sums[p] / seasonal_counts[p]) if seasonal_counts[p] > 0 else 0.0
            for p in range(period)
        ]
        # Normalize seasonal indices to average zero (additive constraint).
        s_mean = sum(seasonal) / period
        seasonal = [s - s_mean for s in seasonal]

        # Extrapolate trend: linear fit on trend vs epoch over the observed span.
        if n >= 2 and len(epochs) == n:
            x_mean = sum(epochs) / n
            t_mean = sum(trend) / n
            num = sum((x - x_mean) * (t - t_mean) for x, t in zip(epochs, trend))
            den = sum((x - x_mean) ** 2 for x in epochs)
            slope = num / den if abs(den) > _EPSILON else 0.0
            last_trend = trend[-1]
        else:
            slope = 0.0
            last_trend = values[-1] if values else 0.0

        last_epoch = epochs[-1] if epochs else 0.0
    else:
        # Not enough data for a full decomposition; fall back to mean level.
        trend = list(values) if values else [0.0]
        seasonal = [0.0] * period
        slope = 0.0
        last_trend = values[-1] if values else 0.0
        last_epoch = epochs[-1] if epochs else 0.0

    step = _infer_step_seconds(timestamps) if timestamps else 3600.0
    future_epochs = [last_epoch + step * (i + 1) for i in range(config.horizon)]
    future_ts = _to_iso(future_epochs)
    points = []
    for i, (t, e) in enumerate(zip(future_ts, future_epochs)):
        trend_val = last_trend + slope * (e - last_epoch)
        seas = seasonal[i % period]
        points.append(ForecastPoint(timestamp=t, value=round(trend_val + seas, 4)))

    return ForecastResult(
        model_name="seasonal_decomposition",
        horizon=config.horizon,
        points=tuple(points),
        mape=None,
        config=config,
    )


def exponential_smoothing_forecast(
    observations: Sequence[ForecastPoint],
    config: ForecastConfig,
) -> ForecastResult:
    """Single (simple) exponential smoothing.

    level_t = alpha * value_t + (1 - alpha) * level_{t-1}.
    Forecast is the final level repeated across the horizon.
    """

    values = [o.value for o in observations]
    timestamps = [o.timestamp for o in observations]
    alpha = config.alpha

    level = values[0] if values else 0.0
    for v in values[1:]:
        level = alpha * v + (1.0 - alpha) * level

    step = _infer_step_seconds(timestamps) if timestamps else 3600.0
    last_ts = timestamps[-1] if timestamps else "1970-01-01T00:00:00Z"
    future_ts = _extend_timestamps(last_ts, config.horizon, step)
    points = tuple(ForecastPoint(timestamp=t, value=round(level, 4)) for t in future_ts)

    return ForecastResult(
        model_name="exponential_smoothing",
        horizon=config.horizon,
        points=points,
        mape=None,
        config=config,
    )


# --------------------------------------------------------------------------- #
# Model registry & in-sample evaluation
# --------------------------------------------------------------------------- #


_MODEL_FUNCS = {
    "moving_average": moving_average_forecast,
    "linear_trend": linear_trend_forecast,
    "seasonal_decomposition": seasonal_decomposition_forecast,
    "exponential_smoothing": exponential_smoothing_forecast,
}


def forecast_with_model(
    model_type: str,
    observations: Sequence[ForecastPoint],
    config: ForecastConfig,
) -> ForecastResult:
    """Run a single named model. Pure function."""

    if model_type not in _MODEL_FUNCS:
        raise ValueError(
            f"Unknown model_type: {model_type!r} (expected one of {sorted(_MODEL_FUNCS)})"
        )
    return _MODEL_FUNCS[model_type](observations, config)


def all_available_models() -> Tuple[str, ...]:
    """Ordered list of supported model types (deterministic order)."""

    return tuple(sorted(_MODEL_FUNCS))


def evaluate_model_in_sample(
    model_type: str,
    observations: Sequence[ForecastPoint],
    config: ForecastConfig,
) -> Optional[float]:
    """Compute holdout MAPE for a model: train on the leading portion,
    forecast the holdout window, score against actuals. Returns None if not
    enough data to evaluate."""

    values = [o.value for o in observations]
    timestamps = [o.timestamp for o in observations]
    n = len(values)
    if n < MIN_POINTS_FOR_MODEL + 1:
        return None

    holdout = max(1, n // 4)
    train_n = n - holdout
    if train_n < MIN_POINTS_FOR_MODEL:
        return None

    train_obs = tuple(
        ForecastPoint(timestamp=t, value=v) for t, v in zip(timestamps[:train_n], values[:train_n])
    )
    actual_holdout = values[train_n:]

    # Evaluate with a horizon exactly matching the holdout window so predicted
    # and actual always align one-to-one.
    eval_config = ForecastConfig(
        model_type=model_type,
        window=config.window,
        horizon=len(actual_holdout),
        seasonal_period=config.seasonal_period,
        alpha=config.alpha,
    )
    result = forecast_with_model(model_type, train_obs, eval_config)
    predicted = [p.value for p in result.points]

    return _mape(actual_holdout, predicted)
