"""Demand Forecasting module: deterministic time-series forecasts for capacity
planning (compute demand, drone track volume, API traffic).

Provides deterministic forecasting models (moving average, linear trend,
seasonal decomposition, exponential smoothing), an engine that ingests
historical observations, runs multiple models, selects the best by
deterministic MAPE on a holdout set, and persists results under
~/.c-uas-platform/forecasting/ (outside the repo).

A pure, advisory module -- no actuation, no randomness without a seed, no
network. Same input always produces the same output.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

from .capacity import (
    ForecastCapacity,
    headroom_from_forecast,
    recommended_rack_additions,
)
from .cli import build_subparser, forecast_main
from .engine import (
    ForecastIngestion,
    load_forecast,
    run_forecast,
    save_forecast,
    select_best_model,
)
from .models import (
    DEFAULT_MODEL_CONFIG,
    ExponentialSmoothingConfig,
    ForecastConfig,
    ForecastPoint,
    ForecastResult,
    LinearTrendConfig,
    MovingAverageConfig,
    SeasonalDecompositionConfig,
    exponential_smoothing_forecast,
    linear_trend_forecast,
    moving_average_forecast,
    seasonal_decomposition_forecast,
)

__all__ = [
    "build_subparser",
    "forecast_main",
    # models
    "ForecastConfig",
    "ForecastPoint",
    "ForecastResult",
    "MovingAverageConfig",
    "LinearTrendConfig",
    "SeasonalDecompositionConfig",
    "ExponentialSmoothingConfig",
    "DEFAULT_MODEL_CONFIG",
    "moving_average_forecast",
    "linear_trend_forecast",
    "seasonal_decomposition_forecast",
    "exponential_smoothing_forecast",
    # engine
    "ForecastIngestion",
    "run_forecast",
    "select_best_model",
    "save_forecast",
    "load_forecast",
    # capacity
    "ForecastCapacity",
    "headroom_from_forecast",
    "recommended_rack_additions",
]
