"""MLOps: model registry, drift detection, and A/B testing for C-UAS models.

State persists under ``~/.c-uas-platform/mlops/`` (outside the repo). All
functions are pure and deterministic: identical inputs always yield identical
outputs. No training hardware, no network, no third-party statistical
packages (KS test and chi-squared are implemented in pure math).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from .ab_test import (
    ABTestError,
    Experiment,
    Variant,
    create_experiment,
    determine_winner,
    get_experiment,
    list_experiments,
    record_trial,
    route_variant,
    set_experiment_status,
    variant_metrics,
)
from .drift import DriftReport, FeatureDriftResult, detect_drift
from .registry import (
    ModelRecord,
    archive_model,
    demote_model,
    get_model,
    list_models,
    promote_model,
    register_model,
    remove_model,
    set_stage,
)

__all__ = [
    "ModelRecord",
    "Experiment",
    "Variant",
    "FeatureDriftResult",
    "DriftReport",
    "ABTestError",
    "register_model",
    "list_models",
    "get_model",
    "set_stage",
    "promote_model",
    "demote_model",
    "archive_model",
    "remove_model",
    "detect_drift",
    "create_experiment",
    "route_variant",
    "record_trial",
    "variant_metrics",
    "determine_winner",
    "list_experiments",
    "get_experiment",
    "set_experiment_status",
]
