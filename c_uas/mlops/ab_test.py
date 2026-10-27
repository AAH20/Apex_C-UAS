"""A/B testing framework for model variants.

* Deterministic hash-based traffic routing: ``route_variant(experiment, key)``
  always returns the same variant for the same ``(experiment_id, key)``.
* Conversion / pk (probability of kill) metrics recorded per variant.
* Winner determination: highest conversion rate, ties broken by mean pk, then
  variant order; requires ``min_trials`` per variant else no winner.

State persists under ``<state_dir>/ab/`` (default:
``~/.c-uas-platform/mlops/ab/``). Frozen dataclasses, pure functions,
atomic JSON writes.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "mlops")
AB_SUBDIR = "ab"
TRIALS_SUBDIR = "trials"
EXPERIMENTS_FILENAME = "experiments.json"

BUCKETS = 100  # hash bucket space for traffic splitting
_WEIGHT_TOLERANCE = 1e-9


@dataclass(frozen=True)
class Variant:
    """One model variant in an experiment with its traffic weight."""

    variant_id: str
    name: str
    model_name: str
    model_version: str
    traffic_weight: float


@dataclass(frozen=True)
class Experiment:
    experiment_id: str
    name: str
    status: str  # "active", "completed", "stopped"
    variants: Tuple[Variant, ...]


@dataclass(frozen=True)
class Trial:
    variant_id: str
    pk: float  # probability of kill for this trial (0..1)
    converted: bool  # conversion outcome (illustrative metric)


@dataclass(frozen=True)
class VariantMetrics:
    variant_id: str
    trials: int
    conversions: int
    conversion_rate: float
    mean_pk: float


@dataclass(frozen=True)
class ABTestError(Exception):
    """Raised on invalid experiment/trial operations."""

    message: str

    def __str__(self) -> str:
        return self.message


def _state_dir(state_dir: Optional[str] = None) -> str:
    if state_dir is not None:
        return state_dir
    return os.environ.get("CUAS_MLOPS_STATE_DIR", DEFAULT_STATE_DIR)


def _ab_dir(state_dir: str) -> Path:
    return Path(state_dir) / AB_SUBDIR


def _experiments_path(state_dir: str) -> Path:
    return _ab_dir(state_dir) / EXPERIMENTS_FILENAME


def _trials_path(state_dir: str, experiment_id: str) -> Path:
    return _ab_dir(state_dir) / TRIALS_SUBDIR / f"{experiment_id}.json"


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp_path, path)


def _load_experiments(state_dir: str) -> Dict[str, Dict[str, Any]]:
    path = _experiments_path(state_dir)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): v for k, v in data.items()}


def _save_experiments(state_dir: str, experiments: Dict[str, Dict[str, Any]]) -> None:
    _atomic_write_json(_experiments_path(state_dir), experiments)


def _dict_to_variant(data: Dict[str, Any]) -> Variant:
    return Variant(
        variant_id=str(data["variant_id"]),
        name=str(data["name"]),
        model_name=str(data["model_name"]),
        model_version=str(data["model_version"]),
        traffic_weight=float(data["traffic_weight"]),
    )


def _dict_to_experiment(experiment_id: str, data: Dict[str, Any]) -> Experiment:
    return Experiment(
        experiment_id=experiment_id,
        name=str(data["name"]),
        status=str(data["status"]),
        variants=tuple(_dict_to_variant(v) for v in data.get("variants", [])),
    )


def create_experiment(
    experiment_id: str,
    name: str,
    variants: List[Variant],
    state_dir: Optional[str] = None,
) -> Experiment:
    """Create an ``active`` experiment. Weights must sum to 1.0; variant ids
    must be unique. Idempotent: re-creating an existing experiment returns it
    unchanged."""
    sdir = _state_dir(state_dir)
    if not experiment_id or not name:
        raise ABTestError("experiment_id and name are required")
    if not variants:
        raise ABTestError("at least one variant is required")
    seen = set()
    total_weight = 0.0
    for variant in variants:
        if variant.variant_id in seen:
            raise ABTestError(f"duplicate variant id: {variant.variant_id}")
        if not (0.0 < variant.traffic_weight <= 1.0):
            raise ABTestError(f"variant {variant.variant_id}: traffic_weight must be in (0, 1]")
        seen.add(variant.variant_id)
        total_weight += variant.traffic_weight
    if abs(total_weight - 1.0) > _WEIGHT_TOLERANCE:
        raise ABTestError(f"traffic weights must sum to 1.0, got {total_weight:.6f}")

    experiments = _load_experiments(sdir)
    if experiment_id in experiments:
        return _dict_to_experiment(experiment_id, experiments[experiment_id])

    payload = {
        "name": name,
        "status": "active",
        "variants": [asdict(v) for v in variants],
    }
    experiments[experiment_id] = payload
    _save_experiments(sdir, experiments)
    return Experiment(
        experiment_id=experiment_id,
        name=name,
        status="active",
        variants=tuple(variants),
    )


def get_experiment(experiment_id: str, state_dir: Optional[str] = None) -> Optional[Experiment]:
    sdir = _state_dir(state_dir)
    data = _load_experiments(sdir).get(experiment_id)
    if data is None:
        return None
    return _dict_to_experiment(experiment_id, data)


def list_experiments(state_dir: Optional[str] = None) -> Tuple[Experiment, ...]:
    sdir = _state_dir(state_dir)
    experiments = _load_experiments(sdir)
    return tuple(_dict_to_experiment(eid, data) for eid, data in sorted(experiments.items()))


def set_experiment_status(
    experiment_id: str, status: str, state_dir: Optional[str] = None
) -> Experiment:
    if status not in ("active", "completed", "stopped"):
        raise ABTestError(f"unknown status: {status!r}")
    sdir = _state_dir(state_dir)
    experiments = _load_experiments(sdir)
    if experiment_id not in experiments:
        raise ABTestError(f"unknown experiment: {experiment_id}")
    experiments[experiment_id]["status"] = status
    _save_experiments(sdir, experiments)
    return _dict_to_experiment(experiment_id, experiments[experiment_id])


def _hash_bucket(experiment_id: str, key: str) -> int:
    """Deterministic bucket in [0, BUCKETS) for ``(experiment_id, key)``."""
    digest = hashlib.sha256(f"{experiment_id}:{key}".encode("utf-8")).hexdigest()
    return int(digest, 16) % BUCKETS


def route_variant(experiment_id: str, key: str, state_dir: Optional[str] = None) -> Variant:
    """Route ``key`` (user/request id) to a variant via hash-based splitting.

    Same ``(experiment_id, key)`` always yields the same variant. Traffic
    shares match ``traffic_weight`` exactly at bucket granularity.
    """
    sdir = _state_dir(state_dir)
    experiment = get_experiment(experiment_id, sdir)
    if experiment is None:
        raise ABTestError(f"unknown experiment: {experiment_id}")
    if experiment.status != "active":
        raise ABTestError(f"experiment not active: {experiment_id} ({experiment.status})")

    bucket = _hash_bucket(experiment_id, key)
    boundary = 0.0
    for variant in experiment.variants:
        boundary += variant.traffic_weight * BUCKETS
        if bucket < boundary + 1e-9:
            return variant
    # Floating-point guard: last variant absorbs any rounding residue.
    return experiment.variants[-1]


def record_trial(
    experiment_id: str,
    variant_id: str,
    pk: float,
    converted: bool = False,
    state_dir: Optional[str] = None,
) -> Trial:
    """Record one trial outcome for a variant. Appends to the trial log."""
    sdir = _state_dir(state_dir)
    experiment = get_experiment(experiment_id, sdir)
    if experiment is None:
        raise ABTestError(f"unknown experiment: {experiment_id}")
    if not any(v.variant_id == variant_id for v in experiment.variants):
        raise ABTestError(f"unknown variant: {variant_id}")
    if not 0.0 <= float(pk) <= 1.0:
        raise ABTestError(f"pk must be in [0, 1], got {pk}")
    trial = Trial(variant_id=variant_id, pk=float(pk), converted=bool(converted))

    path = _trials_path(sdir, experiment_id)
    trials: List[Dict[str, Any]] = []
    if path.exists():
        try:
            trials = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            trials = []
    if not isinstance(trials, list):
        trials = []
    trials.append(asdict(trial))
    _atomic_write_json(path, trials)
    return trial


def _load_trials(sdir: str, experiment_id: str) -> List[Trial]:
    path = _trials_path(sdir, experiment_id)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return []
    if not isinstance(data, list):
        return []
    trials: List[Trial] = []
    for item in data:
        trials.append(
            Trial(
                variant_id=str(item["variant_id"]),
                pk=float(item["pk"]),
                converted=bool(item["converted"]),
            )
        )
    return trials


def variant_metrics(
    experiment_id: str, variant_id: str, state_dir: Optional[str] = None
) -> VariantMetrics:
    sdir = _state_dir(state_dir)
    experiment = get_experiment(experiment_id, sdir)
    if experiment is None:
        raise ABTestError(f"unknown experiment: {experiment_id}")
    if not any(v.variant_id == variant_id for v in experiment.variants):
        raise ABTestError(f"unknown variant: {variant_id}")
    trials = [t for t in _load_trials(sdir, experiment_id) if t.variant_id == variant_id]
    total = len(trials)
    conversions = sum(1 for t in trials if t.converted)
    rate = (conversions / total) if total else 0.0
    mean_pk = (sum(t.pk for t in trials) / total) if total else 0.0
    return VariantMetrics(
        variant_id=variant_id,
        trials=total,
        conversions=conversions,
        conversion_rate=rate,
        mean_pk=mean_pk,
    )


def all_variant_metrics(
    experiment_id: str, state_dir: Optional[str] = None
) -> Tuple[VariantMetrics, ...]:
    experiment = get_experiment(experiment_id, state_dir)
    if experiment is None:
        raise ABTestError(f"unknown experiment: {experiment_id}")
    return tuple(
        variant_metrics(experiment_id, v.variant_id, state_dir) for v in experiment.variants
    )


def determine_winner(
    experiment_id: str,
    min_trials: int = 10,
    state_dir: Optional[str] = None,
) -> Optional[Variant]:
    """Variant with the best (conversion_rate, mean_pk) among variants with
    >= min_trials trials. Ties break by variant order. None if fewer than two
    eligible variants."""
    experiment = get_experiment(experiment_id, state_dir)
    if experiment is None:
        raise ABTestError(f"unknown experiment: {experiment_id}")
    metrics = all_variant_metrics(experiment_id, state_dir)
    eligible = [m for m in metrics if m.trials >= min_trials]
    if len(eligible) < 2:
        return None
    best = max(eligible, key=lambda m: (m.conversion_rate, m.mean_pk))
    for variant in experiment.variants:
        if variant.variant_id == best.variant_id:
            return variant
    return None  # pragma: no cover - unreachable


def complete_experiment(experiment_id: str, state_dir: Optional[str] = None) -> Experiment:
    """Mark an experiment completed, recording its current winner."""
    winner = determine_winner(experiment_id, state_dir=state_dir)
    sdir = _state_dir(state_dir)
    experiments = _load_experiments(sdir)
    if experiment_id not in experiments:
        raise ABTestError(f"unknown experiment: {experiment_id}")
    experiments[experiment_id]["status"] = "completed"
    if winner is not None:
        experiments[experiment_id]["winner_variant_id"] = winner.variant_id
    _save_experiments(sdir, experiments)
    return _dict_to_experiment(experiment_id, experiments[experiment_id])
