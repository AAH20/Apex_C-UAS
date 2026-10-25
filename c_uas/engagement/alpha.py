"""
Alpha measurement: engagement scheduler vs counterfactual baselines.

Alpha = scheduler_Pk − max(counterfactual_Pk). Positive alpha means the
scheduler outperforms every counterfactual control. Statistical significance
is assessed via a deterministic bootstrap over counterfactual expected-kills
(resampled with replacement under a fixed seed), yielding a p-value for the
null hypothesis that alpha <= 0.

Results persist under ~/.c-uas-platform/engagement/alpha/.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

ALPHA_ROOT = Path(
    os.environ.get(
        "C_UAS_ENGAGEMENT_STATE_DIR",
        Path.home() / ".c-uas-platform" / "engagement" / "alpha",
    )
)


def _atomic_write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    os.replace(tmp, path)


@dataclass(frozen=True)
class AlphaResult:
    """Outcome of an alpha measurement."""

    scenario_name: str
    seed: int
    scheduler_pk: float
    best_counterfactual_pk: float
    alpha: float
    p_value: float
    significant: bool  # p_value < 0.05
    n_bootstrap: int
    bootstrap_mean: float
    bootstrap_std: float
    bootstrap_ci_lower: float
    bootstrap_ci_upper: float
    control_pks: Dict[str, float]


def _alpha_seed(scenario_seed: int) -> int:
    digest = hashlib.sha256(f"{scenario_seed}:alpha".encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % (2**31)


def _percentile(sorted_values: List[float], q: float) -> float:
    """Linear-interpolation percentile of a sorted list (deterministic)."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * q
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    d0 = sorted_values[int(f)] * (c - k)
    d1 = sorted_values[int(c)] * (k - f)
    return d0 + d1


def compute_alpha(
    scheduler_pk: float,
    control_pks: List[float],
    control_names: List[str],
    seed: int,
    n_bootstrap: int = 2000,
    alpha_level: float = 0.05,
) -> AlphaResult:
    """Measure scheduler alpha against counterfactuals.

    alpha = scheduler_pk − max(control_pks).

    Deterministic bootstrap: resample the counterfactual expected-kills with
    replacement under ``seed``, recompute alpha* = scheduler_pk −
    max(resampled) each iteration, and derive a p-value as the fraction of
    bootstrap replicates with alpha* <= 0 (null: no positive alpha).
    """
    rng = random.Random(seed)
    best_ctrl_pk = max(control_pks) if control_pks else 0.0
    alpha_point = scheduler_pk - best_ctrl_pk

    replicates: List[float] = []
    n_ctrl = len(control_pks)
    for _ in range(n_bootstrap):
        if n_ctrl > 0:
            sample = [rng.choice(control_pks) for _ in range(n_ctrl)]
            alpha_star = scheduler_pk - max(sample)
        else:
            alpha_star = alpha_point
        replicates.append(alpha_star)

    replicates.sort()
    exceed_zero = sum(1 for a in replicates if a > 0)
    # p-value: fraction of replicates where alpha* <= 0 (fail to reject null)
    p_value = 1.0 - (exceed_zero / n_bootstrap) if n_bootstrap else 1.0
    p_value = min(max(p_value, 0.0), 1.0)

    mean = sum(replicates) / n_bootstrap if n_bootstrap else 0.0
    variance = sum((a - mean) ** 2 for a in replicates) / n_bootstrap if n_bootstrap else 0.0
    std = math.sqrt(variance)
    ci_lower = _percentile(replicates, alpha_level / 2.0)
    ci_upper = _percentile(replicates, 1.0 - alpha_level / 2.0)

    return AlphaResult(
        scenario_name="",
        seed=seed,
        scheduler_pk=round(scheduler_pk, 3),
        best_counterfactual_pk=round(best_ctrl_pk, 3),
        alpha=round(alpha_point, 4),
        p_value=round(p_value, 4),
        significant=p_value < alpha_level,
        n_bootstrap=n_bootstrap,
        bootstrap_mean=round(mean, 4),
        bootstrap_std=round(std, 4),
        bootstrap_ci_lower=round(ci_lower, 4),
        bootstrap_ci_upper=round(ci_upper, 4),
        control_pks={name: round(pk, 3) for name, pk in zip(control_names, control_pks)},
    )


def measure_alpha(
    scenario_name: str,
    scenario_seed: int,
    scheduler_pk: float,
    control_pks: List[float],
    control_names: List[str],
    n_bootstrap: int = 2000,
) -> AlphaResult:
    """Convenience: compute alpha and fill scenario metadata."""
    result = compute_alpha(
        scheduler_pk=scheduler_pk,
        control_pks=control_pks,
        control_names=control_names,
        seed=_alpha_seed(scenario_seed),
        n_bootstrap=n_bootstrap,
    )
    return AlphaResult(
        scenario_name=scenario_name,
        seed=result.seed,
        scheduler_pk=result.scheduler_pk,
        best_counterfactual_pk=result.best_counterfactual_pk,
        alpha=result.alpha,
        p_value=result.p_value,
        significant=result.significant,
        n_bootstrap=result.n_bootstrap,
        bootstrap_mean=result.bootstrap_mean,
        bootstrap_std=result.bootstrap_std,
        bootstrap_ci_lower=result.bootstrap_ci_lower,
        bootstrap_ci_upper=result.bootstrap_ci_upper,
        control_pks=result.control_pks,
    )


def save_alpha_result(result: AlphaResult) -> Path:
    """Persist an alpha result under ~/.c-uas-platform/engagement/alpha/."""
    ALPHA_ROOT.mkdir(parents=True, exist_ok=True)
    safe = result.scenario_name.replace("/", "_").replace(" ", "_")
    path = ALPHA_ROOT / f"{safe}_{result.seed}.json"
    _atomic_write_json(path, asdict(result))
    return path


def load_alpha_result(scenario_name: str, seed: int) -> Optional[AlphaResult]:
    """Load a persisted alpha result, or None if not stored yet."""
    safe = scenario_name.replace("/", "_").replace(" ", "_")
    path = ALPHA_ROOT / f"{safe}_{seed}.json"
    if not path.exists():
        return None
    with path.open() as fh:
        data = json.load(fh)
    return AlphaResult(**data)
