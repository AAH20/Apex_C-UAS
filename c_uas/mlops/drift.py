"""Drift detection: inference-time features vs a training baseline.

Two statistical tests, both implemented in pure math (no scipy):

* numeric features  -> two-sample Kolmogorov-Smirnov test on the raw samples;
  drift score = the KS statistic D in [0, 1].
* categorical features -> chi-squared goodness-of-fit of the current
  category counts against baseline proportions, summarized with Cramér's V in
  [0, 1].

A feature is flagged drifted when its score exceeds ``threshold``. Pure
functions, deterministic: identical inputs always produce identical reports.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple, Union

FeatureValues = Union[Sequence[float], Dict[str, int]]


@dataclass(frozen=True)
class FeatureDriftResult:
    """Drift outcome for a single feature."""

    feature: str
    test: str  # "ks_2samp" or "chisq"
    drift_score: float  # KS D or Cramer's V, both in [0, 1]
    p_value: float
    threshold: float
    drifted: bool
    baseline_size: int
    current_size: int
    detail: Dict[str, Any]


@dataclass(frozen=True)
class DriftReport:
    """One drift comparison: baseline vs inference-time samples."""

    threshold: float
    results: Tuple[FeatureDriftResult, ...]

    @property
    def any_drifted(self) -> bool:
        return any(result.drifted for result in self.results)

    @property
    def drifted_features(self) -> Tuple[str, ...]:
        return tuple(result.feature for result in self.results if result.drifted)


def _is_categorical(values: FeatureValues) -> bool:
    return isinstance(values, dict)


def _sorted_numeric(values: Sequence[float]) -> List[float]:
    return sorted(float(v) for v in values)


def ks_2samp(baseline: Sequence[float], current: Sequence[float]) -> Tuple[float, float]:
    """Two-sample Kolmogorov-Smirnov statistic and p-value.

    Pure-Python implementation: D = sup_x |F_baseline(x) - F_current(x)|
    with the standard Kolmogorov distribution approximation for the p-value.
    Deterministic: no RNG, no sorting randomness beyond ordered data.
    """
    n1 = len(baseline)
    n2 = len(current)
    if n1 < 2 or n2 < 2:
        return 0.0, 1.0

    s1 = _sorted_numeric(baseline)
    s2 = _sorted_numeric(current)
    i1 = i2 = 0
    d = 0.0
    # Walk the merged sample in order. At each unique value x, advance both
    # cursors past every sample <= x, so i1/n1 and i2/n2 are the right-
    # continuous ECDF values F(x). The max |F1 - F2| over these points is D.
    while i1 < n1 or i2 < n2:
        if i2 >= n2 or (i1 < n1 and s1[i1] <= s2[i2]):
            x = s1[i1]
        else:
            x = s2[i2]
        while i1 < n1 and s1[i1] <= x:
            i1 += 1
        while i2 < n2 and s2[i2] <= x:
            i2 += 1
        diff = abs(i1 / n1 - i2 / n2)
        if diff > d:
            d = diff

    n_eff = (n1 * n2) / (n1 + n2)
    sqrt_n = math.sqrt(n_eff)
    lam = (sqrt_n + 0.12 + 0.11 / sqrt_n) * d
    if lam <= 0.0:
        p_value = 1.0
    else:
        p_value = _kolmogorov_sf(lam)
    return d, min(1.0, max(0.0, p_value))


def _kolmogorov_sf(lam: float) -> float:
    """Survival function of the Kolmogorov distribution: 2 * sum (-1)^(k-1)
    exp(-2 k^2 lam^2). Alternating series; terms shrink superexponentially."""
    total = 0.0
    sign = 1.0
    k = 1
    lam2 = lam * lam
    while True:
        term = math.exp(-2.0 * k * k * lam2)
        total += sign * term
        sign = -sign
        k += 1
        if term < 1e-16 or k > 200:
            break
    return max(0.0, min(1.0, 2.0 * total))


def _gamma_upper_regularized(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x): series for small x,
    continued fraction (Numerical Recipes) for large x. Deterministic."""
    if x <= 0.0:
        return 1.0
    gln = math.lgamma(a)
    if x < a + 1.0:
        # Lower series P(a, x); Q = 1 - P.
        ap = a
        total = 1.0 / a
        delta = total
        for _ in range(200):
            ap += 1.0
            delta *= x / ap
            total += delta
            if abs(delta) < abs(total) * 1e-14:
                break
        p = math.exp(-x + a * math.log(x) - gln) * total
        return max(0.0, min(1.0, 1.0 - p))
    # Continued fraction for Q(a, x) directly.
    b = x + 1.0 - a
    c = 1.0 / 1.0e-30
    d = 1.0 / b
    h = d
    for i in range(1, 200):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < 1.0e-30:
            d = 1.0e-30
        c = b + an / c
        if abs(c) < 1.0e-30:
            c = 1.0e-30
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1.0e-14:
            break
    return max(0.0, min(1.0, math.exp(-x + a * math.log(x) - gln) * h))


def chisq_pvalue(chi2: float, df: int) -> float:
    """Chi-squared survival function P(ChiSq_df >= chi2) = Q(df/2, chi2/2)."""
    if df <= 0:
        return 1.0
    if chi2 <= 0.0:
        return 1.0
    return _gamma_upper_regularized(0.5 * df, 0.5 * chi2)


def _cramers_v(chi2: float, n: int, df: int) -> float:
    if n <= 0 or df <= 0:
        return 0.0
    v = math.sqrt(chi2 / (n * df))
    return min(1.0, v)


def feature_drift(
    baseline: FeatureValues,
    current: FeatureValues,
    threshold: float = 0.2,
) -> FeatureDriftResult:
    """Drift result for one feature given baseline vs current observations."""
    baseline_list: List[float]
    current_list: List[float]
    baseline_counts: Dict[str, int]
    current_counts: Dict[str, int]

    if _is_categorical(baseline) or _is_categorical(current):
        if not isinstance(baseline, dict) or not isinstance(current, dict):
            raise ValueError("baseline and current must both be numeric or both categorical")
        baseline_counts = {str(k): int(v) for k, v in baseline.items()}
        current_counts = {str(k): int(v) for k, v in current.items()}
        categories = sorted(set(baseline_counts) | set(current_counts))
        n_base = sum(baseline_counts.values())
        n_curr = sum(current_counts.values())
        detail: Dict[str, Any] = {
            "categories": categories,
            "baseline_counts": {c: baseline_counts.get(c, 0) for c in categories},
            "current_counts": {c: current_counts.get(c, 0) for c in categories},
        }
        if n_base <= 0 or n_curr <= 0 or len(categories) < 2:
            return FeatureDriftResult(
                feature="",
                test="chisq",
                drift_score=0.0,
                p_value=1.0,
                threshold=threshold,
                drifted=False,
                baseline_size=n_base,
                current_size=n_curr,
                detail=detail,
            )
        proportions = {c: baseline_counts.get(c, 0) / n_base for c in categories}
        chi2 = 0.0
        infinite = False
        for c in categories:
            expected = proportions[c] * n_curr
            observed = current_counts.get(c, 0)
            if expected <= 0.0:
                if observed > 0:
                    infinite = True
            else:
                chi2 += (observed - expected) ** 2 / expected
        if infinite:
            chi2 = math.inf
        df = len(categories) - 1
        p_value = 0.0 if infinite else chisq_pvalue(chi2, df)
        score = 1.0 if infinite else _cramers_v(chi2, n_curr, df)
        drifted = score > threshold
        return FeatureDriftResult(
            feature="",
            test="chisq",
            drift_score=score,
            p_value=p_value,
            threshold=threshold,
            drifted=drifted,
            baseline_size=n_base,
            current_size=n_curr,
            detail=detail,
        )

    baseline_list = [float(v) for v in baseline]
    current_list = [float(v) for v in current]
    d, p_value = ks_2samp(baseline_list, current_list)
    detail = {
        "statistic": d,
        "n_baseline": len(baseline_list),
        "n_current": len(current_list),
    }
    drifted = d > threshold
    return FeatureDriftResult(
        feature="",
        test="ks_2samp",
        drift_score=d,
        p_value=p_value,
        threshold=threshold,
        drifted=drifted,
        baseline_size=len(baseline_list),
        current_size=len(current_list),
        detail=detail,
    )


def detect_drift(
    baseline: Dict[str, FeatureValues],
    current: Dict[str, FeatureValues],
    threshold: float = 0.2,
) -> DriftReport:
    """Compare every feature in ``baseline`` with ``current``.

    Features missing from ``current`` get score 1.0 (total drift). Features
    present only in ``current`` are ignored (baseline-driven report). Returns
    a deterministic report sorted by feature name.
    """
    results: List[FeatureDriftResult] = []
    for feature in sorted(baseline):
        base = baseline[feature]
        if feature not in current:
            results.append(
                FeatureDriftResult(
                    feature=feature,
                    test="missing",
                    drift_score=1.0,
                    p_value=0.0,
                    threshold=threshold,
                    drifted=True,
                    baseline_size=len(base) if hasattr(base, "__len__") else 0,
                    current_size=0,
                    detail={"reason": "feature absent at inference time"},
                )
            )
            continue
        result = feature_drift(base, current[feature], threshold=threshold)
        try:
            baseline_size = len(base)  # type: ignore[arg-type]
        except TypeError:
            baseline_size = 0
        results.append(
            FeatureDriftResult(
                feature=feature,
                test=result.test,
                drift_score=result.drift_score,
                p_value=result.p_value,
                threshold=threshold,
                drifted=result.drifted,
                baseline_size=baseline_size,
                current_size=result.current_size,
                detail=result.detail,
            )
        )
    return DriftReport(threshold=threshold, results=tuple(results))
