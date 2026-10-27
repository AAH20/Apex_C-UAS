"""Readiness aggregator: go/no-go decision from domain checks.

Runs all domain checks, computes the overall readiness score as the
weighted average of domain scores (weights from DOMAIN_WEIGHTS, normalized
to sum to 1.0), and decides go/no-go:

  GO   if every critical check passes AND overall score >= 85.0
  NO-GO otherwise

Produces a frozen ReadinessReport suitable for rendering and persistence.
Deterministic given the same checks and generated_at timestamp.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .checks import (
    DOMAIN_WEIGHTS,
    OVERALL_GO_THRESHOLD,
    DomainResult,
)

SCHEMA_VERSION = "1.0.0"
GO = "GO"
NO_GO = "NO-GO"


@dataclass(frozen=True)
class ReadinessReport:
    """Deterministic production readiness report."""

    schema_version: str
    generated_at: str  # caller-provided timestamp (ISO-8601 UTC)
    overall_score: float  # 0-100 weighted average
    go_no_go: str  # "GO" | "NO-GO"
    decision_reason: str
    checks: Tuple[DomainResult, ...]  # per-domain results, fixed domain order
    remediation: Tuple[str, ...]  # deduplicated remediation items


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def overall_score(checks: Tuple[DomainResult, ...]) -> float:
    """Weighted average of domain scores using DOMAIN_WEIGHTS.

    Weights are normalized to sum to 1.0; domains without a weight default
    to 1.0. Identical inputs always produce the same score.
    """
    total_weight = 0.0
    weighted_sum = 0.0
    for check in checks:
        weight = float(DOMAIN_WEIGHTS.get(check.domain, 1.0))
        total_weight += weight
        weighted_sum += weight * float(check.score)
    if total_weight <= 0.0:
        return 0.0
    return round(weighted_sum / total_weight, 2)


def failed_critical(checks: Tuple[DomainResult, ...]) -> Tuple[DomainResult, ...]:
    """Critical checks that failed, in domain order."""
    return tuple(check for check in checks if check.critical and not check.passed)


def decision(
    checks: Tuple[DomainResult, ...],
    score: Optional[float] = None,
    overall_threshold: float = OVERALL_GO_THRESHOLD,
) -> Tuple[str, str]:
    """Pure go/no-go decision: (go_no_go, reason)."""
    score = float(overall_score(checks)) if score is None else float(score)
    failed = failed_critical(checks)
    if failed:
        return (
            NO_GO,
            "critical check(s) failed: " + ", ".join(check.domain for check in failed),
        )
    if score < overall_threshold:
        return (
            NO_GO,
            f"overall readiness {score:.1f} below threshold {overall_threshold:.1f}",
        )
    return GO, "all critical checks pass and overall readiness >= 85.0"


def _dedupe(items: Tuple[str, ...]) -> Tuple[str, ...]:
    seen: set = set()
    deduped: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return tuple(deduped)


def aggregate(checks: Tuple[DomainResult, ...], generated_at: str) -> ReadinessReport:
    """Aggregate domain checks into a ReadinessReport (pure)."""
    score = overall_score(checks)
    go_no_go, reason = decision(checks, score)
    remediation: List[str] = []
    for check in checks:
        if not check.passed:
            remediation.extend(list(check.remediation))
    return ReadinessReport(
        schema_version=SCHEMA_VERSION,
        generated_at=generated_at,
        overall_score=score,
        go_no_go=go_no_go,
        decision_reason=reason,
        checks=tuple(checks),
        remediation=_dedupe(tuple(remediation)),
    )


def run_readiness_check(generated_at: Optional[str] = None) -> ReadinessReport:
    """Run all domain checks and aggregate into a ReadinessReport."""
    from .checks import all_checks

    if generated_at is None:
        generated_at = _utc_now_iso()
    return aggregate(tuple(all_checks()), generated_at)
