"""
SLA compliance tracker: p50/p95/p99 latency, error budget, recovery time.

Tracks per-module latency samples and error events, computes percentile SLAs,
remaining error budget, and recovery time. State persists under
~/.c-uas-platform/performance/sla/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

DEFAULT_SEED = 42
SCHEMA_VERSION = "1.0.0"

# Default SLA targets.
DEFAULT_LATENCY_P99_S = 1.0
DEFAULT_ERROR_BUDGET = 0.01  # 1% error budget
DEFAULT_RECOVERY_S = 30.0


def _sla_dir() -> Path:
    return Path(
        os.environ.get(
            "C_UAS_PERFORMANCE_DIR",
            str(Path.home() / ".c-uas-platform" / "performance" / "sla"),
        )
    )


def _write_json(name: str, obj: object) -> Path:
    path = _sla_dir() / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(obj, "__dataclass_fields__"):
        payload = asdict(obj)  # type: ignore[call-overload]
    else:
        payload = obj
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return path


def _read_json(name: str) -> object:
    path = _sla_dir() / f"{name}.json"
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def percentile(sorted_values: List[float], percentile_rank: float) -> float:
    if not sorted_values:
        return 0.0
    values = sorted(sorted_values)
    rank = percentile_rank / 100.0
    idx = int(math.ceil(rank * len(values))) - 1
    idx = max(0, min(idx, len(values) - 1))
    return values[idx]


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SLATarget:
    """SLA target for one module."""

    module: str
    latency_p50_s: float
    latency_p95_s: float
    latency_p99_s: float
    error_budget: float  # fraction, e.g. 0.01 = 1%
    recovery_time_s: float


@dataclass(frozen=True)
class SLAResult:
    """Computed SLA compliance for one module."""

    module: str
    sample_count: int
    latency_p50_s: float
    latency_p95_s: float
    latency_p99_s: float
    error_count: int
    error_rate: float
    error_budget_remaining: float
    p99_compliant: bool
    error_budget_compliant: bool
    recovery_time_s: float
    recovery_compliant: bool
    overall_compliant: bool
    assessed_at: str


@dataclass(frozen=True)
class ErrorBudget:
    module: str
    total_requests: int
    failed_requests: int
    error_rate: float
    budget: float
    remaining: float
    exhausted: bool
    updated_at: str


@dataclass(frozen=True)
class RecoveryRecord:
    module: str
    incident_started_at: str
    incident_resolved_at: str
    recovery_time_s: float
    target_recovery_s: float
    compliant: bool


# --------------------------------------------------------------------------- #
# SLARegistry
# --------------------------------------------------------------------------- #


class SLARegistry:
    """Tracks latency samples, errors, and recovery per module."""

    def __init__(
        self,
        state_dir: Optional[str] = None,
        targets: Optional[Dict[str, SLATarget]] = None,
        seed: int = DEFAULT_SEED,
    ) -> None:
        self.state_dir = Path(state_dir) if state_dir is not None else _sla_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.seed = seed
        self.targets: Dict[str, SLATarget] = dict(targets) if targets else {}
        self._latencies: Dict[str, List[float]] = {}
        self._requests: Dict[str, int] = {}
        self._failures: Dict[str, int] = {}
        self._recoveries: List[RecoveryRecord] = []

    def add_target(self, target: SLATarget) -> None:
        self.targets[target.module] = target

    def record_latency(self, module: str, seconds: float) -> None:
        self._latencies.setdefault(module, []).append(float(seconds))
        self._requests[module] = self._requests.get(module, 0) + 1

    def record_request(self, module: str, seconds: float, failed: bool = False) -> None:
        self.record_latency(module, seconds)
        if failed:
            self._failures[module] = self._failures.get(module, 0) + 1

    def record_recovery(
        self,
        module: str,
        started_at: str,
        resolved_at: str,
        recovery_time_s: float,
    ) -> RecoveryRecord:
        target = self.targets.get(module)
        target_recovery = target.recovery_time_s if target else DEFAULT_RECOVERY_S
        compliant = recovery_time_s <= target_recovery
        record = RecoveryRecord(
            module=module,
            incident_started_at=started_at,
            incident_resolved_at=resolved_at,
            recovery_time_s=recovery_time_s,
            target_recovery_s=target_recovery,
            compliant=compliant,
        )
        self._recoveries.append(record)
        _write_json("recovery", asdict(record))
        return record

    # ----- pure computations ---------------------------------------------- #

    def compute_result(self, module: str) -> Optional[SLAResult]:
        latencies = self._latencies.get(module)
        if not latencies:
            return None
        sorted_lat = sorted(latencies)
        count = len(sorted_lat)
        requests = self._requests.get(module, count)
        failures = self._failures.get(module, 0)
        error_rate = failures / requests if requests else 0.0

        target = self.targets.get(module)
        p99_target = target.latency_p99_s if target else DEFAULT_LATENCY_P99_S
        budget = target.error_budget if target else DEFAULT_ERROR_BUDGET
        recovery_target = target.recovery_time_s if target else DEFAULT_RECOVERY_S

        p50 = percentile(sorted_lat, 50.0)
        p95 = percentile(sorted_lat, 95.0)
        p99 = percentile(sorted_lat, 99.0)

        p99_compliant = p99 <= p99_target
        error_budget_compliant = error_rate <= budget
        remaining = max(0.0, budget - error_rate)

        last_recovery: Optional[RecoveryRecord] = None
        for rec in reversed(self._recoveries):
            if rec.module == module:
                last_recovery = rec
                break
        recovery_time = last_recovery.recovery_time_s if last_recovery else 0.0
        recovery_compliant = (
            last_recovery.compliant if last_recovery else recovery_time <= recovery_target
        )

        overall = p99_compliant and error_budget_compliant and recovery_compliant

        result = SLAResult(
            module=module,
            sample_count=count,
            latency_p50_s=round(p50, 6),
            latency_p95_s=round(p95, 6),
            latency_p99_s=round(p99, 6),
            error_count=failures,
            error_rate=round(error_rate, 6),
            error_budget_remaining=round(remaining, 6),
            p99_compliant=p99_compliant,
            error_budget_compliant=error_budget_compliant,
            recovery_time_s=round(recovery_time, 6),
            recovery_compliant=recovery_compliant,
            overall_compliant=overall,
            assessed_at=utc_now_iso(),
        )
        _write_json(f"sla_{module}", result)
        return result

    def error_budget(self, module: str) -> Optional[ErrorBudget]:
        requests = self._requests.get(module, 0)
        failures = self._failures.get(module, 0)
        if requests == 0:
            return None
        error_rate = failures / requests
        target = self.targets.get(module)
        budget = target.error_budget if target else DEFAULT_ERROR_BUDGET
        remaining = max(0.0, budget - error_rate)
        return ErrorBudget(
            module=module,
            total_requests=requests,
            failed_requests=failures,
            error_rate=round(error_rate, 6),
            budget=budget,
            remaining=round(remaining, 6),
            exhausted=remaining <= 0.0,
            updated_at=utc_now_iso(),
        )

    def compliance_status(self, module: str) -> str:
        result = self.compute_result(module)
        if result is None:
            return "no_data"
        return "compliant" if result.overall_compliant else "non_compliant"


# --------------------------------------------------------------------------- #
# Module-level pure functions
# --------------------------------------------------------------------------- #


def compute_percentiles(samples: Sequence[float]) -> Dict[str, float]:
    sorted_samples = sorted(samples)
    return {
        "p50": round(percentile(sorted_samples, 50.0), 6),
        "p95": round(percentile(sorted_samples, 95.0), 6),
        "p99": round(percentile(sorted_samples, 99.0), 6),
    }


def error_budget_remaining(error_rate: float, budget: float) -> float:
    return round(max(0.0, budget - error_rate), 6)


def record_request(
    registry: SLARegistry,
    module: str,
    seconds: float,
    failed: bool = False,
) -> None:
    registry.record_request(module, seconds, failed)


def record_recovery(
    registry: SLARegistry,
    module: str,
    started_at: str,
    resolved_at: str,
    recovery_time_s: float,
) -> RecoveryRecord:
    return registry.record_recovery(module, started_at, resolved_at, recovery_time_s)


def compliance_status(registry: SLARegistry, module: str) -> str:
    """SLA compliance status string for a module (pure helper)."""
    return registry.compliance_status(module)
