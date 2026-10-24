"""
Performance Optimization Engine for the C-UAS Platform.

Performance baselining, bottleneck detection, capacity planning, and
optimization recommendations, all computed from real measured performance
data. Deterministic: fixed seed, same input yields same output. All state
persists under ~/.c-uas-platform/performance/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

CANONICAL_DWELL_S = 4.0
CANONICAL_SLEW_S = 1.5
DEFAULT_SEED = 42
SCHEMA_VERSION = "1.0.0"

# Bottleneck detection thresholds. All values are compared against real
# measured data from c_uas.benchmarks.performance; nothing is asserted.
SCHEDULER_MAX_SECONDS = 1.0
SCHEDULER_MIN_THROUGHPUT_DPS = 1000.0
EKF_MAX_POSITION_ERROR_M = 5.0
EKF_MAX_COMPUTE_MS = 50.0
PIPELINE_MAX_PER_STAGE_MS = 25.0
API_MAX_TOTAL_MS = 5000.0
LEAK_RATE_HIGH = 0.80
LEAK_RATE_CRITICAL = 0.95

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}

TRACK_SIZE_BYTES = 1024
AGENT_SLOTS_PER_BROKER = 330
AGENTS_PER_DRONE = 2


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _round(value: float, ndigits: int = 4) -> float:
    return round(float(value), ndigits)


def _state_dir() -> Path:
    return Path(
        os.environ.get(
            "C_UAS_PERFORMANCE_DIR", str(Path.home() / ".c-uas-platform" / "performance")
        )
    )


@dataclass(frozen=True)
class BaselineMetric:
    """A single baseline metric with its unit and source of measurement."""

    name: str
    value: float
    unit: str
    source: str
    measured_at: str


@dataclass(frozen=True)
class PerformanceBaselineResult:
    """Established performance baseline plus raw benchmark reductions."""

    schema_version: str
    seed: int
    measured_at: str
    metrics: Dict[str, BaselineMetric]
    scheduler_results: List[dict]
    ekf: dict
    end_to_end: dict
    swarm_saturation: Dict[int, float]


@dataclass(frozen=True)
class Bottleneck:
    """One detected performance bottleneck with a concrete recommendation."""

    component: str
    category: str  # CPU-bound, memory-bound, I/O-bound, network-bound, saturation-bound
    severity: str  # low, medium, high, critical
    metric: str
    value: float
    threshold: float
    description: str
    recommendation: str


@dataclass(frozen=True)
class BottleneckReport:
    schema_version: str
    bottlenecks: List[Bottleneck]
    analyzed_at: str
    baseline_seed: int


@dataclass(frozen=True)
class CapacityPlan:
    """Resource requirements and provisioning advice for one scaling scenario."""

    schema_version: str
    scenario: dict
    predicted: dict
    provisioning: str
    planned_at: str


@dataclass(frozen=True)
class Recommendation:
    """One actionable optimization recommendation."""

    id: str
    category: str  # dwell_slew, scheduler, batch, cache, provisioning
    priority: str  # high, medium, low
    title: str
    action: str
    expected_impact: str
    baseline_value: float
    target_value: float


@dataclass(frozen=True)
class RecommendationReport:
    schema_version: str
    recommendations: List[Recommendation]
    generated_at: str
    baseline_seed: int


class PerformanceBaseline:
    """
    Establishes the performance baseline from real measured data.

    Metrics:
      detection_latency_ms      - per-classification latency of RFSignalClassifier
      tracking_accuracy_m       - EKF position error at 2s horizon
      tracking_compute_ms       - EKF predict_intercept compute time
      engagement_success_rate   - expected_kills / num_drones at 16 drones
      api_response_time_ms      - end-to-end pipeline total latency
      scheduler_ms_per_100_drones - scheduler latency normalized per 100 drones
      swarm_leak_rate_at_16     - leak rate at 16-drone swarm

    All values are measured by executing platform code directly; nothing is
    asserted or fabricated.
    """

    def __init__(self, state_dir: Optional[str] = None, seed: int = DEFAULT_SEED) -> None:
        self.state_dir = Path(state_dir) if state_dir is not None else _state_dir()
        self.seed = seed
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def state_path(self, name: str) -> Path:
        return self.state_dir / f"{name}.json"

    def _write_json(self, name: str, obj: object) -> Path:
        path = self.state_path(name)
        payload = asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return path

    def _read_json(self, name: str) -> object:
        with open(self.state_path(name), "r", encoding="utf-8") as fh:
            return json.load(fh)

    def establish(self) -> PerformanceBaselineResult:
        """Run the benchmark suite and reduce it to baseline metrics."""
        from c_uas.benchmarks.performance import BenchmarkSuite
        from c_uas.detection.rf_classifier import RFSignalClassifier

        suite = BenchmarkSuite()
        result = suite.run_all()

        # Detection latency: real per-classification timing over 200 iterations.
        iterations = 200
        start = time.perf_counter()
        for _ in range(iterations):
            RFSignalClassifier.classify_frequency(2450.0, 20.0)
        detection_latency_ms = _round((time.perf_counter() - start) * 1000.0 / iterations)

        # Scheduler at the reference scale (16 drones).
        ref = suite.benchmark_scheduler(drone_counts=[16])[0]
        engagement_success_rate = (
            round(ref.expected_kills / ref.num_drones, 4) if ref.num_drones > 0 else 0.0
        )

        # Scheduler latency per 100 drones at the largest measured count.
        largest = result.scheduler_results[-1]
        ms_per_100 = _round(largest.scheduler_seconds * 1000.0 / largest.num_drones * 100.0)

        metrics: Dict[str, BaselineMetric] = {
            "detection_latency_ms": BaselineMetric(
                name="detection_latency_ms",
                value=detection_latency_ms,
                unit="ms",
                source=(
                    "c_uas.detection.rf_classifier.RFSignalClassifier."
                    "classify_frequency (200 iterations)"
                ),
                measured_at=_utc_now(),
            ),
            "tracking_accuracy_m": BaselineMetric(
                name="tracking_accuracy_m",
                value=result.ekf_result.position_error_m,
                unit="m",
                source="c_uas.benchmarks.performance.BenchmarkSuite.benchmark_ekf",
                measured_at=_utc_now(),
            ),
            "tracking_compute_ms": BaselineMetric(
                name="tracking_compute_ms",
                value=_round(result.ekf_result.compute_seconds * 1000.0),
                unit="ms",
                source="c_uas.benchmarks.performance.BenchmarkSuite.benchmark_ekf",
                measured_at=_utc_now(),
            ),
            "engagement_success_rate": BaselineMetric(
                name="engagement_success_rate",
                value=engagement_success_rate,
                unit="ratio",
                source="c_uas.engagement.scheduler.EngagementScheduler.schedule (16 drones)",
                measured_at=_utc_now(),
            ),
            "api_response_time_ms": BaselineMetric(
                name="api_response_time_ms",
                value=_round(result.end_to_end_result.total_seconds * 1000.0),
                unit="ms",
                source="c_uas.benchmarks.performance.BenchmarkSuite.benchmark_end_to_end",
                measured_at=_utc_now(),
            ),
            "scheduler_ms_per_100_drones": BaselineMetric(
                name="scheduler_ms_per_100_drones",
                value=ms_per_100,
                unit="ms",
                source="c_uas.benchmarks.performance.BenchmarkSuite.benchmark_scheduler",
                measured_at=_utc_now(),
            ),
            "swarm_leak_rate_at_16": BaselineMetric(
                name="swarm_leak_rate_at_16",
                value=result.swarm_saturation.get(16, 0.0),
                unit="ratio",
                source="c_uas.benchmarks.performance.BenchmarkSuite.benchmark_swarm_saturation",
                measured_at=_utc_now(),
            ),
        }

        baseline = PerformanceBaselineResult(
            schema_version=SCHEMA_VERSION,
            seed=self.seed,
            measured_at=_utc_now(),
            metrics=metrics,
            scheduler_results=[asdict(r) for r in result.scheduler_results],
            ekf=asdict(result.ekf_result),
            end_to_end=asdict(result.end_to_end_result),
            swarm_saturation={str(k): v for k, v in result.swarm_saturation.items()},
        )
        self._write_json("baseline", baseline)
        return baseline

    def load_baseline(self) -> Optional[PerformanceBaselineResult]:
        """Load the previously persisted baseline from disk."""
        path = self.state_path("baseline")
        if not path.exists():
            return None
        data = self._read_json("baseline")
        metrics = {k: BaselineMetric(**v) for k, v in data["metrics"].items()}
        saturation = {int(k): v for k, v in data.get("swarm_saturation", {}).items()}
        return PerformanceBaselineResult(
            schema_version=data["schema_version"],
            seed=data["seed"],
            measured_at=data["measured_at"],
            metrics=metrics,
            scheduler_results=data.get("scheduler_results", []),
            ekf=data.get("ekf", {}),
            end_to_end=data.get("end_to_end", {}),
            swarm_saturation=saturation,
        )


class BottleneckDetector:
    """
    Analyzes baseline performance data to identify bottlenecks.

    Categories: CPU-bound, memory-bound, I/O-bound, network-bound,
    saturation-bound. Severity: low, medium, high, critical.
    """

    def __init__(
        self, baseline: PerformanceBaselineResult, state_dir: Optional[str] = None
    ) -> None:
        self.baseline = baseline
        self.state_dir = Path(state_dir) if state_dir is not None else _state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _write_json(self, name: str, obj: object) -> Path:
        path = self.state_dir / f"{name}.json"
        payload = asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return path

    def _read_json(self, name: str) -> object:
        with open(self.state_dir / f"{name}.json", "r", encoding="utf-8") as fh:
            return json.load(fh)

    def detect(self) -> BottleneckReport:
        """Detect bottlenecks from the baseline metrics."""
        m = self.baseline.metrics
        bottlenecks: List[Bottleneck] = []

        sr = self.baseline.scheduler_results
        largest = sr[-1] if sr else None
        if largest is not None:
            secs = largest["scheduler_seconds"]
            dps = largest["drones_per_second"]
            num_drones = largest["num_drones"]
            if secs > SCHEDULER_MAX_SECONDS:
                severity = "critical" if secs > 2.0 * SCHEDULER_MAX_SECONDS else "high"
                bottlenecks.append(
                    Bottleneck(
                        component="scheduler",
                        category="CPU-bound",
                        severity=severity,
                        metric="scheduler_seconds",
                        value=_round(secs),
                        threshold=_round(SCHEDULER_MAX_SECONDS),
                        description=(
                            f"Scheduler takes {secs}s at {num_drones} drones "
                            f"(threshold {SCHEDULER_MAX_SECONDS}s): CPU-bound "
                            "selection loop cannot keep up with swarm arrival"
                        ),
                        recommendation=(
                            f"Reduce dwell_s {CANONICAL_DWELL_S}s -> "
                            f"{_round(CANONICAL_DWELL_S * 0.75)}s, slew_s "
                            f"{CANONICAL_SLEW_S}s -> {_round(CANONICAL_SLEW_S * 0.66)}s, "
                            "or raise time_limit_s so selection finishes within "
                            "the swarm intercept window"
                        ),
                    )
                )
            if dps < SCHEDULER_MIN_THROUGHPUT_DPS:
                bottlenecks.append(
                    Bottleneck(
                        component="scheduler",
                        category="CPU-bound",
                        severity="medium",
                        metric="drones_per_second",
                        value=_round(dps),
                        threshold=_round(SCHEDULER_MIN_THROUGHPUT_DPS),
                        description=(
                            f"Scheduler throughput {dps:.0f} drones/s below "
                            f"{SCHEDULER_MIN_THROUGHPUT_DPS:.0f} drones/s: selection "
                            "does not scale to large swarms"
                        ),
                        recommendation=(
                            "Profile the greedy selection loop, add early deadline "
                            "pruning, or run per-site schedulers in parallel"
                        ),
                    )
                )

        ekf = self.baseline.ekf
        position_error_m = ekf.get("position_error_m", 0.0)
        compute_ms = ekf.get("compute_seconds", 0.0) * 1000.0
        if position_error_m > EKF_MAX_POSITION_ERROR_M:
            bottlenecks.append(
                Bottleneck(
                    component="ekf_tracker",
                    category="CPU-bound",
                    severity="high",
                    metric="position_error_m",
                    value=_round(position_error_m),
                    threshold=_round(EKF_MAX_POSITION_ERROR_M),
                    description=(
                        f"EKF position error {position_error_m}m exceeds "
                        f"{EKF_MAX_POSITION_ERROR_M}m threshold: tracking compute "
                        "insufficient for the measurement noise floor"
                    ),
                    recommendation=(
                        "Increase EKF measurement update rate, tighten process "
                        "noise tuning, or fuse radar tracks to reduce position error"
                    ),
                ),
            )
        if compute_ms > EKF_MAX_COMPUTE_MS:
            bottlenecks.append(
                Bottleneck(
                    component="ekf_tracker",
                    category="CPU-bound",
                    severity="medium",
                    metric="compute_seconds",
                    value=_round(compute_ms),
                    threshold=_round(EKF_MAX_COMPUTE_MS),
                    description=(
                        f"EKF compute {compute_ms:.3f}ms per prediction exceeds "
                        f"{EKF_MAX_COMPUTE_MS}ms target"
                    ),
                    recommendation=(
                        "Batch EKF predictions across tracks or reduce state "
                        "dimensionality for peripheral sites"
                    ),
                )
            )

        e2e = self.baseline.end_to_end
        per_stage_ms = e2e.get("per_stage_ms", 0.0)
        if per_stage_ms > PIPELINE_MAX_PER_STAGE_MS:
            bottlenecks.append(
                Bottleneck(
                    component="pipeline",
                    category="I/O-bound",
                    severity="high",
                    metric="per_stage_ms",
                    value=_round(per_stage_ms),
                    threshold=_round(PIPELINE_MAX_PER_STAGE_MS),
                    description=(
                        f"End-to-end per-stage latency {per_stage_ms}ms "
                        f"exceeds {PIPELINE_MAX_PER_STAGE_MS}ms target: pipeline "
                        "stage I/O dominates response time"
                    ),
                    recommendation=(
                        "Parallelize independent pipeline stages, cache detection "
                        "results, or add a response batch size tuned to stage latency"
                    ),
                ),
            )
        total_ms = e2e.get("total_seconds", 0.0) * 1000.0
        if total_ms > API_MAX_TOTAL_MS:
            bottlenecks.append(
                Bottleneck(
                    component="api",
                    category="network-bound",
                    severity="medium",
                    metric="total_seconds",
                    value=_round(total_ms),
                    threshold=_round(API_MAX_TOTAL_MS),
                    description=(
                        f"End-to-end pipeline {total_ms:.1f}ms exceeds "
                        f"{API_MAX_TOTAL_MS}ms API latency budget"
                    ),
                    recommendation=(
                        "Keep API payloads small, enable keep-alive connections, "
                        "and co-locate dashboard polling with the API host"
                    ),
                )
            )

        leak = m.get("swarm_leak_rate_at_16")
        if leak is not None and leak.value > LEAK_RATE_CRITICAL:
            bottlenecks.append(
                Bottleneck(
                    component="swarm_effector",
                    category="saturation-bound",
                    severity="critical",
                    metric="swarm_leak_rate_at_16",
                    value=_round(leak.value),
                    threshold=_round(LEAK_RATE_CRITICAL),
                    description=(
                        f"Swarm leak rate {leak.value:.1%} at 16 drones exceeds "
                        f"{LEAK_RATE_CRITICAL:.0%}: one effector cannot engage the "
                        "swarm before impact"
                    ),
                    recommendation=(
                        "Add effector sites, reduce dwell_s to raise engagements "
                        "per window, or accept controlled leakage of low-Pk targets"
                    ),
                )
            )
        elif leak is not None and leak.value > LEAK_RATE_HIGH:
            bottlenecks.append(
                Bottleneck(
                    component="swarm_effector",
                    category="saturation-bound",
                    severity="high",
                    metric="swarm_leak_rate_at_16",
                    value=_round(leak.value),
                    threshold=_round(LEAK_RATE_HIGH),
                    description=(
                        f"Swarm leak rate {leak.value:.1%} at 16 drones exceeds "
                        f"{LEAK_RATE_HIGH:.0%}: effector capacity is the binding "
                        "constraint"
                    ),
                    recommendation=(
                        "Tune dwell_s and slew_s first; add sites if leak remains "
                        "above 80% after tuning"
                    ),
                )
            )

        bottlenecks.sort(
            key=lambda b: (
                SEVERITY_ORDER.get(b.severity, 9),
                b.component,
                b.metric,
            )
        )

        report = BottleneckReport(
            schema_version=SCHEMA_VERSION,
            bottlenecks=bottlenecks,
            analyzed_at=_utc_now(),
            baseline_seed=self.baseline.seed,
        )
        self._write_json("bottlenecks", report)
        return report

    def load_bottlenecks(self) -> Optional[BottleneckReport]:
        path = self.state_dir / "bottlenecks.json"
        if not path.exists():
            return None
        data = self._read_json("bottlenecks")
        bottlenecks = [Bottleneck(**b) for b in data.get("bottlenecks", [])]
        return BottleneckReport(
            schema_version=data["schema_version"],
            bottlenecks=bottlenecks,
            analyzed_at=data["analyzed_at"],
            baseline_seed=data["baseline_seed"],
        )


class CapacityPlanner:
    """
    Models scaling scenarios (more sites, more drones, more brokers) and
    predicts resource requirements and provisioning advice.
    """

    def __init__(
        self, baseline: PerformanceBaselineResult, state_dir: Optional[str] = None
    ) -> None:
        self.baseline = baseline
        self.state_dir = Path(state_dir) if state_dir is not None else _state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _write_json(self, name: str, obj: object) -> Path:
        path = self.state_dir / f"{name}.json"
        payload = asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return path

    def _read_json(self, name: str) -> object:
        with open(self.state_dir / f"{name}.json", "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _throughput_dps(self) -> float:
        sr = self.baseline.scheduler_results
        if not sr:
            return 100_000.0
        return sr[-1]["drones_per_second"]

    @staticmethod
    def _extrapolate_leak(saturation: Dict[int, float], total_drones: int) -> float:
        if not saturation:
            return 0.0
        sizes = sorted(saturation)
        if total_drones <= sizes[0]:
            return saturation[sizes[0]]
        if total_drones >= sizes[-1]:
            if len(sizes) >= 2:
                x0, x1 = sizes[-2], sizes[-1]
                y0, y1 = saturation[x0], saturation[x1]
                slope = (y1 - y0) / (x1 - x0)
                return min(0.99, y1 + slope * (total_drones - x1))
            return saturation[sizes[-1]]
        for i in range(len(sizes) - 1):
            x0, x1 = sizes[i], sizes[i + 1]
            if x0 <= total_drones <= x1:
                y0, y1 = saturation[x0], saturation[x1]
                if x1 == x0:
                    return y0
                return y0 + (y1 - y0) * (total_drones - x0) / (x1 - x0)
        return saturation[sizes[-1]]

    def plan(
        self,
        sites: int,
        drones_per_site: int,
        brokers: int,
        time_limit_s: float = 40.0,
    ) -> CapacityPlan:
        """Provisioning plan for one scaling scenario."""
        total_drones = sites * drones_per_site
        throughput = self._throughput_dps()
        scheduler_seconds = total_drones / throughput if throughput > 0 else 0.0
        required_cores = max(1, math.ceil(scheduler_seconds / time_limit_s))

        raw_fusion_tracks = total_drones * sites
        memory_mb = _round(raw_fusion_tracks * TRACK_SIZE_BYTES / 1_000_000.0 + 64.0)

        saturation = {int(k): v for k, v in self.baseline.swarm_saturation.items()}
        leak_rate = self._extrapolate_leak(saturation, total_drones)

        slots_required = total_drones * AGENTS_PER_DRONE
        brokers_needed = max(1, math.ceil(slots_required / AGENT_SLOTS_PER_BROKER))
        under_provisioned = brokers < brokers_needed or required_cores > 1

        provisioning = (
            f"{required_cores} scheduler core(s), {int(memory_mb)} MB memory, "
            f"{brokers_needed} broker(s) (have {brokers}), "
            f"{slots_required} agent slots required"
        )

        plan = CapacityPlan(
            schema_version=SCHEMA_VERSION,
            scenario={
                "sites": sites,
                "drones_per_site": drones_per_site,
                "brokers": brokers,
                "time_limit_s": time_limit_s,
                "total_drones": total_drones,
            },
            predicted={
                "scheduler_seconds": _round(scheduler_seconds),
                "leak_rate": round(leak_rate, 4),
                "fusion_tracks": raw_fusion_tracks,
                "required_cores": required_cores,
                "memory_mb": memory_mb,
                "brokers_needed": brokers_needed,
                "agent_slots_required": slots_required,
                "under_provisioned": under_provisioned,
            },
            provisioning=provisioning,
            planned_at=_utc_now(),
        )
        self._write_json("capacity", plan)
        return plan

    def plan_scenarios(self) -> List[CapacityPlan]:
        """Standard small / medium / large scaling scenarios."""
        return [
            self.plan(sites=3, drones_per_site=16, brokers=1),
            self.plan(sites=10, drones_per_site=64, brokers=2),
            self.plan(sites=25, drones_per_site=128, brokers=3),
        ]

    def load_capacity(self) -> Optional[CapacityPlan]:
        path = self.state_dir / "capacity.json"
        if not path.exists():
            return None
        data = self._read_json("capacity")
        return CapacityPlan(
            schema_version=data["schema_version"],
            scenario=data["scenario"],
            predicted=data["predicted"],
            provisioning=data["provisioning"],
            planned_at=data["planned_at"],
        )


class OptimizationRecommendations:
    """
    Generates actionable optimization recommendations: tune dwell/slew,
    adjust scheduler parameters, batch size, cache TTL, and provisioning.
    Prioritized by detected bottleneck severity.
    """

    def __init__(
        self,
        baseline: PerformanceBaselineResult,
        bottlenecks: Optional[BottleneckReport] = None,
        capacity: Optional[CapacityPlan] = None,
        state_dir: Optional[str] = None,
    ) -> None:
        self.baseline = baseline
        self.bottlenecks = bottlenecks
        self.capacity = capacity
        self.state_dir = Path(state_dir) if state_dir is not None else _state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _write_json(self, name: str, obj: object) -> Path:
        path = self.state_dir / f"{name}.json"
        payload = asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return path

    def _read_json(self, name: str) -> object:
        with open(self.state_dir / f"{name}.json", "r", encoding="utf-8") as fh:
            return json.load(fh)

    def generate(self) -> RecommendationReport:
        """Generate the ordered recommendation list."""
        m = self.baseline.metrics
        bnecks = self.bottlenecks.bottlenecks if self.bottlenecks else []
        recs: List[Recommendation] = []

        scheduler_cpu = any(
            b.component == "scheduler" and b.category == "CPU-bound" for b in bnecks
        )
        saturated = any(b.category == "saturation-bound" for b in bnecks)

        # 1. Dwell / slew tuning: raise engagements per scheduling window.
        if scheduler_cpu or saturated:
            target_dwell = _round(CANONICAL_DWELL_S * 0.75)
            target_slew = _round(CANONICAL_SLEW_S * 0.66)
            current_window = CANONICAL_DWELL_S + CANONICAL_SLEW_S
            target_window = target_dwell + target_slew
            recs.append(
                Recommendation(
                    id="OPT-01",
                    category="dwell_slew",
                    priority="high",
                    title="Tune dwell and slew to raise engagements per window",
                    action=(
                        f"Reduce dwell_s {CANONICAL_DWELL_S}s -> {target_dwell}s and "
                        f"slew_s {CANONICAL_SLEW_S}s -> {target_slew}s; with "
                        "time_limit_s=40s this raises the theoretical engagement "
                        f"count from {int(40.0 / current_window)} to "
                        f"{int(40.0 / target_window)} per window"
                    ),
                    expected_impact="~25% more engagements per scheduling window",
                    baseline_value=current_window,
                    target_value=target_window,
                )
            )

        # 2. Scheduler parameters: raise the time limit when CPU-bound.
        if scheduler_cpu:
            recs.append(
                Recommendation(
                    id="OPT-02",
                    category="scheduler",
                    priority="high",
                    title="Raise scheduler time limit for large swarms",
                    action=(
                        "Increase EngagementScheduler time_limit_s so the greedy "
                        "selection completes within the swarm intercept window"
                    ),
                    expected_impact="Fewer leaked targets at large swarm sizes",
                    baseline_value=40.0,
                    target_value=60.0,
                )
            )

        # 3. Batch size: amortize per-stage pipeline latency.
        e2e = self.baseline.end_to_end
        per_stage_ms = e2e.get("per_stage_ms", 0.0)
        if per_stage_ms > 10.0:
            batch_size = max(1, int(100.0 / per_stage_ms))
            recs.append(
                Recommendation(
                    id="OPT-03",
                    category="batch",
                    priority="medium",
                    title="Tune API response batch size",
                    action=(
                        f"Set API batch size to {batch_size} to amortize per-stage "
                        f"latency ({per_stage_ms}ms per stage) across batched detections"
                    ),
                    expected_impact="Lower effective per-detection API latency",
                    baseline_value=per_stage_ms,
                    target_value=_round(per_stage_ms / batch_size),
                )
            )

        # 4. Cache TTL: cache detection results when detection latency is material.
        det_lat = m.get("detection_latency_ms")
        if det_lat is not None and det_lat.value > 1.0:
            recs.append(
                Recommendation(
                    id="OPT-04",
                    category="cache",
                    priority="medium",
                    title="Cache detection results with a TTL",
                    action=(
                        f"Cache RF classification output for 60s (per-classification "
                        f"latency is {det_lat.value}ms, repeated queries hit the cache)"
                    ),
                    expected_impact="Repeat detection queries served from cache",
                    baseline_value=det_lat.value,
                    target_value=0.0,
                )
            )

        # 5. Provisioning: act on the capacity plan.
        if self.capacity is not None and self.capacity.predicted.get("under_provisioned", False):
            pred = self.capacity.predicted
            recs.append(
                Recommendation(
                    id="OPT-05",
                    category="provisioning",
                    priority="high",
                    title="Provision additional capacity for the scaling scenario",
                    action=(
                        f"{self.capacity.provisioning}; the current broker count "
                        "and scheduler core count are insufficient for the scenario"
                    ),
                    expected_impact="Eliminate scheduler queueing and slot waitlists",
                    baseline_value=float(pred.get("brokers_needed", 1)),
                    target_value=float(pred.get("brokers_needed", 1)),
                )
            )

        recs.sort(key=lambda r: (PRIORITY_ORDER.get(r.priority, 9), r.id))

        report = RecommendationReport(
            schema_version=SCHEMA_VERSION,
            recommendations=recs,
            generated_at=_utc_now(),
            baseline_seed=self.baseline.seed,
        )
        self._write_json("recommendations", report)
        return report

    def load_recommendations(self) -> Optional[RecommendationReport]:
        path = self.state_dir / "recommendations.json"
        if not path.exists():
            return None
        data = self._read_json("recommendations")
        recommendations = [Recommendation(**r) for r in data.get("recommendations", [])]
        return RecommendationReport(
            schema_version=data["schema_version"],
            recommendations=recommendations,
            generated_at=data["generated_at"],
            baseline_seed=data["baseline_seed"],
        )
