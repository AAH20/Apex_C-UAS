"""
Latency/throughput profiler with per-endpoint timing, memory pressure
detection, and bottleneck identification.

All measurements are real (perf_counter / tracemalloc). Functions are pure
with respect to their inputs: the same sequence of recorded samples yields the
same profile. State persists under
~/.c-uas-platform/performance/profiler/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

DEFAULT_SEED = 42
SCHEMA_VERSION = "1.0.0"

# Memory pressure threshold (bytes). A process is flagged when its peak RSS
# exceeds this value during a profiling window.
MEMORY_PRESSURE_BYTES = 256 * 1024 * 1024  # 256 MiB

# Bottleneck severity thresholds (seconds).
LATENCY_HIGH_S = 0.5
LATENCY_CRITICAL_S = 1.0
ERROR_RATE_HIGH = 0.05
ERROR_RATE_CRITICAL = 0.20


def _profiler_dir() -> Path:
    return Path(
        os.environ.get(
            "C_UAS_PERFORMANCE_DIR",
            str(Path.home() / ".c-uas-platform" / "performance" / "profiler"),
        )
    )


def _write_json(name: str, obj: object) -> Path:
    path = _profiler_dir() / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(obj, "__dataclass_fields__"):
        payload = asdict(obj)  # type: ignore[call-overload]
    else:
        payload = obj
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return path


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EndpointTiming:
    """Aggregated timing for a single endpoint."""

    endpoint: str
    count: int
    total_seconds: float
    min_seconds: float
    max_seconds: float
    mean_seconds: float
    p50_seconds: float
    p95_seconds: float
    p99_seconds: float
    error_count: int
    error_rate: float


@dataclass(frozen=True)
class MemorySample:
    """One memory usage sample."""

    timestamp_s: float
    rss_bytes: int


@dataclass(frozen=True)
class Bottleneck:
    """One detected performance bottleneck."""

    endpoint: str
    category: str  # latency, throughput, memory, error
    severity: str  # low, medium, high, critical
    metric: str
    value: float
    threshold: float
    description: str
    recommendation: str


@dataclass(frozen=True)
class ProfileResult:
    """A complete profiling run."""

    schema_version: str
    seed: int
    window_seconds: float
    endpoints: Dict[str, EndpointTiming]
    memory_pressure: bool
    peak_rss_bytes: int
    bottlenecks: List[Bottleneck]
    profiled_at: str


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def percentile(sorted_values: Sequence[float], percentile_rank: float) -> float:
    """Nearest-rank percentile over a sorted sequence of floats.

    Pure function: same input -> same output. Empty input returns 0.0.
    """
    if not sorted_values:
        return 0.0
    values = sorted(sorted_values)
    rank = percentile_rank / 100.0
    idx = int(math_ceil(rank * len(values))) - 1
    idx = max(0, min(idx, len(values) - 1))
    return values[idx]


def math_ceil(x: float) -> int:
    import math

    return math.ceil(x)


def utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Profiler store
# --------------------------------------------------------------------------- #


class ProfileStore:
    """Records per-endpoint samples and memory samples for profiling."""

    def __init__(self, state_dir: Optional[str] = None, seed: int = DEFAULT_SEED) -> None:
        self.state_dir = Path(state_dir) if state_dir is not None else _profiler_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.seed = seed
        self._latencies: Dict[str, List[float]] = {}
        self._errors: Dict[str, int] = {}
        self._counts: Dict[str, int] = {}
        self._memory: List[MemorySample] = []
        self._window_start: Optional[float] = None

    # ----- recording ------------------------------------------------------- #

    def record_latency(self, endpoint: str, seconds: float, errored: bool = False) -> None:
        self._latencies.setdefault(endpoint, []).append(float(seconds))
        self._counts[endpoint] = self._counts.get(endpoint, 0) + 1
        if errored:
            self._errors[endpoint] = self._errors.get(endpoint, 0) + 1

    def record_memory(self, timestamp_s: float, rss_bytes: int) -> None:
        self._memory.append(MemorySample(timestamp_s=timestamp_s, rss_bytes=rss_bytes))

    def set_window_start(self, timestamp_s: float) -> None:
        self._window_start = timestamp_s

    # ----- pure computations ---------------------------------------------- #

    def endpoint_timing(self, endpoint: str) -> Optional[EndpointTiming]:
        latencies = self._latencies.get(endpoint)
        if not latencies:
            return None
        sorted_lat = sorted(latencies)
        count = len(latencies)
        total = sum(latencies)
        error_count = self._errors.get(endpoint, 0)
        error_rate = error_count / count if count else 0.0
        return EndpointTiming(
            endpoint=endpoint,
            count=count,
            total_seconds=total,
            min_seconds=sorted_lat[0],
            max_seconds=sorted_lat[-1],
            mean_seconds=total / count,
            p50_seconds=percentile(sorted_lat, 50.0),
            p95_seconds=percentile(sorted_lat, 95.0),
            p99_seconds=percentile(sorted_lat, 99.0),
            error_count=error_count,
            error_rate=error_rate,
        )

    def all_endpoint_timings(self) -> Dict[str, EndpointTiming]:
        timings: Dict[str, EndpointTiming] = {}
        for ep in sorted(self._latencies):
            t = self.endpoint_timing(ep)
            if t is not None:
                timings[ep] = t
        return timings

    def throughput_rps(self, endpoint: str) -> float:
        """Requests per second for an endpoint over the profiled window."""
        timing = self.endpoint_timing(endpoint)
        if timing is None or timing.total_seconds <= 0:
            return 0.0
        return timing.count / timing.total_seconds

    def detect_memory_pressure(self) -> bool:
        if not self._memory:
            return False
        return any(m.rss_bytes > MEMORY_PRESSURE_BYTES for m in self._memory)

    def peak_rss_bytes(self) -> int:
        if not self._memory:
            return 0
        return max(m.rss_bytes for m in self._memory)


# --------------------------------------------------------------------------- #
# Profiling entry point
# --------------------------------------------------------------------------- #


def profile_endpoint(
    endpoint: str,
    samples: Sequence[float],
    errors: int = 0,
    window_seconds: float = 1.0,
    seed: int = DEFAULT_SEED,
) -> EndpointTiming:
    """Profile a single endpoint from a list of latency samples (pure)."""
    sorted_lat = sorted(samples)
    count = len(sorted_lat)
    total = sum(sorted_lat)
    error_rate = errors / count if count else 0.0
    return EndpointTiming(
        endpoint=endpoint,
        count=count,
        total_seconds=total,
        min_seconds=sorted_lat[0] if sorted_lat else 0.0,
        max_seconds=sorted_lat[-1] if sorted_lat else 0.0,
        mean_seconds=(total / count) if count else 0.0,
        p50_seconds=percentile(sorted_lat, 50.0),
        p95_seconds=percentile(sorted_lat, 95.0),
        p99_seconds=percentile(sorted_lat, 99.0),
        error_count=errors,
        error_rate=error_rate,
    )


def detect_bottlenecks(
    timings: Dict[str, EndpointTiming],
    memory_pressure: bool,
    peak_rss_bytes: int,
) -> List[Bottleneck]:
    """Identify bottlenecks from endpoint timings and memory samples (pure)."""
    bottlenecks: List[Bottleneck] = []

    for endpoint in sorted(timings):
        t = timings[endpoint]

        if t.p99_seconds > LATENCY_CRITICAL_S:
            bottlenecks.append(
                Bottleneck(
                    endpoint=endpoint,
                    category="latency",
                    severity="critical",
                    metric="p99_seconds",
                    value=t.p99_seconds,
                    threshold=LATENCY_CRITICAL_S,
                    description=(
                        f"{endpoint} p99 latency {t.p99_seconds:.3f}s exceeds "
                        f"{LATENCY_CRITICAL_S}s critical threshold"
                    ),
                    recommendation=(
                        f"Profile {endpoint} slow path; add caching or parallelize downstream calls"
                    ),
                )
            )
        elif t.p95_seconds > LATENCY_HIGH_S:
            bottlenecks.append(
                Bottleneck(
                    endpoint=endpoint,
                    category="latency",
                    severity="high",
                    metric="p95_seconds",
                    value=t.p95_seconds,
                    threshold=LATENCY_HIGH_S,
                    description=(
                        f"{endpoint} p95 latency {t.p95_seconds:.3f}s exceeds "
                        f"{LATENCY_HIGH_S}s threshold"
                    ),
                    recommendation=(
                        f"Optimize {endpoint} request handling; review per-stage latency breakdown"
                    ),
                )
            )

        if t.error_rate > ERROR_RATE_CRITICAL:
            bottlenecks.append(
                Bottleneck(
                    endpoint=endpoint,
                    category="error",
                    severity="critical",
                    metric="error_rate",
                    value=t.error_rate,
                    threshold=ERROR_RATE_CRITICAL,
                    description=(
                        f"{endpoint} error rate {t.error_rate:.1%} exceeds "
                        f"{ERROR_RATE_CRITICAL:.0%} critical threshold"
                    ),
                    recommendation=(
                        f"Investigate {endpoint} failures; add retries and circuit breaker"
                    ),
                )
            )
        elif t.error_rate > ERROR_RATE_HIGH:
            bottlenecks.append(
                Bottleneck(
                    endpoint=endpoint,
                    category="error",
                    severity="high",
                    metric="error_rate",
                    value=t.error_rate,
                    threshold=ERROR_RATE_HIGH,
                    description=(
                        f"{endpoint} error rate {t.error_rate:.1%} exceeds "
                        f"{ERROR_RATE_HIGH:.0%} threshold"
                    ),
                    recommendation=(f"Review {endpoint} error logs; tighten input validation"),
                )
            )

    if memory_pressure:
        bottlenecks.append(
            Bottleneck(
                endpoint="process",
                category="memory",
                severity="critical",
                metric="peak_rss_bytes",
                value=float(peak_rss_bytes),
                threshold=float(MEMORY_PRESSURE_BYTES),
                description=(
                    f"Peak RSS {peak_rss_bytes / (1024 * 1024):.1f} MiB exceeds "
                    f"{MEMORY_PRESSURE_BYTES / (1024 * 1024):.0f} MiB pressure "
                    "threshold"
                ),
                recommendation=(
                    "Reduce in-memory track buffers, enable streaming responses, "
                    "or raise instance memory limit"
                ),
            )
        )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    bottlenecks.sort(
        key=lambda b: (
            severity_order.get(b.severity, 9),
            b.endpoint,
            b.category,
        )
    )
    return bottlenecks


def detect_memory_pressure(store: ProfileStore) -> bool:
    """Return True when any recorded memory sample exceeds the pressure threshold (pure helper)."""
    return store.detect_memory_pressure()


def throughput_rps(endpoint: str, store: ProfileStore) -> float:
    """Requests per second for an endpoint over the profiled window (pure helper)."""
    return store.throughput_rps(endpoint)


def run_profile(
    store: ProfileStore,
    seed: int = DEFAULT_SEED,
) -> ProfileResult:
    """Build a ProfileResult from a populated ProfileStore and persist it."""
    window_seconds = 0.0
    if store._window_start is not None and store._memory:
        import time

        window_seconds = time.perf_counter() - store._window_start

    timings = store.all_endpoint_timings()
    memory_pressure = store.detect_memory_pressure()
    peak_rss = store.peak_rss_bytes()
    bottlenecks = detect_bottlenecks(timings, memory_pressure, peak_rss)

    result = ProfileResult(
        schema_version=SCHEMA_VERSION,
        seed=seed,
        window_seconds=round(window_seconds, 6),
        endpoints=timings,
        memory_pressure=memory_pressure,
        peak_rss_bytes=peak_rss,
        bottlenecks=bottlenecks,
        profiled_at=utc_now_iso(),
    )
    _write_json("profile", result)
    return result
