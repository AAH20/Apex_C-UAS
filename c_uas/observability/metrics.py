"""
Prometheus-style metrics registry: Counter, Gauge, Histogram, Summary.

Metric families are identified by name + type. Each sample carries a label
set (frozen dict of str -> str) and a timestamp. Collection is deterministic:
series are emitted sorted by name, then label set, then timestamp.

State persists under ~/.c-uas-platform/observability/metrics/ (outside the repo).

License: AGPL-3.0.
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

DEFAULT_SEED = 42
SCHEMA_VERSION = "1.0.0"

OBS_DIR = Path(
    os.environ.get(
        "C_UAS_OBSERVABILITY_DIR",
        str(Path.home() / ".c-uas-platform" / "observability"),
    )
)
METRICS_DIR = OBS_DIR / "metrics"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def monotonic_now() -> float:
    return time.time()


def percentile(sorted_values: Sequence[float], percentile_rank: float) -> float:
    """Nearest-rank percentile (deterministic). Returns 0.0 for empty input."""
    if not sorted_values:
        return 0.0
    values = sorted(sorted_values)
    rank = percentile_rank / 100.0
    idx = int(math.ceil(rank * len(values))) - 1
    idx = max(0, min(idx, len(values) - 1))
    return values[idx]


def _labels_key(labels: Optional[Dict[str, str]]) -> Tuple[Tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted(labels.items()))


def _write_json(path: Path, obj: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj  # type: ignore[call-overload]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return path


def _read_json(path: Path) -> object:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Metric types
# --------------------------------------------------------------------------- #


class MetricType:
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"

    ALL = (COUNTER, GAUGE, HISTOGRAM, SUMMARY)


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Metric:
    """A single labeled observation of a metric family."""

    name: str
    type: str  # one of MetricType.*
    labels: Tuple[Tuple[str, str], ...]  # sorted (key, value) pairs
    value: float
    timestamp: str


@dataclass(frozen=True)
class MetricFamily:
    """Definition of a metric family."""

    name: str
    type: str
    help: str = ""
    unit: str = ""
    label_names: Tuple[str, ...] = ()


@dataclass(frozen=True)
class CounterSample:
    name: str
    labels: Tuple[Tuple[str, str], ...]
    value: float
    timestamp: str


@dataclass(frozen=True)
class GaugeSample:
    name: str
    labels: Tuple[Tuple[str, str], ...]
    value: float
    timestamp: str


@dataclass(frozen=True)
class HistogramBucket:
    le: str  # upper bound ("+Inf" for the final bucket)
    count: int


@dataclass(frozen=True)
class HistogramSnapshot:
    name: str
    labels: Tuple[Tuple[str, str], ...]
    count: int
    sum: float
    buckets: Tuple[HistogramBucket, ...]
    timestamp: str


@dataclass(frozen=True)
class SummarySnapshot:
    name: str
    labels: Tuple[Tuple[str, str], ...]
    count: int
    sum: float
    quantiles: Tuple[Tuple[float, float], ...]  # (quantile, value)
    timestamp: str


@dataclass(frozen=True)
class CollectionResult:
    """Deterministic snapshot of every registered metric family."""

    schema_version: str
    collected_at: str
    counters: Tuple[CounterSample, ...]
    gauges: Tuple[GaugeSample, ...]
    histograms: Tuple[HistogramSnapshot, ...]
    summaries: Tuple[SummarySnapshot, ...]

    def to_text(self) -> str:
        """Prometheus-like text exposition, fully deterministic."""
        lines: List[str] = []
        lines.append(f"# C-UAS Platform Metrics — {self.collected_at}")
        lines.append(f"# schema_version={self.schema_version}")
        for c in sorted(self.counters, key=lambda s: (s.name, s.labels)):
            lbl = "".join(f'{k}="{v}"' for k, v in c.labels) or ""
            lines.append(f"{c.name}{{{lbl}}} {c.value} {int(_ts_ms(c.timestamp))}")
        for g in sorted(self.gauges, key=lambda s: (s.name, s.labels)):
            lbl = "".join(f'{k}="{v}"' for k, v in g.labels) or ""
            lines.append(f"{g.name}{{{lbl}}} {g.value} {int(_ts_ms(g.timestamp))}")
        for h in sorted(self.histograms, key=lambda s: (s.name, s.labels)):
            lbl = "".join(f'{k}="{v}"' for k, v in h.labels) or ""
            lines.append(f"{h.name}_count{{{lbl}}} {h.count}")
            lines.append(f"{h.name}_sum{{{lbl}}} {h.sum}")
            for b in h.buckets:
                lines.append(f'{h.name}_bucket{{{lbl},le="{b.le}"}} {b.count}')
        for s in sorted(self.summaries, key=lambda s: (s.name, s.labels)):
            lbl = "".join(f'{k}="{v}"' for k, v in s.labels) or ""
            lines.append(f"{s.name}_count{{{lbl}}} {s.count}")
            lines.append(f"{s.name}_sum{{{lbl}}} {s.sum}")
            for q, v in s.quantiles:
                lines.append(f'{s.name}{{{lbl},quantile="{q}"}} {v}')
        return "\n".join(lines) + "\n"


def _ts_ms(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000
    except ValueError:
        return 0.0


# --------------------------------------------------------------------------- #
# MetricRegistry
# --------------------------------------------------------------------------- #


class MetricRegistry:
    """Thread-unsafe, deterministic metrics registry.

    All mutations append timestamped samples. Collection sorts output so the
    same sequence of operations always yields identical text.
    """

    def __init__(
        self,
        state_dir: Optional[str] = None,
        seed: int = DEFAULT_SEED,
    ) -> None:
        self.state_dir = Path(state_dir) if state_dir is not None else METRICS_DIR
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.seed = seed
        self._families: Dict[str, MetricFamily] = {}
        # name -> labels_key -> list of (timestamp, value)
        self._counter_samples: Dict[
            str, Dict[Tuple[Tuple[str, str], ...], List[Tuple[str, float]]]
        ] = {}
        self._gauge_samples: Dict[
            str, Dict[Tuple[Tuple[str, str], ...], List[Tuple[str, float]]]
        ] = {}
        self._histogram_observations: Dict[
            str, Dict[Tuple[Tuple[str, str], ...], List[Tuple[str, float]]]
        ] = {}
        self._summary_observations: Dict[
            str, Dict[Tuple[Tuple[str, str], ...], List[Tuple[str, float]]]
        ] = {}
        self._histogram_buckets: Tuple[str, ...] = (
            "0.005",
            "0.01",
            "0.025",
            "0.05",
            "0.1",
            "0.25",
            "0.5",
            "1",
            "2.5",
            "5",
            "10",
            "+Inf",
        )

    # -- registration ------------------------------------------------------ #

    def register(
        self,
        name: str,
        type: str,
        help: str = "",
        unit: str = "",
        label_names: Tuple[str, ...] = (),
    ) -> MetricFamily:
        if type not in MetricType.ALL:
            raise ValueError(f"Unknown metric type: {type}")
        family = MetricFamily(name=name, type=type, help=help, unit=unit, label_names=label_names)
        self._families[name] = family
        return family

    # -- counters ---------------------------------------------------------- #

    def counter(self, name: str) -> "Counter":
        return Counter(registry=self, name=name)

    def _record_counter(
        self, name: str, labels_key: Tuple[Tuple[str, str], ...], value: float
    ) -> None:
        by_label = self._counter_samples.setdefault(name, {})
        series = by_label.setdefault(labels_key, [])
        series.append((utc_now_iso(), value))

    # -- gauges ------------------------------------------------------------ #

    def gauge(self, name: str) -> "Gauge":
        return Gauge(registry=self, name=name)

    def _record_gauge(
        self, name: str, labels_key: Tuple[Tuple[str, str], ...], value: float
    ) -> None:
        by_label = self._gauge_samples.setdefault(name, {})
        series = by_label.setdefault(labels_key, [])
        series.append((utc_now_iso(), value))

    # -- histograms -------------------------------------------------------- #

    def histogram(self, name: str) -> "Histogram":
        return Histogram(registry=self, name=name)

    def _record_histogram(
        self, name: str, labels_key: Tuple[Tuple[str, str], ...], value: float
    ) -> None:
        by_label = self._histogram_observations.setdefault(name, {})
        series = by_label.setdefault(labels_key, [])
        series.append((utc_now_iso(), value))

    # -- summaries --------------------------------------------------------- #

    def summary(self, name: str) -> "Summary":
        return Summary(registry=self, name=name)

    def _record_summary(
        self, name: str, labels_key: Tuple[Tuple[str, str], ...], value: float
    ) -> None:
        by_label = self._summary_observations.setdefault(name, {})
        series = by_label.setdefault(labels_key, [])
        series.append((utc_now_iso(), value))

    # -- collection -------------------------------------------------------- #

    def collect(self) -> CollectionResult:
        counters: List[CounterSample] = []
        for name in sorted(self._counter_samples):
            for labels_key in sorted(self._counter_samples[name]):
                series = self._counter_samples[name][labels_key]
                # Counter value = cumulative sum of all increments (Prometheus semantics).
                value = sum(v for _, v in series)
                counters.append(
                    CounterSample(
                        name=name,
                        labels=labels_key,
                        value=value,
                        timestamp=series[-1][0] if series else utc_now_iso(),
                    )
                )

        gauges: List[GaugeSample] = []
        for name in sorted(self._gauge_samples):
            for labels_key in sorted(self._gauge_samples[name]):
                series = self._gauge_samples[name][labels_key]
                value = series[-1][1] if series else 0.0
                gauges.append(
                    GaugeSample(
                        name=name,
                        labels=labels_key,
                        value=value,
                        timestamp=series[-1][0] if series else utc_now_iso(),
                    )
                )

        histograms: List[HistogramSnapshot] = []
        for name in sorted(self._histogram_observations):
            for labels_key in sorted(self._histogram_observations[name]):
                series = self._histogram_observations[name][labels_key]
                values = [v for _, v in series]
                count = len(values)
                total = sum(values)
                sorted_vals = sorted(values)
                buckets: List[HistogramBucket] = []
                for le in self._histogram_buckets:
                    if le == "+Inf":
                        bcount = count
                    else:
                        bcount = sum(1 for v in values if v <= float(le))
                    buckets.append(HistogramBucket(le=le, count=bcount))
                histograms.append(
                    HistogramSnapshot(
                        name=name,
                        labels=labels_key,
                        count=count,
                        sum=round(total, 6),
                        buckets=tuple(buckets),
                        timestamp=series[-1][0] if series else utc_now_iso(),
                    )
                )

        summaries: List[SummarySnapshot] = []
        for name in sorted(self._summary_observations):
            for labels_key in sorted(self._summary_observations[name]):
                series = self._summary_observations[name][labels_key]
                values = [v for _, v in series]
                count = len(values)
                total = sum(values)
                sorted_vals = sorted(values)
                quantiles: List[Tuple[float, float]] = []
                for q in (0.5, 0.9, 0.95, 0.99):
                    quantiles.append((q, round(percentile(sorted_vals, q * 100.0), 6)))
                summaries.append(
                    SummarySnapshot(
                        name=name,
                        labels=labels_key,
                        count=count,
                        sum=round(total, 6),
                        quantiles=tuple(quantiles),
                        timestamp=series[-1][0] if series else utc_now_iso(),
                    )
                )

        result = CollectionResult(
            schema_version=SCHEMA_VERSION,
            collected_at=utc_now_iso(),
            counters=tuple(counters),
            gauges=tuple(gauges),
            histograms=tuple(histograms),
            summaries=tuple(summaries),
        )
        _write_json(self.state_dir / "collection.json", result)
        return result

    def to_text(self) -> str:
        return self.collect().to_text()


# --------------------------------------------------------------------------- #
# Convenience metric objects (mutable wrappers around the immutable registry)
# --------------------------------------------------------------------------- #


class Counter:
    """Monotonically increasing counter."""

    def __init__(self, registry: MetricRegistry, name: str) -> None:
        self._registry = registry
        self.name = name

    def inc(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        self._registry._record_counter(self.name, _labels_key(labels), float(value))


class Gauge:
    """Gauge that can go up or down."""

    def __init__(self, registry: MetricRegistry, name: str) -> None:
        self._registry = registry
        self.name = name

    def set(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        self._registry._record_gauge(self.name, _labels_key(labels), float(value))

    def inc(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        # Gauge increment: read last value then add. No cross-sample state kept
        # besides the series; last observed value is the current value.
        current = self._current(labels)
        self._registry._record_gauge(self.name, _labels_key(labels), current + float(value))

    def dec(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        current = self._current(labels)
        self._registry._record_gauge(self.name, _labels_key(labels), current - float(value))

    def _current(self, labels: Optional[Dict[str, str]]) -> float:
        by_label = self._registry._gauge_samples.get(self.name, {})
        series = by_label.get(_labels_key(labels), [])
        return series[-1][1] if series else 0.0


class Histogram:
    """Histogram observing sample values into fixed buckets."""

    def __init__(self, registry: MetricRegistry, name: str) -> None:
        self._registry = registry
        self.name = name

    def observe(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        self._registry._record_histogram(self.name, _labels_key(labels), float(value))


class Summary:
    """Summary computing streaming quantiles over observed values."""

    def __init__(self, registry: MetricRegistry, name: str) -> None:
        self._registry = registry
        self.name = name

    def observe(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        self._registry._record_summary(self.name, _labels_key(labels), float(value))


# --------------------------------------------------------------------------- #
# Module-level pure helpers
# --------------------------------------------------------------------------- #


def compute_percentiles(samples: Sequence[float]) -> Dict[str, float]:
    sorted_samples = sorted(samples)
    return {
        "p50": round(percentile(sorted_samples, 50.0), 6),
        "p95": round(percentile(sorted_samples, 95.0), 6),
        "p99": round(percentile(sorted_samples, 99.0), 6),
    }


def new_registry(state_dir: Optional[str] = None) -> MetricRegistry:
    return MetricRegistry(state_dir=state_dir)
