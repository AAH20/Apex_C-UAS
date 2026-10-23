"""
Pure-Python Prometheus metrics registry.

Emits the Prometheus text exposition format (version 0.0.4) without a
runtime dependency on prometheus_client. Counters, gauges, and histograms
are supported; all collectors are deterministic and thread-safe.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import Any, Dict, List, Optional, Tuple


def _sanitize(name: str) -> str:
    out = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in name)
    return out or "metric"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _format_labels(labels: Tuple[Tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{_escape_label(v)}"' for k, v in labels) + "}"


class Metric:
    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Tuple[str, ...],
    ) -> None:
        self.name = _sanitize(name)
        self.documentation = documentation
        self.labelnames = tuple(labelnames)
        self._lock = threading.RLock()

    def collect(self) -> Iterable[str]:
        return iter(())


class Counter(Metric):
    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Tuple[str, ...] = (),
    ) -> None:
        super().__init__(name, documentation, labelnames)
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {}

    def inc(
        self, value: float = 1.0, labels: Optional[Dict[str, str]] = None
    ) -> None:
        labels = labels or {}
        key = tuple((k, labels.get(k, "")) for k in self.labelnames)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + value

    def collect(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.documentation}"
        yield f"# TYPE {self.name} counter"
        with self._lock:
            for key, value in self._values.items():
                yield f"{self.name}{_format_labels(key)} {value}"


class Gauge(Metric):
    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Tuple[str, ...] = (),
    ) -> None:
        super().__init__(name, documentation, labelnames)
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {}

    def set(
        self, value: float, labels: Optional[Dict[str, str]] = None
    ) -> None:
        labels = labels or {}
        key = tuple((k, labels.get(k, "")) for k in self.labelnames)
        with self._lock:
            self._values[key] = float(value)

    def inc(
        self, value: float = 1.0, labels: Optional[Dict[str, str]] = None
    ) -> None:
        labels = labels or {}
        key = tuple((k, labels.get(k, "")) for k in self.labelnames)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + float(value)

    def collect(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.documentation}"
        yield f"# TYPE {self.name} gauge"
        with self._lock:
            for key, value in self._values.items():
                yield f"{self.name}{_format_labels(key)} {value}"


class Histogram(Metric):
    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Tuple[str, ...] = (),
        buckets: Optional[Tuple[float, ...]] = None,
    ) -> None:
        super().__init__(name, documentation, labelnames)
        self._buckets = tuple(buckets or (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10))
        self._counts: Dict[Tuple[Tuple[str, str], ...], int] = {}
        self._sums: Dict[Tuple[Tuple[str, str], ...], float] = {}
        self._bucket_counts: Dict[Tuple[Tuple[Tuple[str, str], ...], float], int] = {}

    def observe(
        self, value: float, labels: Optional[Dict[str, str]] = None
    ) -> None:
        labels = labels or {}
        key = tuple((k, labels.get(k, "")) for k in self.labelnames)
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + 1
            self._sums[key] = self._sums.get(key, 0.0) + float(value)
            for bucket in self._buckets:
                if float(value) <= bucket:
                    bkey = (key, bucket)
                    self._bucket_counts[bkey] = self._bucket_counts.get(bkey, 0) + 1

    def collect(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.documentation}"
        yield f"# TYPE {self.name} histogram"
        with self._lock:
            for (key, bucket), count in sorted(self._bucket_counts.items()):
                bucket_labels = key + (("le", str(bucket)),)
                yield f"{self.name}_bucket{_format_labels(bucket_labels)} {count}"
            for key, count in self._counts.items():
                yield f"{self.name}_count{_format_labels(key)} {count}"
            for key, total in self._sums.items():
                yield f"{self.name}_sum{_format_labels(key)} {total}"


class MetricsRegistry:
    def __init__(self) -> None:
        self._metrics: Dict[str, Metric] = {}
        self._lock = threading.RLock()

    def counter(
        self,
        name: str,
        documentation: str,
        labelnames: Tuple[str, ...] = (),
    ) -> Counter:
        with self._lock:
            metric = Counter(name, documentation, labelnames)
            self._metrics[metric.name] = metric
            return metric

    def gauge(
        self,
        name: str,
        documentation: str,
        labelnames: Tuple[str, ...] = (),
    ) -> Gauge:
        with self._lock:
            metric = Gauge(name, documentation, labelnames)
            self._metrics[metric.name] = metric
            return metric

    def histogram(
        self,
        name: str,
        documentation: str,
        labelnames: Tuple[str, ...] = (),
        buckets: Optional[Tuple[float, ...]] = None,
    ) -> Histogram:
        with self._lock:
            metric = Histogram(name, documentation, labelnames, buckets)
            self._metrics[metric.name] = metric
            return metric

    def render(self) -> str:
        lines: List[str] = []
        with self._lock:
            for metric in self._metrics.values():
                lines.extend(metric.collect())
                lines.append("")
        return "\n".join(lines)


metrics = MetricsRegistry()

HTTP_REQUESTS_TOTAL = metrics.counter(
    "http_requests_total", "Total HTTP requests", ("method", "path", "status")
)
HTTP_REQUEST_DURATION_SECONDS = metrics.histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ("method", "path"),
)
HTTP_ERRORS_TOTAL = metrics.counter(
    "http_errors_total", "Total HTTP error responses", ("method", "path", "status")
)
HTTP_ACTIVE_CONNECTIONS = metrics.gauge("http_active_connections", "Active HTTP connections")

__all__ = [
    "HTTP_ACTIVE_CONNECTIONS",
    "HTTP_ERRORS_TOTAL",
    "HTTP_REQUESTS_TOTAL",
    "HTTP_REQUEST_DURATION_SECONDS",
    "Counter",
    "Gauge",
    "Histogram",
    "MetricsRegistry",
    "metrics",
]
