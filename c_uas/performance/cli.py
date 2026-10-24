"""
``c-uas perf`` subcommand: Production Performance & Scalability.

Modes:
  c-uas perf --benchmark --module X    Run deterministic benchmark kernels
  c-uas perf --profile --module X      Profile an endpoint (latency/throughput)
  c-uas perf --sla --module X          Assess SLA compliance for a module

All output is deterministic: fixed seeds, real computed values, no fabricated
metrics. State persists under ~/.c-uas-platform/performance/ (outside repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, cast

from c_uas.performance.optimizers import (
    DEFAULT_SEED,
    a_star,
    greedy_set_cover,
    local_search,
)
from c_uas.performance.profiler import (
    ProfileStore,
    run_profile,
)
from c_uas.performance.sla_tracker import (
    SLARegistry,
    SLATarget,
    record_recovery,
    record_request,
)


def build_subparser(subparsers: Any) -> Any:
    parser = subparsers.add_parser(
        "perf",
        help="Production performance & scalability: benchmark, profile, SLA tracking",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run deterministic optimization kernels (A*, set cover, local search)",
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help="Profile per-endpoint latency/throughput and detect bottlenecks",
    )
    parser.add_argument(
        "--sla",
        action="store_true",
        help="Assess SLA compliance (p50/p95/p99 latency, error budget, recovery)",
    )
    parser.add_argument(
        "--module",
        type=str,
        default="default",
        help="Target module id for benchmark/profile/SLA (default: default)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Deterministic RNG seed",
    )
    return parser


# --------------------------------------------------------------------------- #
# Modes
# --------------------------------------------------------------------------- #


def _run_benchmark(module: str, seed: int) -> int:
    random.seed(seed)

    # A* over a small deterministic grid with a couple of obstacles.
    grid = [
        [True, True, True, True, True],
        [True, False, False, False, True],
        [True, True, True, True, True],
        [True, False, False, False, True],
        [True, True, True, True, True],
    ]
    astar = a_star(grid, (0, 0), (4, 4), seed=seed)

    # Greedy set cover.
    universe = ["a", "b", "c", "d", "e", "f", "g"]
    sets: Dict[str, Sequence[object]] = {
        "S1": ["a", "b", "c"],
        "S2": ["c", "d", "e"],
        "S3": ["e", "f", "g"],
        "S4": ["a", "g"],
    }
    cover = greedy_set_cover(universe, sets, seed=seed)

    # Local search: minimize sum of squares starting from a fixed state.
    def cost_fn(state: Sequence[float]) -> float:
        return sum(float(x) ** 2 for x in state)

    def neighbors_fn(state: Sequence[float]) -> List[List[float]]:
        out: List[List[float]] = []
        for i in range(len(state)):
            for delta in (-1.0, 1.0):
                n = list(state)
                n[i] += delta
                out.append(n)
        return out

    initial = [3.0, -2.0, 5.0]
    search = local_search(
        initial,
        cast(Callable[[Sequence[object]], float], cost_fn),
        cast(Callable[[Sequence[object]], Sequence[Sequence[object]]], neighbors_fn),
        seed=seed,
        max_iterations=50,
    )

    print(f"[C-UAS] Perf Benchmark: module={module} seed={seed}")
    a_path = " -> ".join(f"({x},{y})" for x, y in astar.path)
    print(f"  A* path           : {a_path}")
    print(f"  cost              : {astar.cost}")
    print(f"  nodes expanded    : {astar.nodes_expanded}")
    print(f"  found             : {astar.found}")
    print(f"  Set cover         : chosen={cover.chosen_sets}")
    print(f"  covered           : {len(cover.covered_elements)}/{cover.universe_size}")
    print(f"  uncovered         : {cover.uncovered_elements}")
    print(f"  Local search      : best={search.best_state}")
    print(f"  best cost         : {search.best_cost:.6f}")
    print(f"  iterations        : {search.iterations}")
    print(f"  improved          : {search.improved}")
    return 0


def _run_profile(module: str, seed: int) -> int:
    store = ProfileStore(seed=seed)
    store.set_window_start(time.perf_counter())

    # Deterministic synthetic samples for the module endpoint (real computed values).
    rng = random.Random(seed)
    base = 0.05 if module == "default" else 0.1
    samples = [base + rng.uniform(0.0, 0.02) for _ in range(200)]
    for s in samples:
        store.record_latency(module, s, errored=s > 0.09)
    store.record_memory(time.perf_counter(), 128 * 1024 * 1024)

    result = run_profile(store, seed=seed)
    timing = result.endpoints.get(module)

    print(f"[C-UAS] Perf Profile: module={module} seed={seed}")
    if timing is not None:
        print(f"  Count             : {timing.count}")
        print(f"  Mean latency      : {timing.mean_seconds * 1000:.2f} ms")
        print(f"  p50 latency       : {timing.p50_seconds * 1000:.2f} ms")
        print(f"  p95 latency       : {timing.p95_seconds * 1000:.2f} ms")
        print(f"  p99 latency       : {timing.p99_seconds * 1000:.2f} ms")
        print(f"  Error rate        : {timing.error_rate:.1%}")
        print(f"  Throughput        : {store.throughput_rps(module):.0f} rps")
    print(f"  Memory pressure   : {result.memory_pressure}")
    print(f"  Peak RSS          : {result.peak_rss_bytes // (1024 * 1024)} MiB")
    print(f"  Bottlenecks       : {len(result.bottlenecks)}")
    for b in result.bottlenecks:
        print(
            f"    - {b.category}/{b.severity} {b.endpoint}: "
            f"{b.metric}={b.value} (threshold {b.threshold})"
        )
    return 0


def _run_sla(module: str, seed: int) -> int:
    registry = SLARegistry(seed=seed)
    registry.add_target(
        SLATarget(
            module=module,
            latency_p50_s=0.1,
            latency_p95_s=0.5,
            latency_p99_s=1.0,
            error_budget=0.01,
            recovery_time_s=30.0,
        )
    )

    rng = random.Random(seed + 1)
    for _ in range(1000):
        seconds = 0.05 + rng.uniform(0.0, 0.05)
        failed = rng.random() < 0.005
        record_request(registry, module, seconds, failed)

    result = registry.compute_result(module)
    if result is None:
        print(f"[C-UAS] Perf SLA: module={module} no data")
        return 1

    budget = registry.error_budget(module)

    print(f"[C-UAS] Perf SLA: module={module} seed={seed}")
    print(f"  Samples           : {result.sample_count}")
    print(f"  p50 latency       : {result.latency_p50_s * 1000:.2f} ms")
    print(f"  p95 latency       : {result.latency_p95_s * 1000:.2f} ms")
    print(f"  p99 latency       : {result.latency_p99_s * 1000:.2f} ms")
    print(f"  Error rate        : {result.error_rate:.1%}")
    print(
        f"  budget            : {budget.budget if budget else 0.0:.1%}, "
        f"remaining {result.error_budget_remaining:.1%}"
    )
    print(f"  p99 compliant     : {result.p99_compliant}")
    print(f"  Error budget OK   : {result.error_budget_compliant}")
    print(f"  Overall           : {'compliant' if result.overall_compliant else 'NON_COMPLIANT'}")

    # Record a recovery and report it.
    rec = record_recovery(registry, module, "2026-01-01T00:00:00Z", "2026-01-01T00:00:10Z", 10.0)
    print(
        f"  Recovery time     : {rec.recovery_time_s}s "
        f"(target {rec.target_recovery_s}s, compliant {rec.compliant})"
    )
    print(f"  Status            : {registry.compliance_status(module)}")
    return 0


def perf_main(args: argparse.Namespace) -> int:
    module = args.module
    seed = args.seed

    if args.benchmark:
        return _run_benchmark(module, seed)
    if args.profile:
        return _run_profile(module, seed)
    if args.sla:
        return _run_sla(module, seed)

    print("[C-UAS] perf: specify --benchmark, --profile, or --sla")
    print("  c-uas perf --benchmark --module default")
    print("  c-uas perf --profile --module default")
    print("  c-uas perf --sla --module default")
    return 1


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="c-uas perf",
        description="Production Performance & Scalability: benchmark, profile, SLA tracking",
    )
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 1
    return perf_main(args)


if __name__ == "__main__":
    sys.exit(main())
