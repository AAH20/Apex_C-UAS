"""
Deterministic hardening tests for the c-uas performance module.

Covers:
  - optimizers: A* pathfinding, greedy set cover, local search (fixed seeds,
    reproducible results).
  - profiler: per-endpoint timing, memory pressure detection, bottleneck
    identification.
  - sla_tracker: p50/p95/p99 latency, error budget, recovery time.
  - cli: c-uas perf --benchmark|--profile|--sla deterministic output.

All values are computed from real execution; no mocks, no fabricated metrics.
State persists under ~/.c-uas-platform/performance/ (outside the repo).
"""

from __future__ import annotations

import os
from typing import Callable, Dict, List, Sequence, cast

from c_uas.performance.optimizers import (
    DEFAULT_SEED,
    AStarResult,
    LocalSearchResult,
    SetCoverResult,
    a_star,
    greedy_set_cover,
    local_search,
)
from c_uas.performance.profiler import (
    EndpointTiming,
    ProfileStore,
    detect_bottlenecks,
    percentile,
    profile_endpoint,
    run_profile,
    throughput_rps,
)
from c_uas.performance.sla_tracker import (
    DEFAULT_SEED as SLA_SEED,
)
from c_uas.performance.sla_tracker import (
    RecoveryRecord,
    SLARegistry,
    SLATarget,
    compliance_status,
    compute_percentiles,
    error_budget_remaining,
    record_recovery,
)

# Force state outside the repo into the scratch dir for deterministic,
# hermetic test runs (never write into ~/.c-uas-platform during tests).
os.environ["C_UAS_PERFORMANCE_DIR"] = "/Users/ahmedhassan/.hermes/cache/scratch/perf_tests"


# --------------------------------------------------------------------------- #
# Optimizers: A*
# --------------------------------------------------------------------------- #


def test_astar_finds_path_on_open_grid() -> None:
    grid = [[True] * 5 for _ in range(5)]
    result = a_star(grid, (0, 0), (4, 4), seed=DEFAULT_SEED)
    assert isinstance(result, AStarResult)
    assert result.found is True
    assert result.path[0] == (0, 0)
    assert result.path[-1] == (4, 4)
    assert result.cost == 8.0  # Manhattan distance on empty 5x5 grid
    assert result.nodes_expanded > 0


def test_astar_blocked_goal_returns_not_found() -> None:
    grid = [[True] * 5 for _ in range(5)]
    grid[4][4] = False  # block the goal
    result = a_star(grid, (0, 0), (4, 4), seed=DEFAULT_SEED)
    assert result.found is False
    assert result.path == ()
    assert result.cost == float("inf")


def test_astar_same_seed_reproducible() -> None:
    grid = [
        [True, True, True, True, True],
        [True, False, False, False, True],
        [True, True, True, True, True],
        [True, False, False, False, True],
        [True, True, True, True, True],
    ]
    r1 = a_star(grid, (0, 0), (4, 4), seed=7)
    r2 = a_star(grid, (0, 0), (4, 4), seed=7)
    assert r1.path == r2.path
    assert r1.cost == r2.cost
    assert r1.nodes_expanded == r2.nodes_expanded


def test_astar_different_seed_may_differ() -> None:
    grid = [[True] * 5 for _ in range(5)]
    r1 = a_star(grid, (0, 0), (4, 4), seed=1)
    r2 = a_star(grid, (0, 0), (4, 4), seed=2)
    # On an open grid all shortest paths have equal cost; cost must match.
    assert r1.cost == r2.cost == 8.0


# --------------------------------------------------------------------------- #
# Optimizers: greedy set cover
# --------------------------------------------------------------------------- #


def test_set_covers_full_universe() -> None:
    universe = ["a", "b", "c", "d", "e"]
    sets: Dict[str, Sequence[object]] = {
        "S1": ["a", "b"],
        "S2": ["c", "d"],
        "S3": ["e"],
        "S4": ["a", "c"],
    }
    result = greedy_set_cover(universe, sets, seed=DEFAULT_SEED)
    assert isinstance(result, SetCoverResult)
    assert set(result.covered_elements) == set(universe)
    assert result.uncovered_elements == ()
    assert result.set_count >= 1


def test_set_cover_deterministic_same_seed() -> None:
    universe = [1, 2, 3, 4, 5, 6]
    sets: Dict[str, Sequence[object]] = {
        "A": [1, 2, 3],
        "B": [3, 4, 5],
        "C": [5, 6],
        "D": [1, 6],
    }
    r1 = greedy_set_cover(universe, sets, seed=42)
    r2 = greedy_set_cover(universe, sets, seed=42)
    assert r1.chosen_sets == r2.chosen_sets
    assert r1.covered_elements == r2.covered_elements


def test_set_cover_universe_empty() -> None:
    result = greedy_set_cover(
        [], cast(Dict[str, Sequence[object]], {"S1": ["a"]}), seed=DEFAULT_SEED
    )
    assert result.universe_size == 0
    assert result.covered_elements == ()
    assert result.uncovered_elements == ()


# --------------------------------------------------------------------------- #
# Optimizers: local search
# --------------------------------------------------------------------------- #


def test_local_search_improves_cost() -> None:
    def cost_fn(state: List[float]) -> float:
        return sum(x**2 for x in state)

    def neighbors_fn(state: List[float]) -> List[List[float]]:
        out: List[List[float]] = []
        for i in range(len(state)):
            for delta in (-1.0, 1.0):
                n = list(state)
                n[i] += delta
                out.append(n)
        return out

    result = local_search(
        [10.0, -10.0],
        cast(Callable[[Sequence[object]], float], cost_fn),
        cast(Callable[[Sequence[object]], Sequence[Sequence[object]]], neighbors_fn),
        seed=DEFAULT_SEED,
        max_iterations=200,
    )
    assert isinstance(result, LocalSearchResult)
    assert result.best_cost < cost_fn([10.0, -10.0])
    assert result.improved is True


def test_local_search_deterministic_same_seed() -> None:
    def cost_fn(state: List[float]) -> float:
        return sum(x**2 for x in state)

    def neighbors_fn(state: List[float]) -> List[List[float]]:
        out: List[List[float]] = []
        for i in range(len(state)):
            for delta in (-1.0, 1.0):
                n = list(state)
                n[i] += delta
                out.append(n)
        return out

    r1 = local_search(
        [5.0, 5.0],
        cast(Callable[[Sequence[object]], float], cost_fn),
        cast(Callable[[Sequence[object]], Sequence[Sequence[object]]], neighbors_fn),
        seed=3,
        max_iterations=50,
    )
    r2 = local_search(
        [5.0, 5.0],
        cast(Callable[[Sequence[object]], float], cost_fn),
        cast(Callable[[Sequence[object]], Sequence[Sequence[object]]], neighbors_fn),
        seed=3,
        max_iterations=50,
    )
    assert r1.best_state == r2.best_state
    assert r1.best_cost == r2.best_cost
    assert r1.iterations == r2.iterations


def test_local_search_stuck_at_optimum_no_improvement() -> None:
    def cost_fn(state: List[float]) -> float:
        return sum(x**2 for x in state)

    def neighbors_fn(state: List[float]) -> List[List[float]]:
        return []

    result = local_search(
        [0.0, 0.0],
        cast(Callable[[Sequence[object]], float], cost_fn),
        cast(Callable[[Sequence[object]], Sequence[Sequence[object]]], neighbors_fn),
        seed=DEFAULT_SEED,
    )
    assert result.improved is False
    assert result.best_cost == 0.0


# --------------------------------------------------------------------------- #
# Profiler: percentiles
# --------------------------------------------------------------------------- #


def test_percentile_sorted_input_deterministic() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    assert percentile(values, 50.0) == 5.0
    assert percentile(values, 95.0) == 10.0
    assert percentile(values, 99.0) == 10.0
    assert percentile(values, 0.0) == 1.0


def test_percentile_empty_returns_zero() -> None:
    assert percentile([], 50.0) == 0.0


# --------------------------------------------------------------------------- #
# Profiler: per-endpoint timing
# --------------------------------------------------------------------------- #


def test_profile_endpoint_computes_real_values() -> None:
    samples = [0.05, 0.06, 0.07, 0.08, 0.20]
    timing = profile_endpoint(
        "api/detect", samples, errors=1, window_seconds=1.0, seed=DEFAULT_SEED
    )
    assert isinstance(timing, EndpointTiming)
    assert timing.endpoint == "api/detect"
    assert timing.count == 5
    assert timing.error_count == 1
    assert timing.error_rate == 0.2
    assert timing.p50_seconds == 0.07
    assert timing.min_seconds == 0.05
    assert timing.max_seconds == 0.20


def test_profile_store_record_and_timing() -> None:
    store = ProfileStore(seed=DEFAULT_SEED)
    for i in range(10):
        store.record_latency("ep", 0.1 + i * 0.01, errored=(i == 9))
    timing = store.endpoint_timing("ep")
    assert timing is not None
    assert timing.count == 10
    assert timing.error_count == 1
    assert timing.error_rate == 0.1


def test_profile_store_unknown_endpoint_returns_none() -> None:
    store = ProfileStore(seed=DEFAULT_SEED)
    assert store.endpoint_timing("missing") is None


def test_throughput_rps_positive() -> None:
    store = ProfileStore(seed=DEFAULT_SEED)
    for _ in range(100):
        store.record_latency("ep", 0.01)
    rps = throughput_rps("ep", store)
    assert rps > 0


# --------------------------------------------------------------------------- #
# Profiler: memory pressure + bottlenecks
# --------------------------------------------------------------------------- #


def test_detect_memory_pressure_flagged() -> None:
    store = ProfileStore(seed=DEFAULT_SEED)
    store.record_memory(1.0, 10 * 1024 * 1024)  # 10 MiB - no pressure
    assert store.detect_memory_pressure() is False

    store2 = ProfileStore(seed=DEFAULT_SEED)
    store2.record_memory(1.0, 300 * 1024 * 1024)  # 300 MiB - pressure
    assert store2.detect_memory_pressure() is True


def test_detect_bottlenecks_flags_high_p99() -> None:
    timing = EndpointTiming(
        endpoint="slow",
        count=10,
        total_seconds=1.0,
        min_seconds=0.1,
        max_seconds=2.0,
        mean_seconds=0.5,
        p50_seconds=0.4,
        p95_seconds=0.8,
        p99_seconds=2.0,
        error_count=0,
        error_rate=0.0,
    )
    bottlenecks = detect_bottlenecks({"slow": timing}, memory_pressure=False, peak_rss_bytes=0)
    assert any(b.category == "latency" and b.severity == "critical" for b in bottlenecks)


def test_run_profile_returns_result() -> None:
    store = ProfileStore(seed=DEFAULT_SEED)
    for i in range(50):
        store.record_latency("ep", 0.05 + (i % 5) * 0.01, errored=(i % 10 == 0))
    store.record_memory(1.0, 64 * 1024 * 1024)
    result = run_profile(store, seed=DEFAULT_SEED)
    assert "ep" in result.endpoints
    assert isinstance(result.memory_pressure, bool)
    assert isinstance(result.bottlenecks, list)


# --------------------------------------------------------------------------- #
# SLA tracker
# --------------------------------------------------------------------------- #


def test_compute_percentiles() -> None:
    samples = [float(i) for i in range(1, 101)]
    p = compute_percentiles(samples)
    assert "p50" in p and "p95" in p and "p99" in p
    assert p["p50"] == 50.0
    assert p["p95"] == 95.0


def test_error_budget_remaining_clamped_at_zero() -> None:
    assert error_budget_remaining(0.05, 0.01) == 0.0
    assert error_budget_remaining(0.005, 0.01) == 0.005


def test_sla_registry_record_and_compute() -> None:
    registry = SLARegistry(seed=SLA_SEED)
    target = SLATarget(
        module="detect",
        latency_p50_s=0.1,
        latency_p95_s=0.5,
        latency_p99_s=1.0,
        error_budget=0.01,
        recovery_time_s=30.0,
    )
    registry.add_target(target)
    for _ in range(1000):
        registry.record_request("detect", 0.05, failed=False)
    for _ in range(2):
        registry.record_request("detect", 0.05, failed=True)
    result = registry.compute_result("detect")
    assert result is not None
    assert result.sample_count == 1002
    assert result.error_count == 2
    assert result.p99_compliant is True
    assert result.overall_compliant is True


def test_sla_registry_error_budget_exceeded() -> None:
    registry = SLARegistry(seed=SLA_SEED)
    target = SLATarget(
        module="flaky",
        latency_p50_s=0.1,
        latency_p95_s=0.5,
        latency_p99_s=1.0,
        error_budget=0.01,
        recovery_time_s=30.0,
    )
    registry.add_target(target)
    for _ in range(1000):
        registry.record_request("flaky", 0.05, failed=False)
    for _ in range(50):  # 5% error rate > 1% budget
        registry.record_request("flaky", 0.05, failed=True)
    result = registry.compute_result("flaky")
    assert result is not None
    assert result.error_budget_compliant is False
    assert result.overall_compliant is False


def test_sla_registry_no_data_returns_none() -> None:
    registry = SLARegistry(seed=SLA_SEED)
    assert registry.compute_result("missing") is None
    assert registry.error_budget("missing") is None


def test_sla_registry_compliance_status() -> None:
    registry = SLARegistry(seed=SLA_SEED)
    assert compliance_status(registry, "empty") == "no_data"


def test_error_budget_structure() -> None:
    registry = SLARegistry(seed=SLA_SEED)
    for _ in range(100):
        registry.record_request("b", 0.05, failed=False)
    for _ in range(5):
        registry.record_request("b", 0.05, failed=True)
    budget = registry.error_budget("b")
    assert budget is not None
    assert budget.total_requests == 105
    assert budget.failed_requests == 5
    assert budget.error_rate == round(5 / 105, 6)
    assert budget.budget == 0.01
    assert budget.exhausted is True  # 5/105 > 0.01


# --------------------------------------------------------------------------- #
# SLA tracker: recovery
# --------------------------------------------------------------------------- #


def test_record_recovery_compliant() -> None:
    registry = SLARegistry(seed=SLA_SEED)
    registry.add_target(
        SLATarget(
            module="rec",
            latency_p50_s=0.1,
            latency_p95_s=0.5,
            latency_p99_s=1.0,
            error_budget=0.01,
            recovery_time_s=30.0,
        )
    )
    rec = record_recovery(registry, "rec", "t0", "t1", 10.0)
    assert isinstance(rec, RecoveryRecord)
    assert rec.recovery_time_s == 10.0
    assert rec.target_recovery_s == 30.0
    assert rec.compliant is True


def test_record_recovery_noncompliant() -> None:
    registry = SLARegistry(seed=SLA_SEED)
    rec = record_recovery(registry, "rec", "t0", "t1", 60.0)
    assert rec.compliant is False


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #


def test_cli_perf_subcommand_registered() -> None:
    from c_uas.cli import main

    # perf with no action prints usage and returns 1 (subcommand registered).
    assert main(["perf"]) == 1


def test_cli_perf_benchmark_deterministic_output(capsys) -> None:
    from c_uas.performance.cli import perf_main

    perf_main(
        type(
            "NS",
            (),
            {
                "benchmark": True,
                "profile": False,
                "sla": False,
                "module": "default",
                "seed": 42,
            },
        )()
    )
    out = capsys.readouterr().out
    assert "[C-UAS] Perf Benchmark" in out
    assert "A* path" in out
    assert "Set cover" in out
    assert "Local search" in out


def test_cli_perf_profile_deterministic_output(capsys) -> None:
    from c_uas.performance.cli import perf_main

    perf_main(
        type(
            "NS",
            (),
            {
                "benchmark": False,
                "profile": True,
                "sla": False,
                "module": "default",
                "seed": 42,
            },
        )()
    )
    out = capsys.readouterr().out
    assert "[C-UAS] Perf Profile" in out
    assert "Mean latency" in out
    assert "p99 latency" in out
    assert "Bottlenecks" in out


def test_cli_perf_sla_deterministic_output(capsys) -> None:
    from c_uas.performance.cli import perf_main

    perf_main(
        type(
            "NS",
            (),
            {
                "benchmark": False,
                "profile": False,
                "sla": True,
                "module": "default",
                "seed": 42,
            },
        )()
    )
    out = capsys.readouterr().out
    assert "[C-UAS] Perf SLA" in out
    assert "p50 latency" in out
    assert "p95 latency" in out
    assert "p99 latency" in out
    assert "Overall" in out
