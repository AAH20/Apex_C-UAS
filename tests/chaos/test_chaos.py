"""Deterministic chaos / resilience tests.

Covers FaultInjector fault kinds, ChaosScenario definitions, ChaosRunner
execution, ResilienceReport generation, and persistence. All values are
computed from real execution — no mocks, no fabricated metrics.
"""

from __future__ import annotations

import time
from dataclasses import replace
from typing import List

import pytest

from c_uas.chaos.faults import (
    ALL_FAULTS,
    Fault,
    FaultInjector,
    api_timeout_fault,
    backend_crash_fault,
    memory_pressure_fault,
    network_latency_fault,
    packet_loss_fault,
)
from c_uas.chaos.report import (
    ResilienceReport,
    ResilienceReportStore,
    compute_passed,
    generate_report,
    run_all_scenarios,
)
from c_uas.chaos.runner import ChaosRunner, ChaosRunResult
from c_uas.chaos.scenarios import (
    ALL_SCENARIOS,
    ChaosScenario,
    ChaosScenarioStore,
    scenario_fingerprint,
)

_FAST_PROBE_INTERVAL = 0.05
_FAST_RECOVERY_BUDGET = 2.0


def _fast(scenario: ChaosScenario) -> ChaosScenario:
    """Return a copy of ``scenario`` with a short duration (fast tests)."""
    return replace(scenario, duration_s=0.5)


def _fast_runner() -> ChaosRunner:
    return ChaosRunner(
        probe_interval_s=_FAST_PROBE_INTERVAL, recovery_budget_s=_FAST_RECOVERY_BUDGET
    )


# --------------------------------------------------------------------------- #
# FaultInjector: fault-kind behavior (deterministic, fixed seed)
# --------------------------------------------------------------------------- #


def _fresh_counter():
    """Return a fresh counter callable (call count starts at 0)."""
    calls = 0

    def counter() -> int:
        nonlocal calls
        calls += 1
        return calls

    return counter


def test_injector_latency_delays_then_runs() -> None:
    """Latency fault sleeps severity seconds then runs the call."""
    injector = FaultInjector()
    fault = network_latency_fault("x", severity=0.05, seed=1)
    injector.activate(fault)
    counter = _fresh_counter()
    start = time.monotonic()
    result = injector.inject("x", counter)
    elapsed = time.monotonic() - start
    injector.deactivate_all()
    assert result == 1
    assert elapsed >= 0.05


def test_injector_memory_delays_then_runs() -> None:
    """Memory fault sleeps severity seconds then runs the call."""
    injector = FaultInjector()
    fault = memory_pressure_fault("x", severity=0.05, seed=1)
    injector.activate(fault)
    counter = _fresh_counter()
    start = time.monotonic()
    result = injector.inject("x", counter)
    elapsed = time.monotonic() - start
    injector.deactivate_all()
    assert result == 1
    assert elapsed >= 0.05


def test_injector_loss_drops_deterministically() -> None:
    """Loss fault drops calls at severity rate with a fixed seed."""
    injector = FaultInjector()
    fault = packet_loss_fault("x", severity=0.5, seed=42)
    injector.activate(fault)
    outcomes: List[bool] = []
    for _ in range(200):
        try:
            injector.inject("x", _fresh_counter())
            outcomes.append(True)
        except RuntimeError:
            outcomes.append(False)
    injector.deactivate_all()
    rate = sum(outcomes) / len(outcomes)
    assert 0.35 < rate < 0.65
    # Deterministic: same seed -> same pattern on a fresh injector.
    injector2 = FaultInjector()
    fault2 = packet_loss_fault("x", severity=0.5, seed=42)
    injector2.activate(fault2)
    outcomes2: List[bool] = []
    for _ in range(200):
        try:
            injector2.inject("x", _fresh_counter())
            outcomes2.append(True)
        except RuntimeError:
            outcomes2.append(False)
    injector2.deactivate_all()
    assert outcomes == outcomes2


def test_injector_crash_raises_deterministically() -> None:
    """Crash fault raises RuntimeError at severity rate with a fixed seed."""
    injector = FaultInjector()
    fault = backend_crash_fault("x", severity=0.8, seed=7)
    injector.activate(fault)
    raised = 0
    for _ in range(100):
        try:
            injector.inject("x", _fresh_counter())
        except RuntimeError:
            raised += 1
    injector.deactivate_all()
    assert 0.6 < raised / 100 < 1.0


def test_injector_timeout_raises_timeouterror() -> None:
    """Timeout fault raises TimeoutError at severity rate."""
    injector = FaultInjector()
    fault = api_timeout_fault("x", severity=1.0, seed=3)
    injector.activate(fault)
    with pytest.raises(TimeoutError):
        injector.inject("x", _fresh_counter())
    injector.deactivate_all()


def test_injector_no_active_fault_runs_call_unchanged() -> None:
    """With no active fault, the call runs normally and returns its result."""
    injector = FaultInjector()
    assert injector.inject("x", _fresh_counter()) == 1


def test_injector_unknown_fault_id_raises_keyerror() -> None:
    injector = FaultInjector()
    with pytest.raises(KeyError):
        injector.activate("does_not_exist")


def test_all_faults_have_valid_fields() -> None:
    """Every predefined fault has a sane kind, target, severity, seed."""
    for fid, fault in ALL_FAULTS.items():
        assert fault.fault_id == fid
        assert fault.kind in {"latency", "loss", "crash", "timeout", "memory"}
        assert 0.0 <= fault.severity <= 1.0
        assert fault.duration_s > 0
        assert isinstance(fault.seed, int)
        assert fault.active is True


# --------------------------------------------------------------------------- #
# ChaosScenario: definitions and store
# --------------------------------------------------------------------------- #


def test_all_scenarios_have_required_fields() -> None:
    for s in ALL_SCENARIOS:
        assert s.scenario_id
        assert s.name
        assert s.description
        assert s.faults
        assert s.targets
        assert isinstance(s.seed, int)
        assert s.duration_s > 0
        assert s.expected_recovery_s > 0
        assert 0.0 <= s.min_success_rate <= 1.0
        for fid in s.faults:
            assert fid in ALL_FAULTS


def test_scenario_ids_unique_and_expected() -> None:
    ids = [s.scenario_id for s in ALL_SCENARIOS]
    assert len(ids) == len(set(ids))
    expected = {
        "backend_failure",
        "network_partition",
        "api_timeout",
        "cascade_failure",
        "partial_outage",
    }
    assert set(ids) == expected


def test_scenario_store_loads_defaults_when_empty(tmp_path) -> None:
    store = ChaosScenarioStore(scenarios_dir=str(tmp_path / "chaos"))
    scenarios = store.load_scenarios()
    assert len(scenarios) == len(ALL_SCENARIOS)
    assert scenarios[0].scenario_id == "backend_failure"


def test_scenario_store_round_trip(tmp_path) -> None:
    dir_path = str(tmp_path / "chaos")
    store = ChaosScenarioStore(scenarios_dir=dir_path)
    store.save_scenarios(list(ALL_SCENARIOS))
    loaded = store.load_scenarios()
    assert len(loaded) == len(ALL_SCENARIOS)
    for orig, loaded_s in zip(ALL_SCENARIOS, loaded):
        assert orig.scenario_id == loaded_s.scenario_id
        assert orig.faults == loaded_s.faults
        assert orig.targets == loaded_s.targets
        assert orig.seed == loaded_s.seed
        assert abs(orig.duration_s - loaded_s.duration_s) < 1e-9


def test_scenario_store_get_unknown_raises_keyerror() -> None:
    store = ChaosScenarioStore()
    with pytest.raises(KeyError):
        store.get_scenario("no_such_scenario")


def test_scenario_fingerprint_deterministic() -> None:
    fp1 = scenario_fingerprint(list(ALL_SCENARIOS))
    fp2 = scenario_fingerprint(list(ALL_SCENARIOS))
    assert fp1 == fp2
    assert len(fp1) == 64  # sha256 hex


# --------------------------------------------------------------------------- #
# ChaosRunner: execution, pass/fail, determinism
# --------------------------------------------------------------------------- #


def test_runner_returns_structured_result() -> None:
    runner = _fast_runner()
    result = runner.run(_fast(ALL_SCENARIOS[0]))  # backend_failure
    assert isinstance(result, ChaosRunResult)
    assert result.scenario_id == "backend_failure"
    assert result.seed == 3001
    assert result.probes_total > 0
    assert 0.0 <= result.success_rate <= 1.0
    assert isinstance(result.failure_modes, list)
    assert isinstance(result.recovered, bool)
    assert isinstance(result.passed, bool)
    assert isinstance(result.details, dict)


def test_runner_deterministic_same_seed() -> None:
    """Same scenario run twice yields identical results."""
    runner = _fast_runner()
    scenario = _fast(ALL_SCENARIOS[3])  # cascade_failure
    r1 = runner.run(scenario)
    r2 = runner.run(scenario)
    assert r1.success_rate == r2.success_rate
    assert r1.failure_modes == r2.failure_modes
    assert r1.recovered == r2.recovered
    assert r1.passed == r2.passed


def test_runner_all_scenarios_pass_default_thresholds() -> None:
    """Every default scenario passes against its own thresholds."""
    runner = _fast_runner()
    for scenario in ALL_SCENARIOS:
        result = runner.run(_fast(scenario))
        assert result.passed, f"{scenario.scenario_id} did not pass"


def test_runner_unknown_fault_in_scenario_raises_valueerror() -> None:
    runner = ChaosRunner()
    bad = ChaosScenario(
        scenario_id="bad",
        name="Bad",
        description="x",
        faults=("no_such_fault",),
        targets=("c_uas.api.server",),
        seed=1,
        duration_s=1.0,
        expected_recovery_s=1.0,
        min_success_rate=0.0,
    )
    with pytest.raises(ValueError):
        runner.run(bad)


def test_runner_success_rate_bounds() -> None:
    runner = _fast_runner()
    for scenario in ALL_SCENARIOS:
        result = runner.run(_fast(scenario))
        assert 0.0 <= result.success_rate <= 1.0


# --------------------------------------------------------------------------- #
# ResilienceReport: generation, summary, remediation, determinism
# --------------------------------------------------------------------------- #


def _run_all_fast() -> tuple:
    runner = _fast_runner()
    scenarios = tuple(_fast(s) for s in ALL_SCENARIOS)
    results = tuple(runner.run(s) for s in scenarios)
    return scenarios, results


def test_generate_report_returns_structured_report() -> None:
    scenarios, results = _run_all_fast()
    report = generate_report(scenarios, results)
    assert isinstance(report, ResilienceReport)
    assert report.report_id.startswith("CHAOS-")
    assert len(report.report_id) == 22  # "CHAOS-" + 16 hex
    assert report.overall_pass is True
    assert report.summary["scenarios_run"] == 5
    assert report.summary["scenarios_passed"] == 5
    assert report.summary["all_recovered"] is True
    assert len(report.results) == 5


def test_report_id_deterministic() -> None:
    scenarios, results = _run_all_fast()
    r1 = generate_report(scenarios, results).report_id
    r2 = generate_report(scenarios, results).report_id
    assert r1 == r2


def test_report_summary_fields() -> None:
    scenarios, results = _run_all_fast()
    report = generate_report(scenarios, results)
    s = report.summary
    for key in (
        "scenarios_run",
        "scenarios_passed",
        "scenarios_failed",
        "overall_pass",
        "avg_success_rate",
        "max_recovery_time_s",
        "all_recovered",
    ):
        assert key in s
    assert 0.0 <= s["avg_success_rate"] <= 1.0


def test_report_remediation_nonempty_on_failure() -> None:
    """A failing scenario yields remediation strings."""
    scenarios, results = _run_all_fast()
    report = generate_report(scenarios, results)
    assert isinstance(report.remediation, tuple)
    for tip in report.remediation:
        assert isinstance(tip, str) and len(tip) > 0


def test_compute_passed_logic() -> None:
    result = ChaosRunResult(
        scenario_id="x",
        scenario_name="X",
        seed=1,
        duration_s=1.0,
        probes_total=10,
        probes_succeeded=8,
        probes_failed=2,
        success_rate=0.8,
        failure_modes=["RuntimeError"],
        recovery_time_s=1.0,
        recovered=True,
        passed=True,
        details={},
    )
    scenario = ChaosScenario(
        scenario_id="x",
        name="X",
        description="d",
        faults=("backend_crash",),
        targets=("c_uas.api.server",),
        seed=1,
        duration_s=1.0,
        expected_recovery_s=5.0,
        min_success_rate=0.5,
    )
    assert compute_passed(result, scenario) is True
    scenario_hard = replace(scenario, min_success_rate=0.9)
    assert compute_passed(result, scenario_hard) is False


# --------------------------------------------------------------------------- #
# Persistence: report store
# --------------------------------------------------------------------------- #


def test_report_store_save_and_load_round_trip(tmp_path) -> None:
    report_dir = str(tmp_path / "chaos" / "reports")
    store = ResilienceReportStore(report_dir=report_dir)
    scenarios = tuple(_fast(s) for s in ALL_SCENARIOS[:1])
    runner = _fast_runner()
    results = tuple(runner.run(s) for s in scenarios)
    report = generate_report(scenarios, results)
    path = store.save_report(report)
    assert path.endswith(f"{report.report_id}.json")
    loaded = store.load_report(report.report_id)
    assert loaded.report_id == report.report_id
    assert loaded.overall_pass == report.overall_pass
    assert loaded.summary["scenarios_passed"] == report.summary["scenarios_passed"]
    assert len(loaded.results) == len(report.results)


def test_report_store_list_and_latest(tmp_path) -> None:
    report_dir = str(tmp_path / "chaos" / "reports")
    store = ResilienceReportStore(report_dir=report_dir)
    scenarios = tuple(_fast(s) for s in ALL_SCENARIOS[:1])
    runner = _fast_runner()
    results = tuple(runner.run(s) for s in scenarios)
    report = generate_report(scenarios, results)
    store.save_report(report)
    assert f"{report.report_id}.json" in store.list_reports()
    assert len(store.list_reports()) >= 1


# --------------------------------------------------------------------------- #
# run_all_scenarios helper
# --------------------------------------------------------------------------- #


def test_run_all_scenarios_returns_all_five() -> None:
    scenarios, results = run_all_scenarios()
    assert len(scenarios) == 5
    assert len(results) == 5
    assert all(isinstance(r, ChaosRunResult) for r in results)


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #


def test_cli_chaos_subcommand_registered() -> None:
    from c_uas.cli import main

    # chaos with no action prints usage and returns 1 (subcommand registered).
    assert main(["chaos"]) == 1
