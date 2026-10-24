"""``c-uas chaos`` subcommand.

Usage:
    c-uas chaos --scenario [--scenario-name X]
    c-uas chaos --run --scenario-name X
    c-uas chaos --report [--scenario-name X]
"""

from __future__ import annotations

import argparse
from typing import Any, Optional

from .report import (
    ResilienceReportStore,
    generate_report,
)
from .runner import ChaosRunner
from .scenarios import ChaosScenarioStore


def build_subparser(subparsers: Any) -> Any:
    parser = subparsers.add_parser(
        "chaos",
        help="Chaos / resilience testing: fault injection and resilience validation",
    )
    parser.add_argument(
        "--scenario",
        action="store_true",
        help="List chaos scenarios (or show one with --scenario-name)",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run a chaos scenario against the platform",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate a resilience report with pass/fail and remediation",
    )
    parser.add_argument(
        "--scenario-name",
        type=str,
        default=None,
        help="Scenario ID to run/report/show (default: all scenarios)",
    )
    return parser


def _print_scenario(store: ChaosScenarioStore, scenario_name: Optional[str]) -> int:
    if scenario_name:
        try:
            scenario = store.get_scenario(scenario_name)
        except KeyError as exc:
            print(f"[C-UAS] {exc}")
            return 1
        from dataclasses import asdict

        data = asdict(scenario)
        data["faults"] = list(data["faults"])
        data["targets"] = list(data["targets"])
        print(f"[C-UAS] Scenario: {scenario.scenario_id} — {scenario.name}")
        print(f"  Description        : {scenario.description}")
        print(f"  Faults             : {', '.join(data['faults'])}")
        print(f"  Targets            : {', '.join(data['targets'])}")
        print(f"  Seed               : {scenario.seed}")
        print(f"  Duration           : {scenario.duration_s}s")
        print(f"  Expected recovery  : {scenario.expected_recovery_s}s")
        print(f"  Min success rate   : {scenario.min_success_rate:.0%}")
        return 0
    scenarios = store.list_scenarios()
    print(f"[C-UAS] Chaos scenarios ({len(scenarios)}):")
    for s in scenarios:
        print(f"  {s.scenario_id:24s}  {s.name}  (seed={s.seed}, faults={','.join(s.faults)})")
    print("  Use c-uas chaos --scenario --scenario-name <id> for details.")
    return 0


def _run_scenario(store: ChaosScenarioStore, scenario_name: Optional[str]) -> int:
    if not scenario_name:
        print("[C-UAS] --scenario-name required for --run")
        return 1
    try:
        scenario = store.get_scenario(scenario_name)
    except KeyError as exc:
        print(f"[C-UAS] {exc}")
        return 1
    runner = ChaosRunner()
    result = runner.run(scenario)
    ResilienceReportStore().save_result(result)
    mark = "PASS" if result.passed else "FAIL"
    print(f"[C-UAS] Chaos Run: {result.scenario_id} — {result.scenario_name}")
    print(f"  Seed              : {result.seed}")
    print(f"  Probes total      : {result.probes_total}")
    print(f"  Probes succeeded  : {result.probes_succeeded}")
    print(f"  Probes failed     : {result.probes_failed}")
    print(f"  Success rate      : {result.success_rate:.1%}")
    print(f"  Failure modes     : {', '.join(result.failure_modes) or '(none)'}")
    print(f"  Recovered         : {result.recovered}")
    print(f"  Recovery time     : {result.recovery_time_s}s")
    print(f"  Result            : {mark}")
    print(f"  Details           : {result.details}")
    return 0


def _report(store: ChaosScenarioStore, scenario_name: Optional[str]) -> int:
    scenarios = list(store.list_scenarios())
    if scenario_name:
        try:
            scenarios = [store.get_scenario(scenario_name)]
        except KeyError as exc:
            print(f"[C-UAS] {exc}")
            return 1
    scenario_tuple = tuple(scenarios)
    runner = ChaosRunner()
    results = tuple(runner.run(s) for s in scenario_tuple)
    report = generate_report(scenario_tuple, results)
    ResilienceReportStore().save_report(report)
    mark = "PASS" if report.overall_pass else "FAIL"
    print(f"[C-UAS] Resilience Report: {report.report_id}")
    print(f"  Overall           : {mark}")
    print(
        f"  Scenarios         : "
        f"{report.summary['scenarios_passed']}/{report.summary['scenarios_run']} passed"
    )
    print(f"  Avg success rate  : {report.summary['avg_success_rate']:.1%}")
    print(f"  Max recovery time : {report.summary['max_recovery_time_s']}s")
    print(f"  All recovered     : {report.summary['all_recovered']}")
    for r in results:
        mark_r = "PASS" if r.passed else "FAIL"
        print(
            f"  [{mark_r}] {r.scenario_id:24s} "
            f"success={r.success_rate:.1%} "
            f"recovery={r.recovery_time_s}s "
            f"recovered={r.recovered}"
        )
    if report.remediation:
        print("  Remediation:")
        for tip in report.remediation:
            print(f"    - {tip}")
    return 0


def chaos_main(args: argparse.Namespace) -> int:
    store = ChaosScenarioStore()
    if args.scenario:
        return _print_scenario(store, args.scenario_name)
    if args.run:
        return _run_scenario(store, args.scenario_name)
    if args.report:
        return _report(store, args.scenario_name)
    print("[C-UAS] chaos: specify --scenario, --run, or --report")
    print("  c-uas chaos --scenario")
    print("  c-uas chaos --run --scenario-name backend_failure")
    print("  c-uas chaos --report")
    return 1
