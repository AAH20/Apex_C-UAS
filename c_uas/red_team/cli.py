"""CLI entry point for the red team adversarial testing framework.

Usage:
    c-uas red-team --scenario [--scenario-name X]
    c-uas red-team --run --scenario-name X
    c-uas red-team --report [--scenario-name X]
"""

from __future__ import annotations

import argparse
from typing import Any, Optional

from .attack_simulator import AttackSimulator
from .report import ReportStore, generate_report
from .scenarios import ScenarioStore


def build_subparser(subparsers: Any) -> Any:
    parser = subparsers.add_parser(
        "red-team",
        help="Red team adversarial testing framework (GNSS spoofing, RF jamming, "
        "swarm saturation, coordinated attacks, controller hijacking)",
    )
    parser.add_argument(
        "--scenario",
        action="store_true",
        help="List adversarial scenarios (or show one with --scenario-name)",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run an adversarial scenario against the platform",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate an adversarial test report with pass/fail and remediation",
    )
    parser.add_argument(
        "--scenario-name",
        type=str,
        default=None,
        help="Scenario ID to run/report/show (default: all scenarios)",
    )
    return parser


def _print_scenario(store: ScenarioStore, scenario_name: Optional[str]) -> int:
    if scenario_name:
        try:
            scenario = store.get_scenario(scenario_name)
        except KeyError as exc:
            print(f"[C-UAS] {exc}")
            return 1
        from dataclasses import asdict

        data = asdict(scenario)
        data["attack_vectors"] = list(data["attack_vectors"])
        data["target_modules"] = list(data["target_modules"])
        print(f"[C-UAS] Scenario: {scenario.scenario_id} — {scenario.name}")
        print(f"  Description     : {scenario.description}")
        print(f"  Attack vectors  : {', '.join(data['attack_vectors'])}")
        print(f"  Target modules  : {', '.join(data['target_modules'])}")
        print(f"  Seed            : {scenario.seed}")
        print(f"  Expected detect : {scenario.expected_detection_rate:.0%}")
        print(f"  Max leak rate   : {scenario.max_acceptable_leak_rate:.0%}")
        print(f"  Max false pos.  : {scenario.max_acceptable_false_positive_rate:.0%}")
        print(f"  Params          : {data['params']}")
        return 0
    scenarios = store.list_scenarios()
    print(f"[C-UAS] Adversarial scenarios ({len(scenarios)}):")
    for s in scenarios:
        print(
            f"  {s.scenario_id:30s}  {s.name}  (seed={s.seed}, "
            f"modules={','.join(s.target_modules)})"
        )
    print("  Use c-uas red-team --scenario --scenario-name <id> for details.")
    return 0


def _run_scenario(store: ScenarioStore, scenario_name: Optional[str]) -> int:
    if not scenario_name:
        print("[C-UAS] --scenario-name required for --run")
        return 1
    try:
        scenario = store.get_scenario(scenario_name)
    except KeyError as exc:
        print(f"[C-UAS] {exc}")
        return 1
    sim = AttackSimulator()
    result = sim.run(scenario)
    ReportStore().save_result(result)
    print(f"[C-UAS] Red Team Run: {result.scenario_id} — {result.scenario_name}")
    print(f"  Seed              : {result.seed}")
    print(f"  Detection rate    : {result.detection_rate:.1%}")
    print(f"  False positive rate: {result.false_positive_rate:.1%}")
    print(f"  Engagement success: {result.engagement_success:.1%}")
    print(f"  Leak rate         : {result.leak_rate:.1%}")
    print(f"  Result            : {'PASS' if result.passed else 'FAIL'}")
    print(f"  Details           : {result.details}")
    return 0


def _report(store: ScenarioStore, scenario_name: Optional[str]) -> int:
    scenarios = list(store.list_scenarios())
    if scenario_name:
        try:
            scenarios = [store.get_scenario(scenario_name)]
        except KeyError as exc:
            print(f"[C-UAS] {exc}")
            return 1
    scenario_tuple = tuple(scenarios)
    sim = AttackSimulator()
    results = tuple(sim.run(s) for s in scenario_tuple)
    report = generate_report(scenario_tuple, results)
    ReportStore().save_report(report)
    print(f"[C-UAS] Red Team Report: {report.report_id}")
    print(f"  Overall           : {'PASS' if report.overall_pass else 'FAIL'}")
    print(
        f"  Scenarios         : {report.summary['scenarios_passed']}/{report.summary['scenarios_run']} passed"
    )
    print(f"  Avg detection     : {report.summary['avg_detection_rate']:.1%}")
    print(f"  Max leak rate     : {report.summary['max_leak_rate']:.1%}")
    print(f"  Max false positive: {report.summary['max_false_positive_rate']:.1%}")
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        print(
            f"  [{mark}] {r.scenario_id:30s} detect={r.detection_rate:.1%} "
            f"fpr={r.false_positive_rate:.1%} leak={r.leak_rate:.1%}"
        )
    if report.remediation:
        print("  Remediation:")
        for tip in report.remediation:
            print(f"    - {tip}")
    return 0


def red_team_main(args: argparse.Namespace) -> int:
    store = ScenarioStore()
    if args.scenario:
        return _print_scenario(store, args.scenario_name)
    if args.run:
        return _run_scenario(store, args.scenario_name)
    if args.report:
        return _report(store, args.scenario_name)
    print("[C-UAS] red-team: specify --scenario, --run, or --report")
    print("  c-uas red-team --scenario")
    print("  c-uas red-team --run --scenario-name gnss_spoofing")
    print("  c-uas red-team --report")
    return 1
