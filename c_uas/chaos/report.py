"""Chaos resilience report generation.

Produces a resilience test report with pass/fail per scenario, recovery time,
and remediation recommendations. Report state persists under
~/.c-uas-platform/chaos/reports/ (outside the repo).

Deterministic: the report ID is a content hash of the scenario results, so
re-running the same scenarios yields the same report ID.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Tuple

from .runner import ChaosRunner, ChaosRunResult
from .scenarios import ALL_SCENARIOS, ChaosScenario

REPORT_DIR = os.path.join(
    os.path.expanduser("~"), ".c-uas-platform", "chaos", "reports"
)
LATEST_PATH = os.path.join(
    os.path.expanduser("~"), ".c-uas-platform", "chaos", "latest_report.json"
)

# Remediation guidance keyed by failure mode. Deterministic, defensive-only.
REMEDIATION = {
    "crash": (
        "Add restart supervision (systemd/kubernetes liveness probe) so a "
        "crashed backend is replaced automatically; circuit-break callers so "
        "a failing backend does not cascade to dependent components."
    ),
    "timeout": (
        "Enforce client-side timeouts on every outbound call, retry with "
        "exponential backoff and jitter, and surface timeout errors as 503 "
        "rather than hanging the request thread."
    ),
    "latency": (
        "Add request timeouts and bulkheads per dependency so a slow backend "
        "cannot exhaust the thread pool; monitor p99 latency and alert on "
        "regression."
    ),
    "loss": (
        "Retry idempotent requests on transient loss, add health checks that "
        "detect unidirectional links, and fail closed when loss exceeds the "
        "configured threshold."
    ),
    "memory": (
        "Set container memory limits and OOM kill policies, add memory "
        "pressure alerts, and shed load (reject new requests) when memory "
        "approaches the limit instead of degrading silently."
    ),
}

REMEDIATION_BY_SCENARIO = {
    "backend_failure": (
        "Deploy the backend behind a load balancer with active health checks "
        "and automatic restart; drain in-flight requests on shutdown."
    ),
    "network_partition": (
        "Use timeouts and retries on all client calls, prefer local cache/"
        "degraded mode during partitions, and alert when partition duration "
        "exceeds the recovery budget."
    ),
    "api_timeout": (
        "Cap every API call with a deadline, return 504 on timeout, and trace "
        "slow dependencies so the offending service is identified quickly."
    ),
    "cascade_failure": (
        "Isolate failure domains with bulkheads and circuit breakers so one "
        "failing component cannot exhaust shared threads, connections, or "
        "memory across the platform."
    ),
    "partial_outage": (
        "Maintain a success-rate SLO per component, route around unhealthy "
        "endpoints, and alert when success rate drops below min_success_rate."
    ),
}


def sid_lookup(scenario_id: str, scenarios: Tuple[ChaosScenario, ...]) -> ChaosScenario:
    for s in scenarios:
        if s.scenario_id == scenario_id:
            return s
    raise KeyError(f"Unknown scenario: {scenario_id}")


def compute_passed(result: ChaosRunResult, scenario: ChaosScenario) -> bool:
    """Pass/fail for one scenario result against its thresholds."""
    return (
        result.success_rate >= scenario.min_success_rate
        and result.recovered
        and result.recovery_time_s <= scenario.expected_recovery_s
    )


def _remediation_for(result: ChaosRunResult, scenario: ChaosScenario) -> List[str]:
    """Deterministic remediation strings for the scenario's failures."""
    tips: List[str] = []
    if not result.recovered or result.recovery_time_s > scenario.expected_recovery_s:
        tips.append(
            "Recovery exceeded budget: add automated restart and health checks "
            "for the affected component."
        )
    if result.success_rate < scenario.min_success_rate:
        tips.append(REMEDIATION.get("loss", "Improve success rate under fault."))
    for mode in result.failure_modes:
        key = mode.lower()
        if key in REMEDIATION:
            tips.append(REMEDIATION[key])
    scenario_tip = REMEDIATION_BY_SCENARIO.get(scenario.scenario_id)
    if scenario_tip:
        tips.append(scenario_tip)
    return tips


@dataclass(frozen=True)
class ResilienceReport:
    """Resilience test report with pass/fail per scenario."""

    report_id: str
    generated_at: float
    scenario_ids: Tuple[str, ...]
    results: Tuple[ChaosRunResult, ...]
    overall_pass: bool
    summary: Dict[str, Any]
    remediation: Tuple[str, ...]


def generate_report(
    scenarios: Tuple[ChaosScenario, ...],
    results: Tuple[ChaosRunResult, ...],
) -> ResilienceReport:
    """Build a ResilienceReport from scenario results (pure computation)."""
    result_by_id = {r.scenario_id: r for r in results}
    passed_flags = [
        compute_passed(result_by_id[sid], sid_lookup(sid, scenarios))
        for sid in result_by_id
    ]
    overall_pass = bool(passed_flags) and all(passed_flags)

    success_rates = [result_by_id[sid].success_rate for sid in result_by_id]
    recovery_times = [result_by_id[sid].recovery_time_s for sid in result_by_id]

    summary: Dict[str, Any] = {
        "scenarios_run": len(results),
        "scenarios_passed": sum(1 for f in passed_flags if f),
        "scenarios_failed": sum(1 for f in passed_flags if not f),
        "overall_pass": overall_pass,
        "avg_success_rate": round(sum(success_rates) / len(success_rates), 4)
        if success_rates
        else 0.0,
        "max_recovery_time_s": round(max(recovery_times), 4)
        if recovery_times
        else 0.0,
        "all_recovered": all(result_by_id[sid].recovered for sid in result_by_id)
        if result_by_id
        else False,
    }

    remediation: List[str] = []
    for sid in sorted(result_by_id):
        result = result_by_id[sid]
        scenario = sid_lookup(sid, scenarios)
        if not compute_passed(result, scenario):
            remediation.extend(_remediation_for(result, scenario))

    seen = set()
    deduped: List[str] = []
    for tip in remediation:
        if tip not in seen:
            seen.add(tip)
            deduped.append(tip)

    report_id = (
        "CHAOS-"
        + hashlib.sha256(
            json.dumps(
                [
                    {
                        "scenario_id": r.scenario_id,
                        "success_rate": r.success_rate,
                        "recovery_time_s": r.recovery_time_s,
                        "recovered": r.recovered,
                        "passed": r.passed,
                    }
                    for r in sorted(results, key=lambda x: x.scenario_id)
                ],
                sort_keys=True,
            ).encode()
        ).hexdigest()[:16]
    )

    return ResilienceReport(
        report_id=report_id,
        generated_at=time.time(),
        scenario_ids=tuple(sorted(result_by_id)),
        results=results,
        overall_pass=overall_pass,
        summary=summary,
        remediation=tuple(deduped),
    )


class ResilienceReportStore:
    """Save/load reports under ~/.c-uas-platform/chaos/reports/."""

    def __init__(self, report_dir: str = REPORT_DIR) -> None:
        self.dir = report_dir

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def save_result(self, result: ChaosRunResult) -> str:
        results_dir = os.path.join(os.path.dirname(self.dir), "results")
        os.makedirs(results_dir, exist_ok=True)
        path = os.path.join(results_dir, f"{result.scenario_id}-{result.seed}.json")
        with open(path, "w") as fh:
            json.dump(asdict(result), fh, indent=2)
        return path

    def save_report(self, report: ResilienceReport) -> str:
        self.ensure_dir()
        path = os.path.join(self.dir, f"{report.report_id}.json")
        serializable = asdict(report)
        serializable["results"] = [asdict(r) for r in report.results]
        with open(path, "w") as fh:
            json.dump(serializable, fh, indent=2)
        with open(LATEST_PATH, "w") as fh:
            json.dump(
                {
                    "report_id": report.report_id,
                    "generated_at": report.generated_at,
                    "overall_pass": report.overall_pass,
                    "summary": report.summary,
                    "path": path,
                },
                fh,
                indent=2,
            )
        return path

    def list_reports(self) -> List[str]:
        if not os.path.isdir(self.dir):
            return []
        return sorted(f for f in os.listdir(self.dir) if f.endswith(".json"))

    def load_report(self, report_id: str) -> ResilienceReport:
        path = os.path.join(self.dir, f"{report_id}.json")
        if not os.path.exists(path):
            raise KeyError(f"Unknown report: {report_id}")
        with open(path) as fh:
            data = json.load(fh)
        results = tuple(
            ChaosRunResult(
                scenario_id=r["scenario_id"],
                scenario_name=r["scenario_name"],
                seed=r["seed"],
                duration_s=r["duration_s"],
                probes_total=r["probes_total"],
                probes_succeeded=r["probes_succeeded"],
                probes_failed=r["probes_failed"],
                success_rate=r["success_rate"],
                failure_modes=r["failure_modes"],
                recovery_time_s=r["recovery_time_s"],
                recovered=r["recovered"],
                passed=r["passed"],
                details=r["details"],
            )
            for r in data["results"]
        )
        return ResilienceReport(
            report_id=data["report_id"],
            generated_at=data["generated_at"],
            scenario_ids=tuple(data["scenario_ids"]),
            results=results,
            overall_pass=data["overall_pass"],
            summary=data["summary"],
            remediation=tuple(data["remediation"]),
        )


def run_all_scenarios() -> Tuple[Tuple[ChaosScenario, ...], Tuple[ChaosRunResult, ...]]:
    """Run every registered chaos scenario deterministically."""
    scenarios = ALL_SCENARIOS
    runner = ChaosRunner()
    results = tuple(runner.run(s) for s in scenarios)
    return scenarios, results
