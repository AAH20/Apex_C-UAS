"""
Red Team report generation.

Produces an adversarial test report with pass/fail per scenario and
remediation recommendations. Report state persists under
~/.c-uas-platform/red_team/reports/ (outside the repo).

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

from .attack_simulator import AttackSimulator
from .scenarios import ALL_SCENARIOS, Scenario, ScenarioResult

REPORT_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "red_team", "reports")
LATEST_PATH = os.path.join(
    os.path.expanduser("~"), ".c-uas-platform", "red_team", "latest_report.json"
)

# Remediation guidance keyed by failure mode. Deterministic, defensive-only.
REMEDIATION = {
    "detection": (
        "Improve detection coverage for this attack vector: tune detector "
        "thresholds, add a redundant sensor modality (RF, GNSS, EO/IR), and "
        "require multi-flag confirmation before alerting to cut false positives."
    ),
    "leak": (
        "Reduce engagement leak under saturation: add beam directors, reduce "
        "dwell/slew time, prioritize targets by threat level and Pk-per-second, "
        "and pre-stage engagement windows for high-density swarm arrivals."
    ),
    "false_positive": (
        "Reduce false positives: raise anomaly thresholds, require "
        "corroboration across two sensor modalities, and add a confirmation "
        "dwell before escalating to countermeasure actions."
    ),
}

REMEDIATION_BY_SCENARIO = {
    "gnss_spoofing": (
        "Harden GNSS reception: dual-constellation receivers, RAIM/FD-CH "
        "consistency checks, and C/N0 anomaly rate-of-change alarms; correlate "
        "spoof alerts with RF direction finding before engaging."
    ),
    "gnss_meaconing": (
        "Add GNSS signal-delay / meaconing detection: compare receiver time of "
        "arrival across antennas, flag elevated C/N0 with abrupt clock-drift "
        "steps, and use authenticated navigation messages."
    ),
    "gnss_replay": (
        "Reject replayed GNSS constellations: validate ephemeris freshness, "
        "detect satellite-count collapse, and cross-check pseudorange rates "
        "against an inertial solution."
    ),
    "rf_jamming": (
        "Add jam detection on the noise floor, frequency-agile control links, "
        "and directional null-steering; alert when the jam band overlaps active "
        "drone control frequencies."
    ),
    "rf_jamming_barrage": (
        "Detect wideband noise barrages on the RF noise floor and switch to "
        "frequency-agile or directional links before control is lost."
    ),
    "rf_jamming_deceptive": (
        "Reject protocol-mimicking emissions inside the drone band: require "
        "cryptographic binding of RF fingerprint to protocol ID and alert on "
        "unexpected protocol transitions."
    ),
    "swarm_saturation": (
        "Increase engagement throughput: additional directors, shorter dwell, "
        "predictive scheduling before drone arrival deadlines, and swarm "
        "triage rules that sacrifice low-priority tracks to protect critical "
        "assets."
    ),
    "coordinated_multi_vector": (
        "Treat simultaneous vectors as CRITICAL: full countermeasure posture, "
        "multi-site track fusion, automated controller geolocation, and "
        "pre-authorized escalation paths so the decision loop is not the "
        "bottleneck during coordinated attacks."
    ),
    "controller_hijacking": (
        "Enforce MAVLink v2 message signing with SECRET_KEY HMAC validation, "
        "reject unsigned COMMAND_LONG/SET_PARAMETER/MISSION_ITEM, and geolocate "
        "the controller via multi-station direction finding for forensic "
        "referral."
    ),
    "mavlink_injection": (
        "Require signed MAVLink commands, reject all-zeros signature fields, "
        "and correlate unsigned COMMAND_LONG traffic with the MAV-2017-001 "
        "signing-bypass weakness for controller referral."
    ),
    "identity_spoofing": (
        "Bind drone identities to RF fingerprints and require authenticated "
        "Remote ID / system ID; alert on ID mismatches, missing authentication, "
        "or unexpected system IDs on the control link."
    ),
    "man_in_the_middle": (
        "Detect MITM via certificate/auth mismatch, round-trip timing "
        "anomalies, and duplicated sequence numbers; require mutual "
        "authentication on controller-to-drone links."
    ),
}


def sid_lookup(scenario_id: str, scenarios: Tuple[Scenario, ...]) -> Scenario:
    for s in scenarios:
        if s.scenario_id == scenario_id:
            return s
    raise KeyError(f"Unknown scenario: {scenario_id}")


def compute_passed(result: ScenarioResult, scenario: Scenario) -> bool:
    """Pass/fail for one scenario result against its thresholds."""
    return (
        result.detection_rate >= scenario.expected_detection_rate
        and result.leak_rate <= scenario.max_acceptable_leak_rate
        and result.false_positive_rate <= scenario.max_acceptable_false_positive_rate
    )


def _remediation_for(result: ScenarioResult, scenario: Scenario) -> List[str]:
    """Deterministic remediation strings for the scenario's failures."""
    tips: List[str] = []
    if result.detection_rate < scenario.expected_detection_rate:
        tips.append(REMEDIATION["detection"])
    if result.leak_rate > scenario.max_acceptable_leak_rate:
        tips.append(REMEDIATION["leak"])
    if result.false_positive_rate > scenario.max_acceptable_false_positive_rate:
        tips.append(REMEDIATION["false_positive"])
    scenario_tip = REMEDIATION_BY_SCENARIO.get(scenario.scenario_id)
    if scenario_tip:
        tips.append(scenario_tip)
    return tips


@dataclass(frozen=True)
class RedTeamReport:
    """Adversarial test report with pass/fail per scenario."""

    report_id: str
    generated_at: float
    scenario_ids: Tuple[str, ...]
    results: Tuple[ScenarioResult, ...]
    overall_pass: bool
    summary: Dict[str, Any]
    remediation: Tuple[str, ...]


def generate_report(
    scenarios: Tuple[Scenario, ...],
    results: Tuple[ScenarioResult, ...],
) -> RedTeamReport:
    """Build a RedTeamReport from scenario results (pure computation)."""
    result_by_id = {r.scenario_id: r for r in results}
    passed_flags = [
        compute_passed(result_by_id[sid], sid_lookup(sid, scenarios)) for sid in result_by_id
    ]
    overall_pass = bool(passed_flags) and all(passed_flags)

    detection_rates = [result_by_id[sid].detection_rate for sid in result_by_id]
    leak_rates = [result_by_id[sid].leak_rate for sid in result_by_id]
    fprs = [result_by_id[sid].false_positive_rate for sid in result_by_id]

    summary: Dict[str, Any] = {
        "scenarios_run": len(results),
        "scenarios_passed": sum(1 for f in passed_flags if f),
        "scenarios_failed": sum(1 for f in passed_flags if not f),
        "overall_pass": overall_pass,
        "avg_detection_rate": round(sum(detection_rates) / len(detection_rates), 4)
        if detection_rates
        else 0.0,
        "max_leak_rate": round(max(leak_rates), 4) if leak_rates else 0.0,
        "max_false_positive_rate": round(max(fprs), 4) if fprs else 0.0,
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
        "RT-"
        + hashlib.sha256(
            json.dumps(
                [
                    {
                        "scenario_id": r.scenario_id,
                        "detection_rate": r.detection_rate,
                        "leak_rate": r.leak_rate,
                        "false_positive_rate": r.false_positive_rate,
                        "passed": r.passed,
                    }
                    for r in sorted(results, key=lambda x: x.scenario_id)
                ],
                sort_keys=True,
            ).encode()
        ).hexdigest()[:16]
    )

    return RedTeamReport(
        report_id=report_id,
        generated_at=time.time(),
        scenario_ids=tuple(sorted(result_by_id)),
        results=results,
        overall_pass=overall_pass,
        summary=summary,
        remediation=tuple(deduped),
    )


class ReportStore:
    """Save/load reports under ~/.c-uas-platform/red_team/reports/."""

    def __init__(self, report_dir: str = REPORT_DIR) -> None:
        self.dir = report_dir

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def save_result(self, result: ScenarioResult) -> str:
        results_dir = os.path.join(os.path.dirname(self.dir), "results")
        os.makedirs(results_dir, exist_ok=True)
        path = os.path.join(results_dir, f"{result.scenario_id}-{result.seed}.json")
        with open(path, "w") as fh:
            json.dump(asdict(result), fh, indent=2)
        return path

    def save_report(self, report: RedTeamReport) -> str:
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

    def load_report(self, report_id: str) -> RedTeamReport:
        path = os.path.join(self.dir, f"{report_id}.json")
        if not os.path.exists(path):
            raise KeyError(f"Unknown report: {report_id}")
        with open(path) as fh:
            data = json.load(fh)
        results = tuple(
            ScenarioResult(
                scenario_id=r["scenario_id"],
                scenario_name=r["scenario_name"],
                seed=r["seed"],
                detection_rate=r["detection_rate"],
                false_positive_rate=r["false_positive_rate"],
                engagement_success=r["engagement_success"],
                leak_rate=r["leak_rate"],
                passed=r["passed"],
                details=r["details"],
                evidence=tuple(r.get("evidence", [])),
            )
            for r in data["results"]
        )
        return RedTeamReport(
            report_id=data["report_id"],
            generated_at=data["generated_at"],
            scenario_ids=tuple(data["scenario_ids"]),
            results=results,
            overall_pass=data["overall_pass"],
            summary=data["summary"],
            remediation=tuple(data["remediation"]),
        )


def run_all_scenarios() -> Tuple[Tuple[Scenario, ...], Tuple[ScenarioResult, ...]]:
    """Run every registered scenario deterministically."""
    scenarios = ALL_SCENARIOS
    sim = AttackSimulator()
    results = tuple(sim.run(s) for s in scenarios)
    return scenarios, results
