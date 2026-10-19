"""Agent eval harness for the C-UAS platform.

Systematic regression testing for the engagement scheduler, decision loop,
detection, tracking, and forensics modules. Rule-based scoring with a golden
dataset (evals/golden/dataset.yaml). Zero Nvidia API calls — pure local Python.

Usage:
    python evals/harness.py run          # run full suite
    python evals/harness.py check        # check regression vs threshold
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# Make c_uas importable when run from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from c_uas.decision.action_module import ActionModule, SystemCommand
from c_uas.decision.decision_engine import DecisionModule, ResponseStrategy, ThreatLevel
from c_uas.decision.perception import PerceptionModule
from c_uas.detection.rf_classifier import RFSignalClassifier
from c_uas.detection.spoof_detector import GNSSMeasurement, GNSSSpoofDetector
from c_uas.engagement.scheduler import DroneTrack, EngagementScheduler
from c_uas.evolution import EvolvedScheduler
from c_uas.forensics.airspace_dossier import AirspaceIntrusionDossier
from c_uas.tracking.ekf_interceptor import EKFTrajectoryPredictor


@dataclass
class EvalResult:
    test_id: str
    category: str
    passed: bool
    score: float
    latency_ms: float
    reason: str
    expected_contains: List[str]
    found_contains: List[str]


class CUASEvalHarness:
    """Rule-based agent eval harness for the C-UAS platform."""

    def __init__(self, dataset_path: str = "evals/golden/dataset.yaml"):
        self.dataset_path = Path(dataset_path)
        with open(self.dataset_path, "r", encoding="utf-8") as f:
            self.dataset = yaml.safe_load(f)
        self.results: List[EvalResult] = []

    def run(self, test_id: Optional[str] = None) -> List[EvalResult]:
        """Run the full suite or a single test by id."""
        tests = self.dataset.get("tests", [])
        if test_id:
            tests = [t for t in tests if t.get("id") == test_id]
            if not tests:
                print(f"Test {test_id} not found in dataset.")
                return []

        self.results = []
        for test in tests:
            result = self._run_test(test)
            self.results.append(result)
            status = "PASS" if result.passed else "FAIL"
            print(
                f"[{status}] {result.test_id} ({result.category}) "
                f"score={result.score:.2f} latency={result.latency_ms:.0f}ms — {result.reason}"
            )
        return self.results

    def check(self, threshold: Optional[float] = None) -> bool:
        """Check regression against threshold. Returns True if suite passes."""
        if not self.results:
            self.run()
        threshold = threshold or float(
            self.dataset.get("regression", {}).get("threshold_pass_rate", 1.0)
        )
        pass_rate = sum(1 for r in self.results if r.passed) / max(len(self.results), 1)
        ok = pass_rate >= threshold
        print(
            f"\nRegression check: pass_rate={pass_rate:.2%} "
            f"threshold={threshold:.2%} -> {'PASS' if ok else 'FAIL'}"
        )
        return ok

    def _run_test(self, test: Dict[str, Any]) -> EvalResult:
        test_id = test["id"]
        category = test["category"]
        start = time.perf_counter()
        try:
            passed, score, reason, found = self._execute(test)
        except Exception as exc:  # noqa: BLE001
            passed = False
            score = 0.0
            reason = f"exception: {exc}"
            found = []
        latency_ms = (time.perf_counter() - start) * 1000
        return EvalResult(
            test_id=test_id,
            category=category,
            passed=passed,
            score=score,
            latency_ms=latency_ms,
            reason=reason,
            expected_contains=test.get("expected_output_contains", []),
            found_contains=found,
        )

    def _execute(self, test: Dict[str, Any]) -> tuple[bool, float, str, List[str]]:
        test_id = test["id"]
        expected_contains = test.get("expected_output_contains", [])
        must_not_contain = test.get("must_not_contain", [])
        min_accuracy = float(test.get("min_accuracy", 1.0))

        # Route by category
        if category := test.get("category"):
            pass

        if test_id == "cuas-eval-001":
            res = RFSignalClassifier.classify_frequency(2450.0, 20.0)
            found = [res["protocol"], res["threat_category"]]
            ok = all(c in found for c in expected_contains)
        elif test_id == "cuas-eval-002":
            res = RFSignalClassifier.classify_frequency(920.0, 0.5)
            found = [res["protocol"], res["threat_category"]]
            ok = all(c in found for c in expected_contains)
        elif test_id == "cuas-eval-003":
            res = RFSignalClassifier.classify_frequency(5000.0, 10.0)
            found = [res["protocol"], res["threat_category"]]
            ok = all(c in found for c in expected_contains)
        elif test_id == "cuas-eval-004":
            det = GNSSSpoofDetector()
            m = GNSSMeasurement(42.0, 10.0, 0.05, 10)
            r = det.evaluate_telemetry(m)
            found = [r["threat_level"], f"spoof_detected: {r['spoof_detected']}"]
            ok = all(c in found for c in expected_contains)
        elif test_id == "cuas-eval-005":
            det = GNSSSpoofDetector()
            m = GNSSMeasurement(60.0, 0.0, 3.8, 2)
            r = det.evaluate_telemetry(m)
            found = [r["threat_level"], f"spoof_detected: {r['spoof_detected']}"]
            ok = all(c in found for c in expected_contains)
        elif test_id == "cuas-eval-006":
            ekf = EKFTrajectoryPredictor(dt=0.1)
            for i in range(15):
                ekf.update_measurement(10.0 + i * 2.0, 0.0, 100.0)
            pred = ekf.predict_intercept(1.0)
            found = ["predict_intercept"]
            ok = pred[0] > ekf.state.x
        elif test_id == "cuas-eval-007":
            sched = EngagementScheduler(dwell_s=2.0, slew_s=0.5)
            plan = sched.schedule(num_drones=5, time_limit_s=60.0)
            found = [
                "expected_kills",
                "engaged_targets",
                "leaked_targets",
                "sequence",
            ]
            ok = all(
                c in str(plan.__dict__) for c in expected_contains
            ) and plan.engaged_targets <= 5
        elif test_id == "cuas-eval-008":
            sched = EngagementScheduler(dwell_s=4.0, slew_s=1.5)
            plan = sched.schedule(num_drones=4, time_limit_s=10.0)
            found = ["engaged_targets", "leaked_targets"]
            ok = plan.engaged_targets + plan.leaked_targets == 4
        elif test_id == "cuas-eval-009":
            dossier = AirspaceIntrusionDossier.generate_signed_dossier(
                target_id="UAV-ROGUE-01",
                protocol="DJI_OCUSYNC_4",
                threat_level="CRITICAL",
                coordinates_path=[{"x": 100.0, "y": 200.0, "z": 50.0}],
                rf_anomalies=["SPOOFED_BROADCAST_ID"],
            )
            found = [
                dossier["admissibility"],
                dossier["signature"][:16],
                dossier["dossier_id"],
                dossier["tamper_evident_hash"],
            ]
            ok = dossier["admissibility"] == "LEGAL_DEFENSE_GRADE"
        elif test_id == "cuas-eval-010":
            dm = DecisionModule({})
            # NONE -> MONITOR
            class SwarmNone:
                num_drones = 0
                controller_location = None
            s_none = dm.select_strategy(dm.assess_threat(SwarmNone()), SwarmNone())
            # CRITICAL -> FULL_COUNTERMEASURE
            class SwarmCrit:
                num_drones = 25
                controller_location = None
            s_crit = dm.select_strategy(dm.assess_threat(SwarmCrit()), SwarmCrit())
            # Unauthorized jammer -> denied
            am = ActionModule({"jamming": {"authorized": False}}, simulation_mode=True)
            import asyncio

            jam = asyncio.run(
                am.execute(
                    SystemCommand(
                        action="activate_jammer",
                        params={"bands": [2.44e9], "power_dBm": 20},
                        timestamp=0.0,
                        priority=3,
                    )
                )
            )
            found = [s_none.value, s_crit.value, jam["status"], jam["details"]["reason"]]
            ok = (
                s_none == ResponseStrategy.MONITOR
                and s_crit == ResponseStrategy.FULL_COUNTERMEASURE
                and jam["status"] == "denied"
            )
        elif test_id == "cuas-eval-011":
            am = ActionModule({"jamming": {"authorized": False}}, simulation_mode=True)
            import asyncio

            jam = asyncio.run(
                am.execute(
                    SystemCommand(
                        action="activate_jammer",
                        params={"bands": [2.44e9], "power_dBm": 20},
                        timestamp=0.0,
                        priority=3,
                    )
                )
            )
            found = [jam["status"], jam["details"]["reason"]]
            ok = jam["status"] == "denied" and "jammer_activated" not in str(jam)
        elif test_id == "cuas-eval-012":
            es = EvolvedScheduler(
                population_size=4,
                generations=3,
                mutation_rate=0.3,
                elitism_count=1,
                dwell_s=4.0,
                slew_s=1.5,
                num_drones=6,
                time_limit_s=30.0,
                seed=42,
            )
            result = es.evolve()
            found = [
                "best_params",
                "best_fitness",
                "generations_run",
                "fitness_history",
            ]
            history = result["fitness_history"]
            ok = (
                result["best_fitness"] >= 0.0
                and len(history) == 3
                and all(history[i] >= history[i - 1] - 1e-9 for i in range(1, len(history)))
            )
        elif test_id == "cuas-eval-013":
            from c_uas.dew.beam_model import DewBeamQualityModel

            bqm = DewBeamQualityModel()
            f_good = bqm.fluence_factor(m2=1.1, jitter_urad=5.0, range_m=3000.0)
            f_bad = bqm.fluence_factor(m2=2.0, jitter_urad=15.0, range_m=3000.0)
            found = ["fluence_factor"]
            ok = f_good > f_bad
        elif test_id == "cuas-eval-014":
            from c_uas.dew.beam_model import DewThermalBloomModel

            tbm = DewThermalBloomModel()
            p_cross = tbm.penalty(continuous_fire_s=10.0, geometry="crossing")
            p_headon = tbm.penalty(continuous_fire_s=10.0, geometry="head_on")
            found = ["penalty"]
            ok = p_headon >= p_cross and p_headon > tbm.penalty(continuous_fire_s=1.0)
        elif test_id == "cuas-eval-015":
            from c_uas.dew.time_to_kill import TimeToKillModel

            ttk = TimeToKillModel()
            t1 = ttk.time_to_kill_s(laser_power_kw=50.0, target_material="aluminum", range_m=3000.0)
            t2 = ttk.time_to_kill_s(laser_power_kw=100.0, target_material="aluminum", range_m=3000.0)
            found = ["time_to_kill_s"]
            ok = t2 < t1 and t1 > 0.0
        else:
            return False, 0.0, f"unknown test {test_id}", []

        # must_not_contain check
        for phrase in must_not_contain:
            if phrase.lower() in " ".join(found).lower():
                ok = False
                reason = f"forbidden phrase present: {phrase}"
                return ok, 0.0, reason, found

        score = 1.0 if ok else 0.0
        reason = "all assertions passed" if ok else "assertion failed"
        return ok, score, reason, found


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="C-UAS Agent Eval Harness")
    parser.add_argument("command", choices=["run", "check"], help="run suite or check regression")
    parser.add_argument("--test", help="run a single test id")
    parser.add_argument("--threshold", type=float, default=None, help="pass-rate threshold")
    args = parser.parse_args(argv)

    harness = CUASEvalHarness()
    if args.command == "run":
        harness.run(test_id=args.test)
    elif args.command == "check":
        ok = harness.check(threshold=args.threshold)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
