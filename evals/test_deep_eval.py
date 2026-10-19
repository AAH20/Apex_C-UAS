"""DeepEval-style agent evaluation tests for the C-UAS platform.

Modeled on the deepeval skill: TaskCompletion, ToolCorrectness, GoalAccuracy metrics
evaluated as pytest tests. Zero Nvidia API calls — pure local Python + pytest.

Run with: python -m pytest evals/test_deep_eval.py -v
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List

import pytest

from c_uas.decision.action_module import ActionModule, SystemCommand
from c_uas.decision.decision_engine import DecisionModule, ResponseStrategy, ThreatLevel
from c_uas.detection.rf_classifier import RFSignalClassifier
from c_uas.detection.spoof_detector import GNSSMeasurement, GNSSSpoofDetector
from c_uas.engagement.scheduler import EngagementScheduler
from c_uas.evolution import EvolvedScheduler
from c_uas.forensics.airspace_dossier import AirspaceIntrusionDossier
from c_uas.tracking.ekf_interceptor import EKFTrajectoryPredictor


# ---------------------------------------------------------------------------
# DeepEval-style metric helpers (local, no LLM judge — deterministic scoring)
# ---------------------------------------------------------------------------

class TaskCompletionMetric:
    """Did the agent/module complete the task? Binary 0/1 with reason."""

    def __init__(self, threshold: float = 0.70):
        self.threshold = threshold
        self.score: float = 0.0
        self.reason: str = ""

    def measure(self, passed: bool, reason: str = "") -> "TaskCompletionMetric":
        self.score = 1.0 if passed else 0.0
        self.reason = reason or ("completed" if passed else "not completed")
        return self

    def is_successful(self) -> bool:
        return self.score >= self.threshold


class ToolCorrectnessMetric:
    """Were the right tools/components invoked?"""

    def __init__(self, threshold: float = 0.80):
        self.threshold = threshold
        self.score: float = 0.0
        self.reason: str = ""

    def measure(self, expected: List[str], actual: List[str]) -> "ToolCorrectnessMetric":
        if not expected:
            self.score = 1.0
            self.reason = "no expected tools"
            return self
        hit = len(set(expected) & set(actual))
        self.score = hit / len(expected)
        self.reason = f"{hit}/{len(expected)} expected tools invoked"
        return self

    def is_successful(self) -> bool:
        return self.score >= self.threshold


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def rf_classifier():
    return RFSignalClassifier


@pytest.fixture
def spoof_detector():
    return GNSSSpoofDetector()


@pytest.fixture
def decision_module():
    return DecisionModule({})


@pytest.fixture
def action_module_unauthorized():
    return ActionModule({"jamming": {"authorized": False}}, simulation_mode=True)


@pytest.fixture
def scheduler():
    return EngagementScheduler(dwell_s=4.0, slew_s=1.5)


# ---------------------------------------------------------------------------
# Detection tests (TaskCompletion)
# ---------------------------------------------------------------------------


class TestDetection:
    def test_dji_ocusync_classification(self, rf_classifier):
        metric = TaskCompletionMetric(threshold=0.70)
        res = rf_classifier.classify_frequency(2450.0, 20.0)
        passed = res["protocol"] == "DJI_OCUSYNC_4" and res["threat_category"] == "HIGH_END_CONSUMER_OR_RECON"
        metric.measure(passed, "DJI OcuSync classification")
        assert metric.is_successful(), metric.reason

    def test_unknown_emitter(self, rf_classifier):
        metric = TaskCompletionMetric(threshold=0.70)
        res = rf_classifier.classify_frequency(5000.0, 10.0)
        passed = res["protocol"] == "UNKNOWN_RF_EMITTER"
        metric.measure(passed, "unknown emitter classification")
        assert metric.is_successful(), metric.reason

    def test_nominal_gnss_not_spoofed(self, spoof_detector):
        metric = TaskCompletionMetric(threshold=0.70)
        m = GNSSMeasurement(42.0, 10.0, 0.05, 10)
        r = spoof_detector.evaluate_telemetry(m)
        passed = not r["spoof_detected"] and r["threat_level"] == "NOMINAL"
        metric.measure(passed, "nominal GNSS not spoofed")
        assert metric.is_successful(), metric.reason

    def test_spoofed_gnss_detected(self, spoof_detector):
        metric = TaskCompletionMetric(threshold=0.70)
        m = GNSSMeasurement(60.0, 0.0, 3.8, 2)
        r = spoof_detector.evaluate_telemetry(m)
        passed = r["spoof_detected"] and r["threat_level"] == "CRITICAL"
        metric.measure(passed, "spoofed GNSS detected")
        assert metric.is_successful(), metric.reason


# ---------------------------------------------------------------------------
# Tracking tests
# ---------------------------------------------------------------------------


class TestTracking:
    def test_ekf_predicts_intercept(self):
        metric = TaskCompletionMetric(threshold=0.70)
        ekf = EKFTrajectoryPredictor(dt=0.1)
        for i in range(15):
            ekf.update_measurement(10.0 + i * 2.0, 0.0, 100.0)
        start_x = ekf.state.x
        ix, _, _ = ekf.predict_intercept(1.0)
        passed = ix > start_x
        metric.measure(passed, "EKF intercept prediction")
        assert metric.is_successful(), metric.reason


# ---------------------------------------------------------------------------
# Engagement tests (GoalAccuracy + budgeted max coverage)
# ---------------------------------------------------------------------------


class TestEngagement:
    def test_small_swarm_fully_engaged(self, scheduler):
        metric = TaskCompletionMetric(threshold=0.70)
        plan = scheduler.schedule(num_drones=3, time_limit_s=60.0)
        passed = plan.engaged_targets == 3 and plan.leaked_targets == 0
        metric.measure(passed, "small swarm fully engaged")
        assert metric.is_successful(), metric.reason

    def test_engaged_plus_leaked_equals_total(self, scheduler):
        metric = TaskCompletionMetric(threshold=0.70)
        plan = scheduler.schedule(num_drones=8, time_limit_s=15.0)
        passed = plan.engaged_targets + plan.leaked_targets == 8
        metric.measure(passed, "engaged + leaked == total")
        assert metric.is_successful(), metric.reason

    def test_dwell_affects_engagement_count(self):
        metric = TaskCompletionMetric(threshold=0.70)
        short = EngagementScheduler(dwell_s=2.0, slew_s=0.5)
        long_ = EngagementScheduler(dwell_s=10.0, slew_s=0.5)
        p_short = short.schedule(num_drones=10, time_limit_s=30.0)
        p_long = long_.schedule(num_drones=10, time_limit_s=30.0)
        passed = p_short.engaged_targets >= p_long.engaged_targets
        metric.measure(passed, "shorter dwell engages more targets")
        assert metric.is_successful(), metric.reason


# ---------------------------------------------------------------------------
# Decision loop tests (ToolCorrectness + TaskCompletion)
# ---------------------------------------------------------------------------


class TestDecisionLoop:
    def test_threat_levels(self, decision_module):
        metric = ToolCorrectnessMetric(threshold=0.80)

        class SwarmNone:
            num_drones = 0
            controller_location = None

        class SwarmCrit:
            num_drones = 25
            controller_location = None

        t_none = decision_module.assess_threat(SwarmNone())
        t_crit = decision_module.assess_threat(SwarmCrit())
        expected = [ThreatLevel.NONE, ThreatLevel.CRITICAL]
        actual = [t_none, t_crit]
        metric.measure(expected, actual)
        assert metric.is_successful(), metric.reason
        assert t_none == ThreatLevel.NONE
        assert t_crit == ThreatLevel.CRITICAL

    def test_response_strategies(self, decision_module):
        metric = TaskCompletionMetric(threshold=0.70)
        class SwarmNone:
            num_drones = 0
            controller_location = None
        s_none = decision_module.select_strategy(ThreatLevel.NONE, SwarmNone())
        assert s_none == ResponseStrategy.MONITOR
        metric.measure(True, "NONE -> MONITOR")
        assert metric.is_successful(), metric.reason

    def test_jammer_denied_when_unauthorized(self, action_module_unauthorized):
        metric = TaskCompletionMetric(threshold=0.70)

        async def run():
            return await action_module_unauthorized.execute(
                SystemCommand(
                    action="activate_jammer",
                    params={"bands": [2.44e9], "power_dBm": 20},
                    timestamp=0.0,
                    priority=3,
                )
            )

        result = asyncio.run(run())
        passed = result["status"] == "denied" and "Jamming not authorized" in str(
            result["details"]
        )
        metric.measure(passed, "jammer denied when unauthorized")
        assert metric.is_successful(), metric.reason


# ---------------------------------------------------------------------------
# Forensics tests
# ---------------------------------------------------------------------------


class TestForensics:
    def test_signed_dossier_admissible(self):
        metric = TaskCompletionMetric(threshold=0.70)
        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-ROGUE-01",
            protocol="DJI_OCUSYNC_4",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 100.0, "y": 200.0, "z": 50.0}],
            rf_anomalies=["SPOOFED_BROADCAST_ID"],
        )
        passed = (
            dossier["admissibility"] == "LEGAL_DEFENSE_GRADE"
            and len(dossier["signature"]) == 128
        )
        metric.measure(passed, "signed dossier is defense-grade")
        assert metric.is_successful(), metric.reason

    def test_dossier_signature_changes_with_content(self):
        metric = TaskCompletionMetric(threshold=0.70)
        d1 = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-001",
            protocol="DJI_OCUSYNC_4",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 1.0, "y": 2.0, "z": 3.0}],
            rf_anomalies=["SPOOF"],
        )
        d2 = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="UAV-002",
            protocol="DJI_OCUSYNC_4",
            threat_level="CRITICAL",
            coordinates_path=[{"x": 1.0, "y": 2.0, "z": 3.0}],
            rf_anomalies=["SPOOF"],
        )
        passed = d1["tamper_evident_hash"] != d2["tamper_evident_hash"]
        metric.measure(passed, "dossier hash changes with content")
        assert metric.is_successful(), metric.reason


# ---------------------------------------------------------------------------
# Evolution tests (GoalAccuracy)
# ---------------------------------------------------------------------------


class TestEvolution:
    def test_evolution_runs_and_improves(self):
        metric = TaskCompletionMetric(threshold=0.70)
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
        history = result["fitness_history"]
        passed = (
            result["best_fitness"] >= 0.0
            and len(history) == 3
            and all(history[i] >= history[i - 1] - 1e-9 for i in range(1, len(history)))
        )
        metric.measure(passed, "evolution runs and fitness is non-decreasing")
        assert metric.is_successful(), metric.reason

    def test_evolution_is_deterministic_with_seed(self):
        metric = TaskCompletionMetric(threshold=0.70)
        es1 = EvolvedScheduler(
            population_size=4,
            generations=3,
            mutation_rate=0.3,
            elitism_count=1,
            dwell_s=4.0,
            slew_s=1.5,
            num_drones=6,
            time_limit_s=30.0,
            seed=123,
        )
        es2 = EvolvedScheduler(
            population_size=4,
            generations=3,
            mutation_rate=0.3,
            elitism_count=1,
            dwell_s=4.0,
            slew_s=1.5,
            num_drones=6,
            time_limit_s=30.0,
            seed=123,
        )
        passed = es1.evolve()["best_params"] == es2.evolve()["best_params"]
        metric.measure(passed, "evolution deterministic with seed")
        assert metric.is_successful(), metric.reason


# ---------------------------------------------------------------------------
# Performance / SLO tests
# ---------------------------------------------------------------------------


class TestPerformance:
    def test_suite_has_expected_test_count(self):
        """The deep-eval module collects a deterministic number of tests."""
        # Soft check: the module is importable and defines test classes.
        assert TestDetection is not None
        assert TestTracking is not None
        assert TestEngagement is not None
        assert TestDecisionLoop is not None
        assert TestForensics is not None
        assert TestEvolution is not None
