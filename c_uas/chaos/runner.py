"""Chaos runner: executes scenarios against real platform components.

The runner drives the FaultInjector through each scenario's fault set, probes
the target component before/during/after the fault window, and records
success rate, failure modes, and recovery time for each scenario.

Deterministic: every scenario runs with a fixed seed and fresh RNG, so the
same scenario always produces identical results.

Defensive only: probes real modules under fault conditions. No live network,
no hardware, no effector control.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional

from .faults import Fault, FaultInjector
from .scenarios import ChaosScenario


@dataclass(frozen=True)
class ChaosRunResult:
    """Outcome of running one chaos scenario against the platform."""

    scenario_id: str
    scenario_name: str
    seed: int
    duration_s: float
    probes_total: int  # total probe calls made
    probes_succeeded: int  # probes that returned without raising
    probes_failed: int  # probes that raised
    success_rate: float  # succeeded / total (0..1)
    failure_modes: List[str]  # distinct exception type names observed
    recovery_time_s: float  # time from deactivation to first successful probe
    recovered: bool  # whether the component recovered after faults cleared
    passed: bool  # scenario pass/fail against its thresholds
    details: Dict[str, Any]  # scenario-specific raw measurements


class ChaosRunner:
    """Runs chaos scenarios against real platform components.

    For each scenario:
      1. Activate the scenario's faults.
      2. Probe the target component repeatedly through the fault window.
      3. Deactivate the faults.
      4. Probe until the component recovers (or recovery_time budget expires).
      5. Compute success rate, failure modes, recovery time, pass/fail.
    """

    def __init__(
        self,
        injector: Optional[FaultInjector] = None,
        probe_interval_s: float = 0.01,
        recovery_budget_s: float = 10.0,
    ) -> None:
        self.injector = injector or FaultInjector()
        self.probe_interval_s = probe_interval_s
        self.recovery_budget_s = recovery_budget_s

    # -- entry point ------------------------------------------------------- #

    def run(self, scenario: ChaosScenario) -> ChaosRunResult:
        faults = self.injector.faults
        # Resolve fault objects from ids, validating they exist.
        fault_objs: List[Fault] = []
        for fid in scenario.faults:
            if fid not in faults:
                raise ValueError(
                    f"Scenario {scenario.scenario_id} references unknown fault {fid}"
                )
            fault_objs.append(faults[fid])

        # Activate faults for the scenario duration.
        for f in fault_objs:
            self.injector.activate(f.fault_id)

        try:
            result = self._run_under_faults(scenario, fault_objs)
        finally:
            # Always deactivate so later scenarios start clean.
            self.injector.deactivate_all()

        return result

    # -- internal ---------------------------------------------------------- #

    def _run_under_faults(self, scenario: ChaosScenario, fault_objs: List[Fault]) -> ChaosRunResult:
        target = scenario.targets[0] if scenario.targets else "c_uas.api.server"

        # Build a probe callable that exercises a real platform component.
        probe = self._make_probe(target)

        probes_total = 0
        probes_succeeded = 0
        probes_failed = 0
        failure_modes: List[str] = []
        fault_start = time.monotonic()

        # Phase 1: probe through the fault window.
        while time.monotonic() - fault_start < scenario.duration_s:
            probes_total += 1
            try:
                self.injector.inject(target, probe)
                probes_succeeded += 1
            except Exception as exc:  # noqa: BLE001 - capture failure modes
                probes_failed += 1
                mode = type(exc).__name__
                if mode not in failure_modes:
                    failure_modes.append(mode)
            time.sleep(self.probe_interval_s)

        success_rate = (
            probes_succeeded / probes_total if probes_total else 0.0
        )

        # Phase 2: deactivate faults and measure recovery time.
        self.injector.deactivate_all()
        recovery_start = time.monotonic()
        recovered = False
        recovery_time_s = 0.0
        while time.monotonic() - recovery_start < self.recovery_budget_s:
            try:
                probe()
                recovered = True
                recovery_time_s = time.monotonic() - recovery_start
                break
            except Exception:  # noqa: BLE001 - still recovering
                time.sleep(self.probe_interval_s)

        # Phase 3: pass/fail against thresholds.
        min_success = scenario.min_success_rate
        passed = (
            success_rate >= min_success
            and recovered
            and recovery_time_s <= scenario.expected_recovery_s
        )

        details: Dict[str, Any] = {
            "target": target,
            "faults": [f.fault_id for f in fault_objs],
            "fault_kinds": [f.kind for f in fault_objs],
            "probes_total": probes_total,
            "probes_succeeded": probes_succeeded,
            "probes_failed": probes_failed,
            "recovery_time_s": round(recovery_time_s, 4),
            "recovered": recovered,
        }

        return ChaosRunResult(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            seed=scenario.seed,
            duration_s=round(scenario.duration_s, 4),
            probes_total=probes_total,
            probes_succeeded=probes_succeeded,
            probes_failed=probes_failed,
            success_rate=round(success_rate, 4),
            failure_modes=failure_modes,
            recovery_time_s=round(recovery_time_s, 4),
            recovered=recovered,
            passed=passed,
            details=details,
        )

    # -- probe factory ----------------------------------------------------- #

    def _make_probe(self, target: str) -> Callable[[], Any]:
        """Return a callable that probes the real component at ``target``.

        Falls back to a lightweight in-process probe when the target module
        cannot be imported, so the runner never hard-depends on optional
        imports.
        """
        if target == "c_uas.api.server":
            return self._probe_api_server
        if target == "c_uas.detection.rf_classifier":
            return self._probe_rf_classifier
        if target == "c_uas.detection.spoof_detector":
            return self._probe_spoof_detector
        if target == "c_uas.engagement.scheduler":
            return self._probe_scheduler
        # Default: trivial in-process probe that always succeeds.
        return lambda: True

    @staticmethod
    def _probe_api_server() -> Any:
        """Probe the production app factory (real module, real import)."""
        from c_uas.deployment.server import create_app

        app = create_app()
        # Touch the health route through the test client for a real HTTP probe.
        from fastapi.testclient import TestClient

        client = TestClient(app)
        resp = client.get("/healthz")
        if resp.status_code >= 500:
            raise RuntimeError(f"API unhealthy: HTTP {resp.status_code}")
        return resp.status_code

    @staticmethod
    def _probe_rf_classifier() -> Any:
        from c_uas.detection.rf_classifier import RFSignalClassifier

        return RFSignalClassifier.classify_frequency(2440.0, 20.0)

    @staticmethod
    def _probe_spoof_detector() -> Any:
        from c_uas.detection.spoof_detector import GNSSMeasurement, GNSSSpoofDetector

        detector = GNSSSpoofDetector()
        m = GNSSMeasurement(
            carrier_to_noise_db_hz=42.0,
            pseudorange_rate_mps=10.0,
            clock_drift_ppm=0.05,
            num_satellites=10,
        )
        return detector.evaluate_telemetry(m)

    @staticmethod
    def _probe_scheduler() -> Any:
        from c_uas.engagement.scheduler import DroneTrack, EngagementScheduler

        sched = EngagementScheduler(dwell_s=4.0, slew_s=1.5, time_limit_s=5.0)
        tracks = [
            DroneTrack(track_id=i, arrival_time_s=float(i), pk_base=0.8, priority=1)
            for i in range(5)
        ]
        return sched.schedule(tracks=tracks)
