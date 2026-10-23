"""
Performance Benchmarks for the C-UAS Platform.

Measures real execution performance:
- Engagement scheduler throughput vs drone count
- EKF tracking accuracy (position error vs ground truth)
- End-to-end pipeline latency (detection → decision → dossier)
- Swarm saturation thresholds

All benchmarks run deterministically and report real measured values.
No fabricated metrics.

Usage:
    from c_uas.benchmarks.performance import BenchmarkSuite
    suite = BenchmarkSuite()
    results = suite.run_all()
    print(results)
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from c_uas.engagement.scheduler import (
    DroneTrack,
    EngagementScheduler,
)
from c_uas.swarm import SwarmConfig, SwarmSimulator
from c_uas.tracking.ekf_interceptor import EKFTrajectoryPredictor


@dataclass(frozen=True)
class SchedulerBenchmarkResult:
    """Result of a single scheduler performance benchmark."""

    num_drones: int
    time_limit_s: float
    scheduler_seconds: float  # wall-clock time to compute schedule
    expected_kills: float
    engaged_targets: int
    leaked_targets: int
    drones_per_second: float  # scheduling throughput


@dataclass(frozen=True)
class EKFBenchmarkResult:
    """Result of EKF tracking accuracy benchmark."""

    num_measurements: int
    horizon_s: float
    position_error_m: float  # RMS error vs ground truth at intercept
    velocity_error_mps: float
    compute_seconds: float


@dataclass(frozen=True)
class EndToEndBenchmarkResult:
    """Result of end-to-end pipeline latency benchmark."""

    pipeline_stages: int
    total_seconds: float
    per_stage_ms: float
    dossier_generated: bool


@dataclass(frozen=True)
class BenchmarkSuiteResult:
    """Aggregate benchmark results."""

    scheduler_results: List[SchedulerBenchmarkResult]
    ekf_result: EKFBenchmarkResult
    end_to_end_result: EndToEndBenchmarkResult
    swarm_saturation: Dict[int, float]  # drone count -> leak rate


class BenchmarkSuite:
    """
    Runs the full performance benchmark suite.

    Results are real measurements from code execution, not estimates.
    """

    def __init__(self) -> None:
        self.scheduler_results: List[SchedulerBenchmarkResult] = []
        self.ekf_result: Optional[EKFBenchmarkResult] = None
        self.end_to_end_result: Optional[EndToEndBenchmarkResult] = None
        self.swarm_saturation: Dict[int, float] = {}

    def benchmark_scheduler(
        self,
        drone_counts: List[int] = None,
        time_limit_s: float = 30.0,
    ) -> List[SchedulerBenchmarkResult]:
        """Measure scheduler wall-clock time vs drone count."""
        if drone_counts is None:
            drone_counts = [4, 8, 16, 32, 64, 128]

        results: List[SchedulerBenchmarkResult] = []
        for n in drone_counts:
            scheduler = EngagementScheduler(dwell_s=4.0, slew_s=1.5, time_limit_s=time_limit_s)
            tracks = [
                DroneTrack(
                    track_id=i,
                    arrival_time_s=5.0 + i * 0.5,
                    pk_base=0.75,
                    priority=3,
                )
                for i in range(n)
            ]

            start = time.perf_counter()
            plan = scheduler.schedule(tracks=tracks)
            elapsed = time.perf_counter() - start

            results.append(
                SchedulerBenchmarkResult(
                    num_drones=n,
                    time_limit_s=time_limit_s,
                    scheduler_seconds=round(elapsed, 6),
                    expected_kills=plan.expected_kills,
                    engaged_targets=plan.engaged_targets,
                    leaked_targets=plan.leaked_targets,
                    drones_per_second=round(n / elapsed, 2) if elapsed > 0 else 0.0,
                )
            )

        self.scheduler_results = results
        return results

    def benchmark_ekf(
        self,
        num_measurements: int = 50,
        horizon_s: float = 2.0,
    ) -> EKFBenchmarkResult:
        """Measure EKF tracking accuracy against known ground truth."""
        ekf = EKFTrajectoryPredictor(dt=0.1)

        # Ground truth: drone moving at constant velocity
        true_x0, true_y0, true_z0 = 100.0, 500.0, 120.0
        true_vx, true_vy, true_vz = 15.0, -8.0, 2.0

        # Feed noisy measurements with realistic, small measurement noise
        rng = random.Random(42)
        for i in range(num_measurements):
            t = i * 0.1
            # Small Gaussian-like measurement noise (+/- 1.0m)
            noise_x = rng.uniform(-1.0, 1.0)
            noise_y = rng.uniform(-1.0, 1.0)
            noise_z = rng.uniform(-0.5, 0.5)
            ekf.update_measurement(
                true_x0 + true_vx * t + noise_x,
                true_y0 + true_vy * t + noise_y,
                true_z0 + true_vz * t + noise_z,
            )

        # Predict intercept at horizon
        start = time.perf_counter()
        intercept = ekf.predict_intercept(horizon_s)
        compute_seconds = time.perf_counter() - start

        # Ground truth position at intercept time (current time + horizon)
        # Current time = num_measurements * dt (time of last measurement)
        current_time_s = num_measurements * 0.1
        true_x = true_x0 + true_vx * (current_time_s + horizon_s)
        true_y = true_y0 + true_vy * (current_time_s + horizon_s)
        true_z = true_z0 + true_vz * (current_time_s + horizon_s)

        # Position error
        position_error_m = (
            (intercept[0] - true_x) ** 2
            + (intercept[1] - true_y) ** 2
            + (intercept[2] - true_z) ** 2
        ) ** 0.5

        # Velocity error (EKF state velocity vs true velocity)
        vel_error = (
            (ekf.state.vx - true_vx) ** 2
            + (ekf.state.vy - true_vy) ** 2
            + (ekf.state.vz - true_vz) ** 2
        ) ** 0.5

        self.ekf_result = EKFBenchmarkResult(
            num_measurements=num_measurements,
            horizon_s=horizon_s,
            position_error_m=round(position_error_m, 4),
            velocity_error_mps=round(vel_error, 4),
            compute_seconds=round(compute_seconds, 6),
        )
        return self.ekf_result

    def benchmark_end_to_end(self) -> EndToEndBenchmarkResult:
        """Measure end-to-end pipeline latency."""
        import asyncio

        from c_uas.decision import (
            ActionModule,
            DecisionModule,
            PerceptionModule,
        )
        from c_uas.detection.rf_classifier import RFSignalClassifier
        from c_uas.detection.spoof_detector import GNSSMeasurement, GNSSSpoofDetector
        from c_uas.forensics.airspace_dossier import AirspaceIntrusionDossier

        stages = 0
        total_start = time.perf_counter()

        # Stage 1: RF detection
        rf_result = RFSignalClassifier.classify_frequency(2450.0, 20.0)
        stages += 1

        # Stage 2: GNSS spoof detection
        detector = GNSSSpoofDetector()
        nominal = GNSSMeasurement(
            carrier_to_noise_db_hz=42.0,
            pseudorange_rate_mps=10.0,
            clock_drift_ppm=0.05,
            num_satellites=10,
        )
        gnss_result = detector.evaluate_telemetry(nominal)
        stages += 1

        # Stage 3: EKF tracking
        ekf = EKFTrajectoryPredictor(dt=0.1)
        for i in range(10):
            ekf.update_measurement(10.0 + i * 2.0, 50.0 + i * 1.5, 120.0 - i * 0.5)
        _ = ekf.predict_intercept(2.0)
        stages += 1

        # Stage 4: Engagement scheduling
        scheduler = EngagementScheduler(dwell_s=4.0, slew_s=1.5, time_limit_s=30.0)
        tracks = [
            DroneTrack(track_id=i, arrival_time_s=5.0 + i * 3.0, pk_base=0.8, priority=3)
            for i in range(4)
        ]
        plan = scheduler.schedule(tracks=tracks)
        stages += 1

        # Stage 5: Decision loop
        perception = PerceptionModule()
        perception.update_rf([rf_result])
        perception.update_classification([rf_result])
        situation = perception.get_situation_summary()
        situation["num_drones"] = len(tracks)
        decision = DecisionModule(config={"jamming": {"authorized": False}})
        threat_level = decision.assess_threat(situation)
        strategy = decision.select_strategy(threat_level, situation)
        commands = decision.plan_actions(strategy, situation)
        stages += 1

        # Stage 6: Action execution (async)
        action = ActionModule(config={"jamming": {"authorized": False}}, simulation_mode=True)
        asyncio.run(self._execute_commands(action, commands))
        stages += 1

        # Stage 7: Forensic dossier
        dossier = AirspaceIntrusionDossier.generate_signed_dossier(
            target_id="BENCHMARK-01",
            protocol=rf_result["protocol"],
            threat_level=str(threat_level.name),
            coordinates_path=[{"x": 100.0, "y": 200.0, "z": 50.0}],
            rf_anomalies=gnss_result.get("anomaly_flags", []),
        )
        stages += 1

        total_seconds = time.perf_counter() - total_start

        self.end_to_end_result = EndToEndBenchmarkResult(
            pipeline_stages=stages,
            total_seconds=round(total_seconds, 6),
            per_stage_ms=round(total_seconds * 1000.0 / stages, 3),
            dossier_generated=dossier["admissibility"] == "LEGAL_DEFENSE_GRADE",
        )
        return self.end_to_end_result

    def benchmark_swarm_saturation(
        self,
        drone_counts: List[int] = None,
        spread_s: float = 10.0,
    ) -> Dict[int, float]:
        """Measure leak rate vs swarm size — the swarm saturation curve."""
        if drone_counts is None:
            drone_counts = [8, 16, 32, 64, 128]

        saturation: Dict[int, float] = {}
        scheduler = EngagementScheduler(dwell_s=4.0, slew_s=1.5, time_limit_s=40.0)

        for n in drone_counts:
            config = SwarmConfig(
                num_drones=n,
                arrival_spread_s=spread_s,
                speed_mps=30.0,
                start_distance_km=2.0,
                evasion_probability=0.3,
                seed=42,
            )
            sim = SwarmSimulator(config)
            tracks = sim.generate_tracks()

            from c_uas.engagement.scheduler import DroneTrack

            drone_tracks = [
                DroneTrack(
                    track_id=t.track_id,
                    arrival_time_s=t.arrival_time_s,
                    pk_base=t.pk_base,
                    priority=t.priority,
                )
                for t in tracks
            ]
            plan = scheduler.schedule(tracks=drone_tracks)
            saturation[n] = round(plan.leaked_targets / n, 4)

        self.swarm_saturation = saturation
        return saturation

    def run_all(self) -> BenchmarkSuiteResult:
        """Run all benchmarks and return aggregate results."""
        self.benchmark_scheduler()
        self.benchmark_ekf()
        self.benchmark_end_to_end()
        self.benchmark_swarm_saturation()

        return BenchmarkSuiteResult(
            scheduler_results=self.scheduler_results,
            ekf_result=self.ekf_result,
            end_to_end_result=self.end_to_end_result,
            swarm_saturation=self.swarm_saturation,
        )

    async def _execute_commands(self, action, commands):
        results = []
        for cmd in commands:
            result = await action.execute(cmd)
            results.append(result)
        return results
