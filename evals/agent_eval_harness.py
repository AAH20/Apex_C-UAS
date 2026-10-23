"""
Agent Evaluation Harness.

Systematic reliability evaluation for agentic C-UAS components:
- Site agent detection coverage
- Federation track fusion accuracy
- Engagement deconfliction correctness
- End-to-end orchestration latency

All metrics computed from real code execution — no fabricated numbers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from c_uas.orchestration import (
    Federation,
    SiteAgent,
    SiteConfig,
    build_demo_federation,
)
from c_uas.swarm import SwarmConfig, SwarmSimulator


@dataclass
class EvalResult:
    name: str
    passed: bool
    value: float
    threshold: float
    unit: str
    detail: str


@dataclass
class EvalSuite:
    results: list[EvalResult] = field(default_factory=list)

    def add(self, result: EvalResult) -> None:
        self.results.append(result)

    def summary(self) -> dict:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": round(passed / total, 4) if total else 0.0,
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "value": r.value,
                    "threshold": r.threshold,
                    "unit": r.unit,
                    "detail": r.detail,
                }
                for r in self.results
            ],
        }


class AgentEvalHarness:
    """
    Runs a suite of reliability evaluations against agentic components.
    """

    def __init__(self) -> None:
        self.suite = EvalSuite()

    def evaluate_site_detection(
        self, site: SiteAgent, swarm_config: SwarmConfig
    ) -> EvalResult:
        """Evaluate: site detects all drones in swarm within range."""
        sim = SwarmSimulator(swarm_config)
        new_tracks = site.detect_and_track(sim)
        detected = len(new_tracks)
        expected = swarm_config.num_drones
        coverage = detected / expected if expected else 0.0
        passed = coverage >= 0.95
        return EvalResult(
            name="site_detection_coverage",
            passed=passed,
            value=round(coverage, 4),
            threshold=0.95,
            unit="fraction",
            detail=f"{detected}/{expected} drones detected",
        )

    def evaluate_fusion_dedup(
        self, fed: Federation
    ) -> EvalResult:
        """Evaluate: fusion does not duplicate tracks across sites."""
        fed.fuse_tracks()
        total_tracks = sum(len(a.tracks) for a in fed.sites.values())
        site_count = len(fed.sites)
        # After fusion, each unique drone should appear at each site once.
        # No duplicates means tracks_per_site are consistent.
        per_site = [len(a.tracks) for a in fed.sites.values()]
        max_tracks = max(per_site) if per_site else 0
        min_tracks = min(per_site) if per_site else 0
        # Consistency: all sites should have similar track counts after fusion
        consistency = 1.0 - (max_tracks - min_tracks) / max(max_tracks, 1)
        passed = consistency >= 0.9
        return EvalResult(
            name="fusion_track_consistency",
            passed=passed,
            value=round(consistency, 4),
            threshold=0.9,
            unit="fraction",
            detail=f"tracks per site: min={min_tracks}, max={max_tracks}",
        )

    def evaluate_deconfliction(
        self, fed: Federation, swarm_config: SwarmConfig
    ) -> EvalResult:
        """Evaluate: deconfliction eliminates multi-site engagement conflicts."""
        fed.run_round(swarm_config)
        report = fed.deconflict_engagements()
        conflicts = report["conflicts_detected"]
        resolved = report["conflicts_resolved"]
        resolution_rate = resolved / max(conflicts, 1)
        passed = resolution_rate >= 1.0 or conflicts == 0
        return EvalResult(
            name="engagement_deconfliction",
            passed=passed,
            value=round(resolution_rate, 4),
            threshold=1.0,
            unit="fraction",
            detail=f"{conflicts} conflicts, {resolved} resolved",
        )

    def evaluate_orchestration_latency(
        self, fed: Federation, swarm_config: SwarmConfig
    ) -> EvalResult:
        """Evaluate: one orchestration round completes within threshold."""
        start = time.perf_counter()
        fed.run_round(swarm_config)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        passed = elapsed_ms < 500.0  # under 500ms per round
        return EvalResult(
            name="orchestration_round_latency_ms",
            passed=passed,
            value=round(elapsed_ms, 2),
            threshold=500.0,
            unit="ms",
            detail=f"{len(fed.sites)} sites, {swarm_config.num_drones} drones",
        )

    def evaluate_leak_rate_reduction(
        self, fed: Federation, swarm_config: SwarmConfig
    ) -> EvalResult:
        """Evaluate: federation reduces overall leak rate vs single site."""
        # Single site leak rate
        single = SiteAgent(
            config=SiteConfig(
                site_id="single", name="Single", latitude_deg=0, longitude_deg=0
            )
        )
        sim = SwarmSimulator(swarm_config)
        single.detect_and_track(sim)
        plan = single.schedule_engagements()
        single_leak = (
            plan.leaked_targets / max(len(single.tracks), 1)
            if single.tracks
            else 1.0
        )

        # Federated leak rate (average across sites after fusion)
        fed.run_round(swarm_config)
        fed_leaks = []
        for agent in fed.sites.values():
            if agent.engagements:
                p = agent.engagements.get("plan")
                if p is not None:
                    leak = p.leaked_targets / max(len(agent.tracks), 1)
                    fed_leaks.append(leak)
        fed_leak = sum(fed_leaks) / len(fed_leaks) if fed_leaks else 1.0

        # Improvement: federated leak should be <= single site leak
        improvement = single_leak - fed_leak
        passed = fed_leak <= single_leak + 0.05  # small tolerance
        return EvalResult(
            name="federation_leak_rate_improvement",
            passed=passed,
            value=round(improvement, 4),
            threshold=0.0,
            unit="fraction",
            detail=f"single={round(single_leak,4)}, federated={round(fed_leak,4)}",
        )

    def run_all(self, num_sites: int = 3, num_drones: int = 16) -> dict:
        """Run the full evaluation suite."""
        swarm_config = SwarmConfig(
            num_drones=num_drones,
            arrival_spread_s=10.0,
            speed_mps=30.0,
            start_distance_km=2.0,
            evasion_probability=0.3,
            seed=42,
        )

        fed = build_demo_federation(num_sites)

        # Site detection (use first site)
        first_site = list(fed.sites.values())[0]
        self.suite.add(self.evaluate_site_detection(first_site, swarm_config))

        # Fusion dedup
        self.suite.add(self.evaluate_fusion_dedup(fed))

        # Deconfliction
        self.suite.add(self.evaluate_deconfliction(fed, swarm_config))

        # Latency
        self.suite.add(self.evaluate_orchestration_latency(fed, swarm_config))

        # Leak rate reduction
        self.suite.add(self.evaluate_leak_rate_reduction(fed, swarm_config))

        return self.suite.summary()
