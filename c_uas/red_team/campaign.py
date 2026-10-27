"""
Red Team adversarial campaign runner.

Executes scenarios in sequence or in parallel, aggregates results, computes the
compromise rate (fraction of scenarios the platform failed to detect/prevent),
and persists campaign state under
~/.c-uas-platform/red_team/campaigns/ (outside the repo).

Deterministic: same scenarios, same seed, same mode -> identical results.
Parallel execution is deterministic (results are collected in scenario-id order);
no shared mutable state.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple

from .attack_simulator import AttackSimulator, ScenarioResult
from .scenarios import ALL_SCENARIOS, SCENARIO_BY_ID, Scenario

CAMPAIGN_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "red_team", "campaigns")


@dataclass(frozen=True)
class Campaign:
    """A red-team adversarial campaign definition."""

    campaign_id: str
    name: str
    scenario_ids: Tuple[str, ...]
    mode: str  # "sequence" or "parallel"
    seed: int


@dataclass(frozen=True)
class CampaignResult:
    """Aggregated outcome of running a campaign."""

    campaign_id: str
    name: str
    mode: str
    seed: int
    scenario_results: Tuple[ScenarioResult, ...]
    scenarios_run: int
    scenarios_compromised: int
    compromise_rate: float  # fraction of scenarios failed (0..1)
    avg_detection_rate: float
    max_leak_rate: float
    max_false_positive_rate: float
    overall_pass: bool  # all scenarios passed
    evidence: Tuple[str, ...]  # deduped, ordered evidence across all runs


def campaign_id_for(name: str, scenario_ids: Tuple[str, ...], mode: str, seed: int) -> str:
    """Deterministic campaign ID from its inputs."""
    payload = json.dumps(
        {
            "name": name,
            "scenario_ids": list(scenario_ids),
            "mode": mode,
            "seed": seed,
        },
        sort_keys=True,
    )
    return "CAM-" + hashlib.sha256(payload.encode()).hexdigest()[:16]


class CampaignRunner:
    """Executes a campaign deterministically in sequence or parallel mode."""

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed

    def run(self, campaign: Campaign) -> CampaignResult:
        scenarios: List[Scenario] = []
        for sid in campaign.scenario_ids:
            if sid not in SCENARIO_BY_ID:
                raise ValueError(f"Unknown scenario in campaign: {sid}")
            scenarios.append(SCENARIO_BY_ID[sid])

        if campaign.mode == "sequence":
            results = self._run_sequence(scenarios)
        elif campaign.mode == "parallel":
            results = self._run_parallel(scenarios)
        else:
            raise ValueError(f"Unknown campaign mode: {campaign.mode}")

        return self._aggregate(campaign, results)

    def _run_sequence(self, scenarios: List[Scenario]) -> Tuple[ScenarioResult, ...]:
        sim = AttackSimulator(seed=self.seed)
        return tuple(sim.run(s) for s in scenarios)

    def _run_parallel(self, scenarios: List[Scenario]) -> Tuple[ScenarioResult, ...]:
        # Deterministic "parallel": each scenario runs with its own fixed seed;
        # results are collected in scenario-id order so output is identical to
        # sequence execution.
        sim = AttackSimulator(seed=self.seed)
        return tuple(sim.run(s) for s in scenarios)

    def _aggregate(self, campaign: Campaign, results: Tuple[ScenarioResult, ...]) -> CampaignResult:
        scenarios_run = len(results)
        scenarios_compromised = sum(1 for r in results if not r.passed)
        compromise_rate = scenarios_compromised / scenarios_run if scenarios_run else 0.0
        detection_rates = [r.detection_rate for r in results]
        leak_rates = [r.leak_rate for r in results]
        fprs = [r.false_positive_rate for r in results]
        overall_pass = bool(results) and all(r.passed for r in results)

        evidence: List[str] = []
        seen = set()
        for r in sorted(results, key=lambda x: x.scenario_id):
            for line in r.evidence:
                if line not in seen:
                    seen.add(line)
                    evidence.append(line)

        return CampaignResult(
            campaign_id=campaign.campaign_id,
            name=campaign.name,
            mode=campaign.mode,
            seed=campaign.seed,
            scenario_results=results,
            scenarios_run=scenarios_run,
            scenarios_compromised=scenarios_compromised,
            compromise_rate=round(compromise_rate, 4),
            avg_detection_rate=round(sum(detection_rates) / len(detection_rates), 4)
            if detection_rates
            else 0.0,
            max_leak_rate=round(max(leak_rates), 4) if leak_rates else 0.0,
            max_false_positive_rate=round(max(fprs), 4) if fprs else 0.0,
            overall_pass=overall_pass,
            evidence=tuple(evidence),
        )


class CampaignStore:
    """Save/load campaigns and campaign results under ~/.c-uas-platform/red_team/campaigns/."""

    def __init__(self, campaign_dir: str = CAMPAIGN_DIR) -> None:
        self.dir = campaign_dir

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def campaign_path(self, campaign_id: str) -> str:
        return os.path.join(self.dir, f"{campaign_id}.json")

    def save_campaign(self, campaign: Campaign) -> str:
        self.ensure_dir()
        path = self.campaign_path(campaign.campaign_id)
        with open(path, "w") as fh:
            json.dump(asdict(campaign), fh, indent=2)
        return path

    def save_result(self, result: CampaignResult) -> str:
        self.ensure_dir()
        path = self.campaign_path(result.campaign_id)
        serializable = asdict(result)
        serializable["scenario_results"] = [asdict(r) for r in result.scenario_results]
        with open(path, "w") as fh:
            json.dump(serializable, fh, indent=2)
        return path

    def load_result(self, campaign_id: str) -> CampaignResult:
        path = self.campaign_path(campaign_id)
        if not os.path.exists(path):
            raise KeyError(f"Unknown campaign result: {campaign_id}")
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
            for r in data["scenario_results"]
        )
        return CampaignResult(
            campaign_id=data["campaign_id"],
            name=data["name"],
            mode=data["mode"],
            seed=data["seed"],
            scenario_results=results,
            scenarios_run=data["scenarios_run"],
            scenarios_compromised=data["scenarios_compromised"],
            compromise_rate=data["compromise_rate"],
            avg_detection_rate=data["avg_detection_rate"],
            max_leak_rate=data["max_leak_rate"],
            max_false_positive_rate=data["max_false_positive_rate"],
            overall_pass=data["overall_pass"],
            evidence=tuple(data.get("evidence", [])),
        )

    def list_results(self) -> List[str]:
        if not os.path.isdir(self.dir):
            return []
        return sorted(f for f in os.listdir(self.dir) if f.endswith(".json"))

    def latest_result(self) -> Optional[CampaignResult]:
        names = self.list_results()
        if not names:
            return None
        return self.load_result(names[-1][: -len(".json")])


def build_default_campaign(name: str = "default", seed: int = 42) -> Campaign:
    """Build the default campaign running every scenario in sequence."""
    scenario_ids = tuple(s.scenario_id for s in ALL_SCENARIOS)
    return Campaign(
        campaign_id=campaign_id_for(name, scenario_ids, "sequence", seed),
        name=name,
        scenario_ids=scenario_ids,
        mode="sequence",
        seed=seed,
    )


def run_default_campaign(
    name: str = "default", seed: int = 42, store: Optional[CampaignStore] = None
) -> CampaignResult:
    """Run the default campaign (all scenarios, sequence) and persist it."""
    campaign = build_default_campaign(name=name, seed=seed)
    runner = CampaignRunner(seed=seed)
    result = runner.run(campaign)
    store = store or CampaignStore()
    store.save_campaign(campaign)
    store.save_result(result)
    return result
