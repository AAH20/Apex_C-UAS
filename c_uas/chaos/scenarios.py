"""Chaos scenarios for the C-UAS platform.

Defines deterministic resilience scenarios (backend_failure, network_partition,
api_timeout, cascade_failure, partial_outage) used to validate that platform
components degrade gracefully and recover under injected faults.

Defensive only: exercises real modules under failure conditions. No live
network, no hardware, no effector control.

Scenario state persists under ~/.c-uas-platform/chaos/ (outside the repo).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import List, Tuple

CHAOS_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "chaos")
SCENARIOS_PATH = os.path.join(CHAOS_DIR, "scenarios.json")


@dataclass(frozen=True)
class ChaosScenario:
    """A single deterministic chaos scenario.

    scenario_id   : stable identifier, e.g. "backend_failure"
    name          : human-readable name
    description   : what the scenario exercises
    faults        : tuple of fault_ids activated during the scenario
    targets       : component paths the faults apply to
    seed          : RNG seed for reproducible fault patterns
    duration_s    : scenario run length, seconds
    expected_recovery_s : maximum acceptable recovery time, seconds
    min_success_rate  : minimum fraction of calls that must succeed (0..1)
    """

    scenario_id: str
    name: str
    description: str
    faults: Tuple[str, ...]
    targets: Tuple[str, ...]
    seed: int
    duration_s: float
    expected_recovery_s: float
    min_success_rate: float


# --------------------------------------------------------------------------- #
# Predefined deterministic scenarios
# --------------------------------------------------------------------------- #


BACKEND_FAILURE = ChaosScenario(
    scenario_id="backend_failure",
    name="Backend Failure",
    description=(
        "The API backend crashes under load. Fault injector applies backend_crash "
        "against c_uas.api.server; the platform must return errors (not hang) and "
        "recover once the fault is deactivated."
    ),
    faults=("backend_crash",),
    targets=("c_uas.api.server",),
    seed=3001,
    duration_s=5.0,
    expected_recovery_s=5.0,
    min_success_rate=0.0,
)

NETWORK_PARTITION = ChaosScenario(
    scenario_id="network_partition",
    name="Network Partition",
    description=(
        "High latency plus packet loss between client and backend simulates a "
        "network partition. The platform must degrade gracefully: some calls "
        "succeed, failed calls fail fast, and the system recovers when the "
        "partition heals."
    ),
    faults=("network_latency", "packet_loss"),
    targets=("c_uas.api.server",),
    seed=3002,
    duration_s=5.0,
    expected_recovery_s=5.0,
    min_success_rate=0.40,
)

API_TIMEOUT = ChaosScenario(
    scenario_id="api_timeout",
    name="API Timeout",
    description=(
        "The backend stops responding within the client timeout window. Calls "
        "must raise TimeoutError quickly rather than blocking indefinitely, and "
        "the platform recovers once the fault clears."
    ),
    faults=("api_timeout",),
    targets=("c_uas.api.server",),
    seed=3003,
    duration_s=5.0,
    expected_recovery_s=5.0,
    min_success_rate=0.0,
)

CASCADE_FAILURE = ChaosScenario(
    scenario_id="cascade_failure",
    name="Cascade Failure",
    description=(
        "Backend crash plus memory pressure strike simultaneously. Multiple "
        "faults amplify each other; the platform must fail closed (errors, not "
        "silent corruption) and recover fully when all faults are deactivated."
    ),
    faults=("backend_crash", "memory_pressure"),
    targets=("c_uas.api.server",),
    seed=3004,
    duration_s=5.0,
    expected_recovery_s=5.0,
    min_success_rate=0.0,
)

PARTIAL_OUTAGE = ChaosScenario(
    scenario_id="partial_outage",
    name="Partial Outage",
    description=(
        "A subset of calls fail (packet loss) while others succeed. The "
        "platform must maintain a usable success rate above min_success_rate "
        "and recover when the outage ends."
    ),
    faults=("packet_loss",),
    targets=("c_uas.api.server",),
    seed=3005,
    duration_s=5.0,
    expected_recovery_s=5.0,
    min_success_rate=0.60,
)

ALL_SCENARIOS: Tuple[ChaosScenario, ...] = (
    BACKEND_FAILURE,
    NETWORK_PARTITION,
    API_TIMEOUT,
    CASCADE_FAILURE,
    PARTIAL_OUTAGE,
)

SCENARIO_BY_ID = {s.scenario_id: s for s in ALL_SCENARIOS}


def scenario_fingerprint(scenarios: List[ChaosScenario]) -> str:
    """Deterministic fingerprint of a scenario set (for report IDs)."""
    payload = json.dumps(
        [
            {
                "scenario_id": s.scenario_id,
                "faults": s.faults,
                "targets": s.targets,
                "seed": s.seed,
                "min_success_rate": s.min_success_rate,
            }
            for s in sorted(scenarios, key=lambda x: x.scenario_id)
        ],
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Persistence (outside the repo)
# --------------------------------------------------------------------------- #


class ChaosScenarioStore:
    """Load/save chaos scenarios under ~/.c-uas-platform/chaos/."""

    def __init__(self, scenarios_dir: str = CHAOS_DIR) -> None:
        self.dir = scenarios_dir
        self.path = os.path.join(self.dir, "scenarios.json")

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def save_scenarios(self, scenarios: List[ChaosScenario]) -> None:
        self.ensure_dir()
        serializable = []
        for s in scenarios:
            d = asdict(s)
            d["faults"] = list(d["faults"])
            d["targets"] = list(d["targets"])
            serializable.append(d)
        with open(self.path, "w") as fh:
            json.dump(serializable, fh, indent=2)

    def load_scenarios(self) -> List[ChaosScenario]:
        """Return stored scenarios, falling back to the predefined defaults."""
        if not os.path.exists(self.path):
            return list(ALL_SCENARIOS)
        with open(self.path) as fh:
            data = json.load(fh)
        scenarios: List[ChaosScenario] = []
        for d in data:
            scenarios.append(
                ChaosScenario(
                    scenario_id=d["scenario_id"],
                    name=d["name"],
                    description=d["description"],
                    faults=tuple(d.get("faults", [])),
                    targets=tuple(d.get("targets", [])),
                    seed=int(d["seed"]),
                    duration_s=float(d["duration_s"]),
                    expected_recovery_s=float(d["expected_recovery_s"]),
                    min_success_rate=float(d["min_success_rate"]),
                )
            )
        return scenarios

    def list_scenarios(self) -> List[ChaosScenario]:
        return self.load_scenarios()

    def get_scenario(self, scenario_id: str) -> ChaosScenario:
        for s in self.load_scenarios():
            if s.scenario_id == scenario_id:
                return s
        raise KeyError(f"Unknown scenario: {scenario_id}")


def default_store() -> ChaosScenarioStore:
    return ChaosScenarioStore()
