"""
Red Team Adversarial Scenarios for the C-UAS platform.

Defines deterministic attack scenarios (GNSS spoofing, RF jamming, swarm
saturation, coordinated multi-vector attack, controller hijacking) used to
validate detection, tracking, and engagement defenses under adversarial
conditions.

Defensive only: simulates attack telemetry against the platform's real
detectors, scheduler, and decision engine. No exploitation code, no live RF,
no payloads, no bypass techniques.

Scenario state persists under ~/.c-uas-platform/red_team/ (outside the repo).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Tuple

RED_TEAM_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "red_team")
SCENARIOS_PATH = os.path.join(RED_TEAM_DIR, "scenarios.json")


@dataclass(frozen=True)
class AdversarialScenario:
    """A single adversarial test scenario with deterministic parameters.

    All runs of the same scenario (same seed) produce identical results.
    """

    scenario_id: str
    name: str
    description: str
    attack_vectors: Tuple[str, ...]
    target_modules: Tuple[str, ...]
    seed: int
    params: Dict[str, Any]
    expected_detection_rate: float  # 0..1, minimum acceptable detection rate
    max_acceptable_leak_rate: float  # 0..1, maximum acceptable leak rate
    max_acceptable_false_positive_rate: float  # 0..1, max false alarms


# ---------------------------------------------------------------------------
# Predefined deterministic scenarios
# ---------------------------------------------------------------------------

GNSS_SPOOFING = AdversarialScenario(
    scenario_id="gnss_spoofing",
    name="GNSS Spoofing / Meaconing",
    description=(
        "Adversary broadcasts a counterfeit GNSS signal with elevated C/N0, "
        "clock-drift steps, and a collapsed constellation to force a target "
        "drone onto a false position fix."
    ),
    attack_vectors=("gnss_spoof", "meaconing"),
    target_modules=("detection",),
    seed=1101,
    params={
        "spoofed_measurements": 40,
        "nominal_measurements": 30,
        "cn0_spoof_db_hz": 62.0,
        "clock_drift_jump_ppm": 4.0,
        "satellites_spoofed": 2,
    },
    expected_detection_rate=0.90,
    max_acceptable_leak_rate=0.0,
    max_acceptable_false_positive_rate=0.10,
)

RF_JAMMING = AdversarialScenario(
    scenario_id="rf_jamming",
    name="RF Jamming",
    description=(
        "Wideband noise jams the drone control bands (2.4 GHz ISR, 915 MHz "
        "telemetry, 868 MHz EPLS, 433 MHz LoRa). Emissions inside the jam "
        "band become unobservable; the platform must still detect and classify "
        "emitters outside the jam band without false alarms on clean spectrum."
    ),
    attack_vectors=("rf_jam", "noise_jam"),
    target_modules=("detection",),
    seed=1102,
    params={
        "jam_band_low_mhz": 2400.0,
        "jam_band_high_mhz": 2483.5,
        "drone_frequencies_mhz": [2440.0, 915.0, 868.0, 433.0],
        "clean_frequencies_mhz": [100.0, 5000.0, 146.0],
    },
    expected_detection_rate=0.75,
    max_acceptable_leak_rate=0.0,
    max_acceptable_false_positive_rate=0.10,
)

SWARM_SATURATION = AdversarialScenario(
    scenario_id="swarm_saturation",
    name="Swarm Saturation",
    description=(
        "A large swarm arrives in a compressed time window, saturating the "
        "single beam director's dwell/slew budget. Engagement leaks grow with "
        "swarm density; the platform must keep the leak rate within tolerance."
    ),
    attack_vectors=("swarm_saturation",),
    target_modules=("detection", "tracking", "engagement"),
    seed=1103,
    params={
        "num_drones": 40,
        "arrival_spread_s": 30.0,
        "speed_mps": 30.0,
        "start_distance_km": 2.0,
        "evasion_probability": 0.3,
        "dwell_s": 4.0,
        "slew_s": 1.5,
        "time_limit_s": 120.0,
    },
    expected_detection_rate=1.0,
    max_acceptable_leak_rate=0.50,
    max_acceptable_false_positive_rate=0.0,
)

COORDINATED_MULTI_VECTOR = AdversarialScenario(
    scenario_id="coordinated_multi_vector",
    name="Coordinated Multi-Vector Attack",
    description=(
        "GNSS spoofing, RF jamming, and swarm saturation strike simultaneously. "
        "The decision engine must assess CRITICAL threat and select a full "
        "countermeasure response while the engagement scheduler absorbs the leak."
    ),
    attack_vectors=("gnss_spoof", "rf_jam", "swarm_saturation"),
    target_modules=("detection", "tracking", "engagement", "decision"),
    seed=1104,
    params={
        "swarm_num_drones": 48,
        "swarm_spread_s": 20.0,
        "jam_band_low_mhz": 2400.0,
        "jam_band_high_mhz": 2483.5,
        "gnss_spoofed_measurements": 20,
        "gnss_nominal_measurements": 20,
    },
    expected_detection_rate=0.80,
    max_acceptable_leak_rate=0.60,
    max_acceptable_false_positive_rate=0.10,
)

CONTROLLER_HIJACKING = AdversarialScenario(
    scenario_id="controller_hijacking",
    name="Controller Hijacking",
    description=(
        "An adversary attempts MAVLink-based controller hijack (unsigned "
        "COMMAND_LONG / SET_PARAMETER injection, CVE-2017-15872 pattern). The "
        "platform must detect the signing-bypass signature, classify the "
        "vulnerability, and geolocate the controller via RF direction finding."
    ),
    attack_vectors=("mavlink_command_injection", "controller_hijack"),
    target_modules=("detection", "forensics"),
    seed=1105,
    params={
        "observed_unsigned_messages": 25,
        "vulnerability_ids": ["MAV-2017-001", "MAV-2017-002"],
        "sensor_sites": [
            ("S1", 34.0522, -118.2437, 100.0),
            ("S2", 37.7749, -122.4194, 150.0),
            ("S3", 32.7157, -117.1611, 200.0),
        ],
    },
    expected_detection_rate=0.90,
    max_acceptable_leak_rate=0.0,
    max_acceptable_false_positive_rate=0.05,
)

ALL_SCENARIOS: Tuple[AdversarialScenario, ...] = (
    GNSS_SPOOFING,
    RF_JAMMING,
    SWARM_SATURATION,
    COORDINATED_MULTI_VECTOR,
    CONTROLLER_HIJACKING,
)

SCENARIO_BY_ID = {s.scenario_id: s for s in ALL_SCENARIOS}


def scenario_fingerprint(scenarios: List[AdversarialScenario]) -> str:
    """Deterministic fingerprint of a scenario set (for report IDs)."""
    payload = json.dumps(
        [
            {
                "scenario_id": s.scenario_id,
                "seed": s.seed,
                "params": s.params,
            }
            for s in sorted(scenarios, key=lambda x: x.scenario_id)
        ],
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Persistence (outside the repo)
# ---------------------------------------------------------------------------


class ScenarioStore:
    """Load/save adversarial scenarios under ~/.c-uas-platform/red_team/."""

    def __init__(self, scenarios_dir: str = RED_TEAM_DIR) -> None:
        self.dir = scenarios_dir
        self.path = os.path.join(self.dir, "scenarios.json")

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def save_scenarios(self, scenarios: List[AdversarialScenario]) -> None:
        self.ensure_dir()
        serializable = []
        for s in scenarios:
            d = asdict(s)
            d["attack_vectors"] = list(d["attack_vectors"])
            d["target_modules"] = list(d["target_modules"])
            serializable.append(d)
        with open(self.path, "w") as fh:
            json.dump(serializable, fh, indent=2)

    def load_scenarios(self) -> List[AdversarialScenario]:
        """Return stored scenarios, falling back to the predefined defaults."""
        if not os.path.exists(self.path):
            return list(ALL_SCENARIOS)
        with open(self.path) as fh:
            data = json.load(fh)
        scenarios: List[AdversarialScenario] = []
        for d in data:
            scenarios.append(
                AdversarialScenario(
                    scenario_id=d["scenario_id"],
                    name=d["name"],
                    description=d["description"],
                    attack_vectors=tuple(d.get("attack_vectors", [])),
                    target_modules=tuple(d.get("target_modules", [])),
                    seed=int(d["seed"]),
                    params=d["params"],
                    expected_detection_rate=float(d["expected_detection_rate"]),
                    max_acceptable_leak_rate=float(d["max_acceptable_leak_rate"]),
                    max_acceptable_false_positive_rate=float(
                        d["max_acceptable_false_positive_rate"]
                    ),
                )
            )
        return scenarios

    def list_scenarios(self) -> List[AdversarialScenario]:
        return self.load_scenarios()

    def get_scenario(self, scenario_id: str) -> AdversarialScenario:
        for s in self.load_scenarios():
            if s.scenario_id == scenario_id:
                return s
        raise KeyError(f"Unknown scenario: {scenario_id}")


def default_store() -> ScenarioStore:
    return ScenarioStore()
