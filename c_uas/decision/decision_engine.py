"""
AI Decision Engine: threat assessment and response strategy selection.

Maps swarm state to threat levels (NONE..CRITICAL) and response strategies
(MONITOR..FULL_COUNTERMEASURE). Generates executable system commands.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class ThreatLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ResponseStrategy(Enum):
    NONE = "none"
    MONITOR = "monitor"
    ALERT = "alert"
    TRACK = "track"
    JAM_CONTROL_UPLINK = "jam_control_uplink"
    JAM_SWARM_DISRUPT = "jam_swarm_disrupt"
    LOCATE_CONTROLLER = "locate_controller"
    FULL_COUNTERMEASURE = "full_countermeasure"


@dataclass
class SystemCommand:
    action: str
    params: Dict[str, Any]
    timestamp: float
    priority: int


class DecisionModule:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.response_matrix = {
            ThreatLevel.NONE: ResponseStrategy.MONITOR,
            ThreatLevel.LOW: ResponseStrategy.TRACK,
            ThreatLevel.MEDIUM: ResponseStrategy.JAM_CONTROL_UPLINK,
            ThreatLevel.HIGH: ResponseStrategy.JAM_SWARM_DISRUPT,
            ThreatLevel.CRITICAL: ResponseStrategy.FULL_COUNTERMEASURE,
        }

    def assess_threat(self, swarm_state: Any) -> ThreatLevel:
        num_drones = getattr(swarm_state, "num_drones", 0)
        if num_drones == 0:
            return ThreatLevel.NONE
        if num_drones >= 20:
            return ThreatLevel.CRITICAL
        elif num_drones >= 10:
            return ThreatLevel.HIGH
        elif num_drones >= 3:
            return ThreatLevel.MEDIUM
        elif num_drones >= 1:
            return ThreatLevel.LOW
        return ThreatLevel.NONE

    def select_strategy(
        self,
        threat: ThreatLevel,
        swarm_state: Optional[Any] = None,
    ) -> ResponseStrategy:
        base_strategy = self.response_matrix.get(threat, ResponseStrategy.MONITOR)
        # Override: if controller located, be more targeted at MEDIUM+
        controller_loc = getattr(swarm_state, "controller_location", None) if swarm_state else None
        if controller_loc and threat.value >= ThreatLevel.MEDIUM.value:
            return ResponseStrategy.LOCATE_CONTROLLER
        return base_strategy

    def plan_actions(
        self,
        strategy: ResponseStrategy,
        swarm_state: Optional[Any] = None,
    ) -> List[SystemCommand]:
        import time

        now = time.time()
        actions: List[SystemCommand] = []

        if strategy == ResponseStrategy.MONITOR:
            actions.append(
                SystemCommand(
                    action="scan_rf",
                    params={"duration_s": 1.0},
                    timestamp=now,
                    priority=1,
                )
            )

        elif strategy == ResponseStrategy.TRACK:
            actions.append(
                SystemCommand(
                    action="scan_rf",
                    params={"duration_s": 0.5},
                    timestamp=now,
                    priority=1,
                )
            )
            actions.append(
                SystemCommand(
                    action="direction_find",
                    params={"frequency": 2.44e9},
                    timestamp=now,
                    priority=2,
                )
            )

        elif strategy == ResponseStrategy.JAM_CONTROL_UPLINK:
            actions.append(
                SystemCommand(
                    action="activate_jammer",
                    params={
                        "bands": [2.44e9],
                        "waveform": "noise",
                        "bandwidth": 80e6,
                        "power_dBm": 20,
                    },
                    timestamp=now,
                    priority=3,
                )
            )

        elif strategy == ResponseStrategy.JAM_SWARM_DISRUPT:
            actions.append(
                SystemCommand(
                    action="activate_jammer",
                    params={
                        "bands": [2.44e9, 5.8e9],
                        "waveform": "chirp",
                        "bandwidth": 160e6,
                        "power_dBm": 25,
                    },
                    timestamp=now,
                    priority=3,
                )
            )

        elif strategy == ResponseStrategy.LOCATE_CONTROLLER:
            actions.append(
                SystemCommand(
                    action="multi_station_df",
                    params={"frequency": 2.44e9, "num_stations": 4},
                    timestamp=now,
                    priority=4,
                )
            )

        elif strategy == ResponseStrategy.FULL_COUNTERMEASURE:
            actions.append(
                SystemCommand(
                    action="activate_jammer",
                    params={
                        "bands": [2.44e9, 5.8e9, 915e6],
                        "waveform": "noise",
                        "bandwidth": 200e6,
                        "power_dBm": 30,
                    },
                    timestamp=now,
                    priority=5,
                )
            )
            actions.append(
                SystemCommand(
                    action="multi_station_df",
                    params={"frequency": 2.44e9, "num_stations": 4},
                    timestamp=now,
                    priority=5,
                )
            )
            actions.append(
                SystemCommand(
                    action="alert_authorities",
                    params={"threat_level": "CRITICAL"},
                    timestamp=now,
                    priority=5,
                )
            )

        return actions
