"""
Action Module: executes system commands (RF scan, direction find, jam, etc.)

In simulation mode, generates results without SDR hardware. In live mode,
would interface with HackRF/USRP. Jamming is safety-gated behind an
authorization flag.
"""

import asyncio
import time
from typing import Any, Dict, List

from .decision_engine import SystemCommand


class ActionModule:
    def __init__(self, config: Dict[str, Any], simulation_mode: bool = True) -> None:
        self.config = config
        self.sim_mode = simulation_mode
        self.jammer_active = False
        self.executed_commands: List[Dict[str, Any]] = []

    async def execute(self, command: SystemCommand) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "command": command.action,
            "status": "executed",
            "timestamp": time.time(),
        }

        if command.action == "scan_rf":
            result["details"] = await self._scan_rf(command.params)
        elif command.action == "direction_find":
            result["details"] = await self._direction_find(command.params)
        elif command.action == "activate_jammer":
            jam_result = await self._activate_jammer(command.params)
            result["details"] = jam_result
            if jam_result.get("status") == "denied":
                result["status"] = "denied"
        elif command.action == "multi_station_df":
            result["details"] = await self._multi_station_df(command.params)
        elif command.action == "alert_authorities":
            result["details"] = await self._alert_authorities(command.params)
        else:
            result["status"] = "unknown_command"

        self.executed_commands.append(result)
        return result

    async def _scan_rf(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if self.sim_mode:
            await asyncio.sleep(0.1)
            import random

            return {
                "status": "scan_complete",
                "detections": random.randint(0, 5),
            }
        return {"status": "not_implemented"}

    async def _direction_find(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if self.sim_mode:
            await asyncio.sleep(0.05)
            import random

            return {
                "status": "df_complete",
                "bearing": random.uniform(-180, 180),
                "confidence": random.uniform(0.5, 1.0),
            }
        return {"status": "not_implemented"}

    async def _activate_jammer(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if not self.config.get("jamming", {}).get("authorized", False):
            return {"status": "denied", "reason": "Jamming not authorized"}
        if self.sim_mode:
            self.jammer_active = True
            return {
                "status": "jammer_activated",
                "bands": params.get("bands"),
                "power_dBm": params.get("power_dBm"),
            }
        return {"status": "not_implemented"}

    async def _multi_station_df(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if self.sim_mode:
            await asyncio.sleep(0.2)
            import random

            return {
                "status": "triangulation_complete",
                "position": (
                    random.uniform(-100, 100),
                    random.uniform(-100, 100),
                ),
                "accuracy_m": random.uniform(5, 50),
            }
        return {"status": "not_implemented"}

    async def _alert_authorities(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "alert_sent",
            "threat_level": params.get("threat_level"),
            "timestamp": time.time(),
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "jammer_active": self.jammer_active,
            "simulation_mode": self.sim_mode,
            "commands_executed": len(self.executed_commands),
        }
