"""
Persistence for gateway state under ~/.c-uas-platform/gateway/ (outside repo).

Config, backend states, circuit states, the round-robin index, and a JSONL
routing log are all written to disk so decisions remain reproducible across
process restarts.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any, Dict, Optional

from .circuit import CircuitState
from .config import Backend, GatewayConfig
from .router import BackendState


class GatewayStateStore:
    def __init__(self, state_dir: str) -> None:
        self.state_dir = state_dir
        os.makedirs(self.state_dir, exist_ok=True)

    def _path(self, name: str) -> str:
        return os.path.join(self.state_dir, name)

    def _load_json(self, name: str) -> Optional[Any]:
        path = self._path(name)
        if not os.path.exists(path):
            return None
        with open(path, "r") as fh:
            return json.load(fh)

    def _save_json(self, name: str, data: Any) -> None:
        with open(self._path(name), "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)

    # ---- config ---------------------------------------------------------
    def load_config(self) -> Optional[GatewayConfig]:
        raw = self._load_json("config.json")
        if raw is None:
            return None
        backends = tuple(Backend(**b) for b in raw.get("backends", []))
        return GatewayConfig(
            backends=backends,
            strategy=raw.get("strategy", "round_robin"),
            failure_threshold=raw.get("failure_threshold", 3),
            recovery_timeout_s=raw.get("recovery_timeout_s", 30.0),
            health_interval_s=raw.get("health_interval_s", 10.0),
            seed=raw.get("seed", 42),
            state_dir=self.state_dir,
        )

    def save_config(self, config: GatewayConfig) -> None:
        data = {
            "backends": [asdict(b) for b in config.backends],
            "strategy": config.strategy,
            "failure_threshold": config.failure_threshold,
            "recovery_timeout_s": config.recovery_timeout_s,
            "health_interval_s": config.health_interval_s,
            "seed": config.seed,
            "state_dir": config.state_dir,
        }
        self._save_json("config.json", data)

    # ---- backend states -------------------------------------------------
    def load_backend_states(self) -> Dict[str, BackendState]:
        raw = self._load_json("backend_states.json") or {}
        states: Dict[str, BackendState] = {}
        for bid, d in raw.items():
            states[bid] = BackendState(**d)
        return states

    def save_backend_states(self, states: Dict[str, BackendState]) -> None:
        self._save_json("backend_states.json", {k: asdict(v) for k, v in states.items()})

    # ---- circuit states -------------------------------------------------
    def load_circuit_states(self) -> Dict[str, CircuitState]:
        raw = self._load_json("circuit_states.json") or {}
        states: Dict[str, CircuitState] = {}
        for bid, d in raw.items():
            states[bid] = CircuitState(**d)
        return states

    def save_circuit_states(self, states: Dict[str, CircuitState]) -> None:
        self._save_json("circuit_states.json", {k: asdict(v) for k, v in states.items()})

    # ---- router index ---------------------------------------------------
    def load_rr_index(self) -> int:
        raw = self._load_json("router.json") or {}
        return int(raw.get("rr_index", 0))

    def save_rr_index(self, index: int) -> None:
        self._save_json("router.json", {"rr_index": int(index)})

    # ---- routing log ----------------------------------------------------
    def append_routing_log(self, entry: Dict[str, Any]) -> None:
        path = self._path("routing_log.jsonl")
        with open(path, "a") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
