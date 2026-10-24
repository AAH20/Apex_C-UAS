"""Fault injection primitives for the C-UAS platform.

Each fault is a dataclass describing a deterministic failure mode. The
FaultInjector applies faults against real platform components by wrapping
their calls and either raising, delaying, dropping, or degrading outputs.
All faults use a fixed seed so fault patterns are reproducible.

Defensive only: simulates infrastructure failure against real modules. No
live network, no hardware, no effector control.
"""

from __future__ import annotations

import json
import os
import random
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional, Union

CHAOS_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "chaos")


@dataclass(frozen=True)
class Fault:
    """A single injectable fault with deterministic parameters.

    fault_id      : stable identifier, e.g. "network_latency"
    kind          : fault category (latency|loss|crash|timeout|memory)
    target        : component path the fault applies to, e.g. "c_uas.api.server"
    severity      : 0.0 (minor) .. 1.0 (total failure)
    duration_s    : how long the fault stays active, seconds
    seed          : RNG seed for reproducible fault patterns
    active        : whether the fault is currently enabled
    """

    fault_id: str
    kind: str
    target: str
    severity: float
    duration_s: float
    seed: int
    active: bool = True


# --------------------------------------------------------------------------- #
# Predefined deterministic faults
# --------------------------------------------------------------------------- #


def network_latency_fault(target: str, severity: float = 0.5, seed: int = 2001) -> Fault:
    """Added latency on calls to ``target`` (seconds = severity)."""
    return Fault(
        fault_id="network_latency",
        kind="latency",
        target=target,
        severity=severity,
        duration_s=30.0,
        seed=seed,
    )


def packet_loss_fault(target: str, severity: float = 0.3, seed: int = 2002) -> Fault:
    """Fraction of calls to ``target`` dropped (severity = drop probability)."""
    return Fault(
        fault_id="packet_loss",
        kind="loss",
        target=target,
        severity=severity,
        duration_s=30.0,
        seed=seed,
    )


def backend_crash_fault(target: str, severity: float = 1.0, seed: int = 2003) -> Fault:
    """Calls to ``target`` raise (severity = crash probability)."""
    return Fault(
        fault_id="backend_crash",
        kind="crash",
        target=target,
        severity=severity,
        duration_s=30.0,
        seed=seed,
    )


def api_timeout_fault(target: str, severity: float = 1.0, seed: int = 2004) -> Fault:
    """Calls to ``target`` time out (severity = timeout probability)."""
    return Fault(
        fault_id="api_timeout",
        kind="timeout",
        target=target,
        severity=severity,
        duration_s=30.0,
        seed=seed,
    )


def memory_pressure_fault(target: str, severity: float = 0.7, seed: int = 2005) -> Fault:
    """Calls to ``target`` degrade under memory pressure (severity = slowdown)."""
    return Fault(
        fault_id="memory_pressure",
        kind="memory",
        target=target,
        severity=severity,
        duration_s=30.0,
        seed=seed,
    )


ALL_FAULTS: Dict[str, Fault] = {
    f.fault_id: f
    for f in (
        network_latency_fault("c_uas.api.server"),
        packet_loss_fault("c_uas.api.server"),
        backend_crash_fault("c_uas.api.server"),
        api_timeout_fault("c_uas.api.server"),
        memory_pressure_fault("c_uas.api.server"),
    )
}


# --------------------------------------------------------------------------- #
# Injector
# --------------------------------------------------------------------------- #


class FaultInjector:
    """Applies faults to platform components deterministically.

    The injector wraps a callable and, based on the fault kind and severity,
    either delays the call, drops it (raises), crashes it, or times it out.
    A fresh RNG per fault id keeps fault patterns reproducible across runs.
    """

    def __init__(self, faults: Optional[Dict[str, Fault]] = None) -> None:
        self.faults: Dict[str, Fault] = dict(faults or ALL_FAULTS)
        self._active_faults: Dict[str, Fault] = {}
        self._rngs: Dict[str, random.Random] = {}

    # -- fault lifecycle --------------------------------------------------- #

    def activate(self, fault_id_or_fault: Union[str, Fault]) -> None:
        if isinstance(fault_id_or_fault, Fault):
            fault = fault_id_or_fault
            self.faults[fault.fault_id] = fault
            fault_id = fault.fault_id
        else:
            fault_id = fault_id_or_fault
            if fault_id not in self.faults:
                raise KeyError(f"Unknown fault: {fault_id}")
            fault = self.faults[fault_id]
        self._active_faults[fault_id] = fault
        self._rngs[fault_id] = random.Random(fault.seed)

    def deactivate(self, fault_id: str) -> None:
        self._active_faults.pop(fault_id, None)
        self._rngs.pop(fault_id, None)

    def activate_all(self) -> None:
        for fault_id in self.faults:
            self.activate(fault_id)

    def deactivate_all(self) -> None:
        self._active_faults.clear()
        self._rngs.clear()

    def active_faults(self) -> List[str]:
        return sorted(self._active_faults)

    def is_active(self, target: str) -> Optional[Fault]:
        """Return the active fault matching ``target``, else None."""
        for fault in self._active_faults.values():
            if fault.target == target and fault.active:
                return fault
        return None

    # -- application ------------------------------------------------------- #

    def inject(self, target: str, call: Callable[[], Any]) -> Any:
        """Run ``call`` under any active fault for ``target``.

        Returns the call's result when no fault applies. Fault behavior:
          * latency  : sleep severity seconds, then run the call
          * loss     : drop call with probability severity (raise RuntimeError)
          * crash    : raise RuntimeError with probability severity
          * timeout  : raise TimeoutError with probability severity
          * memory   : sleep severity seconds, then run the call (degraded)
        """
        fault = self.is_active(target)
        if fault is None:
            return call()

        rng = self._rngs.get(fault.fault_id)
        if rng is None:
            return call()

        kind = fault.kind
        severity = float(fault.severity)

        if kind == "latency":
            time.sleep(severity)
            return call()

        if kind == "memory":
            time.sleep(severity)
            return call()

        if kind == "loss":
            if rng.random() < severity:
                raise RuntimeError(
                    f"Fault {fault.fault_id}: packet loss on {target}"
                )
            return call()

        if kind == "crash":
            if rng.random() < severity:
                raise RuntimeError(
                    f"Fault {fault.fault_id}: backend crash on {target}"
                )
            return call()

        if kind == "timeout":
            if rng.random() < severity:
                raise TimeoutError(f"Fault {fault.fault_id}: API timeout on {target}")
            return call()

        # Unknown kind: run the call unchanged.
        return call()


# --------------------------------------------------------------------------- #
# Persistence (outside the repo)
# --------------------------------------------------------------------------- #


class FaultStore:
    """Save/load fault definitions under ~/.c-uas-platform/chaos/."""

    def __init__(self, chaos_dir: str = CHAOS_DIR) -> None:
        self.dir = chaos_dir
        self.path = os.path.join(self.dir, "faults.json")

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def save_faults(self, faults: Dict[str, Fault]) -> None:
        self.ensure_dir()
        serializable = {fid: asdict(f) for fid, f in faults.items()}
        with open(self.path, "w") as fh:
            json.dump(serializable, fh, indent=2)

    def load_faults(self) -> Dict[str, Fault]:
        if not os.path.exists(self.path):
            return dict(ALL_FAULTS)
        with open(self.path) as fh:
            data = json.load(fh)
        faults: Dict[str, Fault] = {}
        for fid, d in data.items():
            faults[fid] = Fault(
                fault_id=d["fault_id"],
                kind=d["kind"],
                target=d["target"],
                severity=float(d["severity"]),
                duration_s=float(d["duration_s"]),
                seed=int(d["seed"]),
                active=bool(d.get("active", True)),
            )
        return faults
