"""
Autonomous compliance agent for GRC_Clab agentic governance.

Deterministic, fixed-interval monitoring loop:

- scans registered AI systems and their controls for violations
- auto-logs each violation to the hash-linked evidence chain
- triggers remediation planning for failed controls

Driven by an external scheduler (cron, systemd timer, or in-process loop)
via is_due() + run_tick(), so tests never block on real sleep.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from c_uas.grc_clab.evidence_chain import EvidenceChain
from c_uas.grc_clab.remediation import RemediationPlanner

DEFAULT_SCAN_INTERVAL_S = 300.0


@dataclass(frozen=True)
class ControlViolation:
    """A detected control violation: an applicable control not implemented."""

    violation_id: str
    detected_at: float
    control_id: str
    system_id: Optional[str]
    description: str
    severity: str  # "low", "medium", "high", "critical"


@dataclass(frozen=True)
class ScanResult:
    """Result of one monitoring cycle."""

    scan_id: str
    scanned_at: float
    interval_s: float
    systems_scanned: int
    violations: List[ControlViolation] = field(default_factory=list)
    evidence_entries: List[str] = field(default_factory=list)
    remediation_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _control_severity(control_id: str) -> str:
    """Deterministic severity by Annex A control domain."""
    parts = control_id.split(".")
    domain = ".".join(parts[:2]) if len(parts) >= 2 else "A.8"
    return {
        "A.5": "high",  # organizational / policy
        "A.6": "high",  # roles / responsibilities
        "A.7": "high",  # risk assessment process
        "A.8": "critical",  # data / input validation / output verification
        "A.9": "medium",  # monitoring and measurement
        "A.10": "high",  # incident management
        "A.11": "medium",  # third-party AI
    }.get(domain, "medium")


class AutonomousAgent:
    """Continuous compliance monitoring agent (deterministic, fixed interval)."""

    def __init__(
        self,
        chain: Optional[EvidenceChain] = None,
        planner: Optional[RemediationPlanner] = None,
        interval_s: float = DEFAULT_SCAN_INTERVAL_S,
    ) -> None:
        self.chain = chain or EvidenceChain()
        self.planner = planner or RemediationPlanner()
        self.interval_s = interval_s
        self._last_tick = 0.0
        self._scans: List[ScanResult] = []

    def is_due(self) -> bool:
        """True if the fixed scan interval has elapsed since the last tick."""
        return time.time() - self._last_tick >= self.interval_s

    def detect_violations(
        self,
        systems: List[Any],
        controls: List[Any],
    ) -> List[ControlViolation]:
        """Pure detection: applicable-but-unimplemented controls are violations."""
        violations: List[ControlViolation] = []
        implemented = {c.control_id for c in controls if c.implemented}
        target = systems[0] if systems else None
        system_id = getattr(target, "system_id", None) if target is not None else None
        for control in sorted(controls, key=lambda c: c.control_id):
            if not control.applicable:
                continue
            if control.control_id in implemented:
                continue
            violations.append(
                ControlViolation(
                    violation_id=f"viol-{uuid.uuid4().hex[:8]}",
                    detected_at=time.time(),
                    control_id=control.control_id,
                    system_id=system_id,
                    description=(
                        f"Applicable control {control.control_id} "
                        f"({control.title}) not implemented."
                    ),
                    severity=_control_severity(control.control_id),
                )
            )
        return violations

    def run_tick(
        self,
        systems: List[Any],
        controls: List[Any],
    ) -> ScanResult:
        """One monitoring cycle: detect violations, log evidence, trigger remediation."""
        violations = self.detect_violations(systems, controls)
        evidence_ids: List[str] = []
        for v in violations:
            entry = self.chain.log(
                "control_violation",
                {
                    "violation_id": v.violation_id,
                    "control_id": v.control_id,
                    "system_id": v.system_id,
                    "severity": v.severity,
                    "description": v.description,
                },
                v.system_id,
            )
            evidence_ids.append(entry.entry_id)
            self.planner.add_violation(v)

        result = ScanResult(
            scan_id=f"scan-{uuid.uuid4().hex[:8]}",
            scanned_at=time.time(),
            interval_s=self.interval_s,
            systems_scanned=len(systems),
            violations=violations,
            evidence_entries=evidence_ids,
            remediation_actions=[a.action_id for a in self.planner.list_actions()],
        )
        self._scans.append(result)
        self._last_tick = time.time()
        return result

    def monitor_loop(
        self,
        systems: List[Any],
        controls: List[Any],
        max_iterations: int = 1,
    ) -> List[ScanResult]:
        """Run cycles while due, capped at max_iterations (deterministic)."""
        results: List[ScanResult] = []
        for _ in range(max_iterations):
            if not self.is_due():
                break
            results.append(self.run_tick(systems, controls))
        return results

    def list_scans(self) -> List[ScanResult]:
        return list(self._scans)
