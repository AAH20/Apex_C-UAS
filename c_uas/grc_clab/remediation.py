"""
Remediation planner for GRC_Clab agentic governance.

Maps failed controls to remediation actions with:

- priority scoring (deterministic, real computed values)
- estimated effort (hours, deterministic per Annex A domain)
- dependency ordering (topological sort)
- persistence under ~/.c-uas-platform/grc_clab/remediation/

Conventions: frozen dataclasses, pure functions, deterministic.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

_REMED_DIR = Path.home() / ".c-uas-platform" / "grc_clab" / "remediation"
_PLANS_FILE = _REMED_DIR / "actions.json"

# Estimated effort (hours) per Annex A control domain.
_EFFORT_BY_DOMAIN: Dict[str, float] = {
    "A.5": 4.0,
    "A.6": 6.0,
    "A.7": 8.0,
    "A.8": 12.0,
    "A.9": 16.0,
    "A.10": 10.0,
    "A.11": 20.0,
}

# Base priority weight per domain (higher = more urgent).
_PRIORITY_WEIGHT: Dict[str, float] = {
    "A.5": 9.0,
    "A.6": 8.0,
    "A.7": 9.0,
    "A.8": 10.0,
    "A.9": 6.0,
    "A.10": 9.0,
    "A.11": 5.0,
}


@dataclass(frozen=True)
class RemediationAction:
    """A proposed remediation action for a failed control."""

    action_id: str
    control_id: str
    title: str
    description: str
    priority_score: float
    estimated_effort_hours: float
    depends_on: List[str] = field(default_factory=list)
    status: str = "proposed"  # proposed, in_progress, completed, rejected
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _domain_of(control_id: str) -> str:
    parts = control_id.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else "A.8"


def estimated_effort_hours(control_id: str) -> float:
    """Pure function: deterministic estimated effort in hours for a control."""
    return _EFFORT_BY_DOMAIN.get(_domain_of(control_id), 8.0)


def priority_score(
    control_id: str,
    violation_severity: str,
    open_risk_count: int = 0,
) -> float:
    """Pure function: deterministic priority score (higher = more urgent).

    Computed from control domain weight, violation severity, and open risk count.
    """
    severity_weight = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}.get(
        violation_severity, 2.0
    )
    base = _PRIORITY_WEIGHT.get(_domain_of(control_id), 5.0)
    return round(base * severity_weight + 0.5 * open_risk_count, 2)


def dependency_order(actions: List[RemediationAction]) -> List[RemediationAction]:
    """Pure function: topological sort of actions by depends_on (deterministic).

    Ties broken by descending priority_score then ascending action_id.
    Cycles are broken deterministically by skipping the back-edge.
    """
    by_id = {a.action_id: a for a in actions}
    ordered: List[RemediationAction] = []
    visited: set = set()
    temp: set = set()

    def visit(node: str) -> None:
        if node in visited or node not in by_id:
            return
        if node in temp:
            return  # cycle: break the back-edge deterministically
        temp.add(node)
        for dep in sorted(by_id[node].depends_on):
            visit(dep)
        temp.discard(node)
        visited.add(node)
        ordered.append(by_id[node])

    for action in sorted(actions, key=lambda a: (-a.priority_score, a.action_id)):
        visit(action.action_id)
    return ordered


def _ensure_dir() -> None:
    _REMED_DIR.mkdir(parents=True, exist_ok=True)


def _load_actions() -> List[RemediationAction]:
    _ensure_dir()
    if not _PLANS_FILE.exists():
        return []
    try:
        rows = json.loads(_PLANS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    return [RemediationAction(**row) for row in rows]


def _save_actions(actions: List[RemediationAction]) -> None:
    _ensure_dir()
    _PLANS_FILE.write_text(json.dumps([a.to_dict() for a in actions], indent=2))


class RemediationPlanner:
    """Maps failed controls to remediation actions with priority and ordering."""

    def __init__(self) -> None:
        self._actions: List[RemediationAction] = _load_actions()

    def add_violation(self, violation: Any) -> RemediationAction:
        """Create (or return existing) remediation action for a control violation."""
        control_id = violation.control_id
        severity = getattr(violation, "severity", "medium")
        description = getattr(violation, "description", control_id)
        existing = [
            a for a in self._actions if a.control_id == control_id and a.status != "rejected"
        ]
        if existing:
            return existing[0]
        action = RemediationAction(
            action_id=f"rem-{uuid.uuid4().hex[:8]}",
            control_id=control_id,
            title=f"Implement {control_id}",
            description=(
                f"Remediate failed control {control_id}: {description} (severity: {severity})."
            ),
            priority_score=priority_score(control_id, severity),
            estimated_effort_hours=estimated_effort_hours(control_id),
            depends_on=[],
            status="proposed",
            created_at=time.time(),
        )
        self._actions.append(action)
        _save_actions(self._actions)
        return action

    def plan_for_controls(
        self,
        failed_controls: List[Any],
        open_risk_count: int = 0,
    ) -> List[RemediationAction]:
        """Plan remediation actions for a list of failed controls."""
        created: List[RemediationAction] = []
        for ctrl in failed_controls:
            control_id = getattr(ctrl, "control_id", ctrl)
            sev = getattr(ctrl, "severity", "medium")
            existing = [
                a for a in self._actions if a.control_id == control_id and a.status != "rejected"
            ]
            if existing:
                continue
            action = RemediationAction(
                action_id=f"rem-{uuid.uuid4().hex[:8]}",
                control_id=control_id,
                title=f"Implement {control_id}",
                description=f"Remediate failed control {control_id}.",
                priority_score=priority_score(control_id, sev, open_risk_count),
                estimated_effort_hours=estimated_effort_hours(control_id),
                depends_on=[],
                status="proposed",
                created_at=time.time(),
            )
            self._actions.append(action)
            created.append(action)
        if created:
            _save_actions(self._actions)
        return created

    def add_dependency(self, action_id: str, depends_on: str) -> bool:
        for i, a in enumerate(self._actions):
            if a.action_id == action_id:
                deps = set(a.depends_on)
                if depends_on not in deps:
                    updated = RemediationAction(
                        **{**a.to_dict(), "depends_on": sorted(deps | {depends_on})}
                    )
                    self._actions[i] = updated
                    _save_actions(self._actions)
                return True
        return False

    def list_actions(self) -> List[RemediationAction]:
        return list(self._actions)

    def list_proposed(self) -> List[RemediationAction]:
        return [a for a in self._actions if a.status == "proposed"]

    def ordered_plan(self) -> List[RemediationAction]:
        return dependency_order(self._actions)

    def mark_completed(self, action_id: str, evidence: str = "") -> bool:
        for i, a in enumerate(self._actions):
            if a.action_id == action_id and a.status == "proposed":
                updated = RemediationAction(
                    **{
                        **a.to_dict(),
                        "status": "completed",
                        "completed_at": time.time(),
                    }
                )
                self._actions[i] = updated
                _save_actions(self._actions)
                return True
        return False
