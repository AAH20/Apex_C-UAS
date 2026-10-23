"""
AI Governance Chassis — ISO 42001 Compliance for Agentic C-UAS Systems.

Implements an AI management system (AIMS) per ISO/IEC 42001:2023 for
agentic counter-UAS components. Provides:

- AI system inventory (register C-UAS modules as ISO 42001 AI systems)
- Risk assessment and treatment (identify, evaluate, treat AI risks)
- Control implementation (ISO 42001 Annex A controls mapped to C-UAS)
- Audit evidence chain (immutable, hash-linked evidence log)
- Incident management (record, classify, track AI incidents)
- Compliance reporting (ISO 42001 conformity status)

Defensive-only: governance, risk, and compliance for defensive C-UAS AI.
No weapons-employment effector, no live SDR, no exploitation code.

All data persisted to ~/.c-uas-platform/governance/ (outside the repo).
Audit evidence is hash-linked for tamper-evidence.

Usage:
    from c_uas.governance import AISystemRegistry, RiskAssessment, ControlImplementation
    from c_uas.governance import AuditEvidenceChain, IncidentManager, ComplianceReporter

    registry = AISystemRegistry()
    sys_id = registry.register("EKF Tracking", "c_uas.tracking.ekf_interceptor", "detection")

    assessor = RiskAssessment()
    risk = assessor.assess(sys_id, "EKF state divergence under sensor noise",
                          likelihood="medium", impact="high")

    controller = ControlImplementation()
    ctrl = controller.implement("A.8.2", "EKF input validation and bounds checking")

    chain = AuditEvidenceChain()
    entry = chain.log("risk_assessment", risk, sys_id)

    mgr = IncidentManager()
    inc = mgr.record("EKF_INTERCEPT_ERROR", "medium", "Intercept prediction off by 3m")

    reporter = ComplianceReporter()
    report = reporter.generate()
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Persistent storage outside the repo — governance data survives repo rebuilds.
_GOV_DIR = Path.home() / ".c-uas-platform" / "governance"
_SYSTEMS_FILE = _GOV_DIR / "ai_systems.json"
_RISKS_FILE = _GOV_DIR / "risks.json"
_CONTROLS_FILE = _GOV_DIR / "controls.json"
_EVIDENCE_FILE = _GOV_DIR / "evidence.json"
_INCIDENTS_FILE = _GOV_DIR / "incidents.json"


def _ensure_dir() -> None:
    _GOV_DIR.mkdir(parents=True, exist_ok=True)


def _load_json(path: Path) -> list:
    _ensure_dir()
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save_json(path: Path, data: list) -> None:
    _ensure_dir()
    path.write_text(json.dumps(data, indent=2))


def _hash_entry(prev_hash: str, payload: Dict[str, Any]) -> str:
    """Hash-link an evidence entry to its predecessor for tamper-evidence."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    material = prev_hash + canonical
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AISystem:
    """An ISO 42001 AI system registered in the C-UAS platform."""

    system_id: str
    name: str
    module_path: str
    lifecycle_stage: str  # "development", "deployment", "operation", "decommission"
    risk_level: str  # "low", "medium", "high", "critical"
    registered_at: float
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Risk:
    """An identified AI risk with assessment and treatment."""

    risk_id: str
    system_id: str
    description: str
    likelihood: str  # "low", "medium", "high"
    impact: str  # "low", "medium", "high"
    risk_level: str  # computed: "low", "medium", "high", "critical"
    treatment: str  # "mitigate", "avoid", "transfer", "accept"
    treatment_plan: str
    status: str  # "open", "in_progress", "closed", "accepted"
    identified_at: float
    closed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Control:
    """An ISO 42001 Annex A control implementation."""

    control_id: str  # e.g. "A.8.2"
    title: str
    description: str
    applicable: bool  # whether this control applies to the C-UAS system
    implemented: bool
    implementation_evidence: str  # pointer to evidence entry or doc
    implemented_at: Optional[float] = None
    last_reviewed: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceEntry:
    """An immutable audit evidence entry, hash-linked to its predecessor."""

    entry_id: str
    timestamp: float
    event_type: str  # "risk_assessment", "control_implementation", "incident", ...
    system_id: Optional[str]
    payload: Dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Incident:
    """An AI incident record."""

    incident_id: str
    system_id: Optional[str]
    title: str
    description: str
    severity: str  # "low", "medium", "high", "critical"
    detected_at: float
    status: str  # "open", "investigating", "resolved", "closed"
    resolution: Optional[str] = None
    resolved_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ComplianceReport:
    """ISO 42001 compliance status report."""

    generated_at: float
    total_ai_systems: int
    total_risks: int
    open_risks: int
    total_controls: int
    implemented_controls: int
    total_incidents: int
    open_incidents: int
    compliance_percentage: float
    overall_status: str  # "compliant", "partial", "non_compliant"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------


def _compute_risk_level(likelihood: str, impact: str) -> str:
    """Compute ISO 42001 risk level from likelihood and impact."""
    scores = {"low": 1, "medium": 2, "high": 3}
    l = scores.get(likelihood, 1)
    i = scores.get(impact, 1)
    product = l * i
    if product >= 9:
        return "critical"
    if product >= 6:
        return "high"
    if product >= 3:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Managers
# ---------------------------------------------------------------------------


class AISystemRegistry:
    """Registry of ISO 42001 AI systems in the C-UAS platform."""

    def __init__(self) -> None:
        self._systems: Dict[str, AISystem] = {}
        for row in _load_json(_SYSTEMS_FILE):
            sys = AISystem(**row)
            self._systems[sys.system_id] = sys

    def register(
        self,
        name: str,
        module_path: str,
        lifecycle_stage: str,
        risk_level: str = "medium",
        description: str = "",
    ) -> str:
        """Register a new AI system. Returns the system_id."""
        system_id = f"ais-{uuid.uuid4().hex[:8]}"
        sys = AISystem(
            system_id=system_id,
            name=name,
            module_path=module_path,
            lifecycle_stage=lifecycle_stage,
            risk_level=risk_level,
            registered_at=time.time(),
            description=description,
        )
        self._systems[system_id] = sys
        _save_json(_SYSTEMS_FILE, [s.to_dict() for s in self._systems.values()])
        return system_id

    def get(self, system_id: str) -> Optional[AISystem]:
        return self._systems.get(system_id)

    def list_all(self) -> List[AISystem]:
        return list(self._systems.values())

    def list_by_risk(self, risk_level: str) -> List[AISystem]:
        return [s for s in self._systems.values() if s.risk_level == risk_level]

    def update_risk_level(self, system_id: str, risk_level: str) -> bool:
        sys = self._systems.get(system_id)
        if sys is None:
            return False
        updated = AISystem(
            system_id=sys.system_id,
            name=sys.name,
            module_path=sys.module_path,
            lifecycle_stage=sys.lifecycle_stage,
            risk_level=risk_level,
            registered_at=sys.registered_at,
            description=sys.description,
        )
        self._systems[system_id] = updated
        _save_json(_SYSTEMS_FILE, [s.to_dict() for s in self._systems.values()])
        return True


class RiskAssessment:
    """Identify, assess, and treat AI risks per ISO 42001 Clause 6."""

    def __init__(self) -> None:
        self._risks: Dict[str, Risk] = {}
        for row in _load_json(_RISKS_FILE):
            risk = Risk(**row)
            self._risks[risk.risk_id] = risk

    def assess(
        self,
        system_id: str,
        description: str,
        likelihood: str,
        impact: str,
        treatment: str = "mitigate",
        treatment_plan: str = "",
    ) -> Risk:
        """Create and record a risk assessment."""
        risk_id = f"risk-{uuid.uuid4().hex[:8]}"
        risk_level = _compute_risk_level(likelihood, impact)
        risk = Risk(
            risk_id=risk_id,
            system_id=system_id,
            description=description,
            likelihood=likelihood,
            impact=impact,
            risk_level=risk_level,
            treatment=treatment,
            treatment_plan=treatment_plan,
            status="open",
            identified_at=time.time(),
        )
        self._risks[risk_id] = risk
        _save_json(_RISKS_FILE, [r.to_dict() for r in self._risks.values()])
        return risk

    def get(self, risk_id: str) -> Optional[Risk]:
        return self._risks.get(risk_id)

    def list_all(self) -> List[Risk]:
        return list(self._risks.values())

    def list_open(self) -> List[Risk]:
        return [r for r in self._risks.values() if r.status == "open"]

    def close_risk(self, risk_id: str) -> bool:
        risk = self._risks.get(risk_id)
        if risk is None:
            return False
        updated = Risk(
            risk_id=risk.risk_id,
            system_id=risk.system_id,
            description=risk.description,
            likelihood=risk.likelihood,
            impact=risk.impact,
            risk_level=risk.risk_level,
            treatment=risk.treatment,
            treatment_plan=risk.treatment_plan,
            status="closed",
            identified_at=risk.identified_at,
            closed_at=time.time(),
        )
        self._risks[risk_id] = updated
        _save_json(_RISKS_FILE, [r.to_dict() for r in self._risks.values()])
        return True


class ControlImplementation:
    """Implement ISO 42001 Annex A controls for C-UAS AI systems."""

    # Default Annex A controls relevant to agentic C-UAS
    DEFAULT_CONTROLS: List[Dict[str, Any]] = [
        {
            "control_id": "A.5.1",
            "title": "AI policy",
            "description": "Establish AI policy covering responsible AI development and use.",
        },
        {
            "control_id": "A.5.2",
            "title": "AI system inventory",
            "description": "Maintain an inventory of all AI systems and their purposes.",
        },
        {
            "control_id": "A.6.1",
            "title": "Roles and responsibilities",
            "description": "Assign AI-related roles and responsibilities.",
        },
        {
            "control_id": "A.7.1",
            "title": "AI risk assessment process",
            "description": "Define and maintain a process for AI risk assessment.",
        },
        {
            "control_id": "A.8.1",
            "title": "Data governance",
            "description": "Ensure training and operational data quality and provenance.",
        },
        {
            "control_id": "A.8.2",
            "title": "Input validation",
            "description": "Validate all inputs to AI systems (RF signals, GNSS, tracks).",
        },
        {
            "control_id": "A.8.3",
            "title": "Output verification",
            "description": "Verify AI system outputs before acting (engagement decisions).",
        },
        {
            "control_id": "A.9.1",
            "title": "Monitoring and measurement",
            "description": "Continuously monitor AI system performance and anomalies.",
        },
        {
            "control_id": "A.10.1",
            "title": "Incident management",
            "description": "Detect, report, and respond to AI incidents.",
        },
        {
            "control_id": "A.11.1",
            "title": "Third-party AI",
            "description": "Manage risks from third-party AI components and models.",
        },
    ]

    def __init__(self) -> None:
        self._controls: Dict[str, Control] = {}
        for row in _load_json(_CONTROLS_FILE):
            ctrl = Control(**row)
            self._controls[ctrl.control_id] = ctrl
        # Seed defaults for controls not yet in storage
        existing_ids = set(self._controls.keys())
        for dc in self.DEFAULT_CONTROLS:
            if dc["control_id"] not in existing_ids:
                ctrl = Control(
                    control_id=dc["control_id"],
                    title=dc["title"],
                    description=dc["description"],
                    applicable=True,
                    implemented=False,
                    implementation_evidence="",
                )
                self._controls[ctrl.control_id] = ctrl
        _save_json(_CONTROLS_FILE, [c.to_dict() for c in self._controls.values()])

    def get(self, control_id: str) -> Optional[Control]:
        return self._controls.get(control_id)

    def list_all(self) -> List[Control]:
        return list(self._controls.values())

    def list_implemented(self) -> List[Control]:
        return [c for c in self._controls.values() if c.implemented]

    def implement(
        self,
        control_id: str,
        evidence: str,
        implemented_at: Optional[float] = None,
    ) -> Optional[Control]:
        """Mark a control as implemented with evidence pointer."""
        ctrl = self._controls.get(control_id)
        if ctrl is None:
            return None
        updated = Control(
            control_id=ctrl.control_id,
            title=ctrl.title,
            description=ctrl.description,
            applicable=ctrl.applicable,
            implemented=True,
            implementation_evidence=evidence,
            implemented_at=implemented_at or time.time(),
            last_reviewed=ctrl.last_reviewed,
        )
        self._controls[control_id] = updated
        _save_json(_CONTROLS_FILE, [c.to_dict() for c in self._controls.values()])
        return updated

    def mark_not_applicable(self, control_id: str) -> Optional[Control]:
        ctrl = self._controls.get(control_id)
        if ctrl is None:
            return None
        updated = Control(
            control_id=ctrl.control_id,
            title=ctrl.title,
            description=ctrl.description,
            applicable=False,
            implemented=ctrl.implemented,
            implementation_evidence=ctrl.implementation_evidence,
            implemented_at=ctrl.implemented_at,
            last_reviewed=ctrl.last_reviewed,
        )
        self._controls[control_id] = updated
        _save_json(_CONTROLS_FILE, [c.to_dict() for c in self._controls.values()])
        return updated


class AuditEvidenceChain:
    """Immutable, hash-linked audit evidence chain per ISO 42001 Clause 9."""

    def __init__(self) -> None:
        self._entries: List[EvidenceEntry] = []
        for row in _load_json(_EVIDENCE_FILE):
            entry = EvidenceEntry(**row)
            self._entries.append(entry)

    def _prev_hash(self) -> str:
        if not self._entries:
            return "0" * 64  # genesis hash
        return self._entries[-1].entry_hash

    def log(
        self,
        event_type: str,
        payload: Dict[str, Any],
        system_id: Optional[str] = None,
    ) -> EvidenceEntry:
        """Append a new evidence entry, hash-linked to its predecessor."""
        entry_id = f"ev-{uuid.uuid4().hex[:8]}"
        prev_hash = self._prev_hash()
        entry_hash = _hash_entry(prev_hash, payload)
        entry = EvidenceEntry(
            entry_id=entry_id,
            timestamp=time.time(),
            event_type=event_type,
            system_id=system_id,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        _save_json(_EVIDENCE_FILE, [e.to_dict() for e in self._entries])
        return entry

    def list_all(self) -> List[EvidenceEntry]:
        return list(self._entries)

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire evidence chain."""
        prev_hash = "0" * 64
        for entry in self._entries:
            expected_hash = _hash_entry(prev_hash, entry.payload)
            if entry.prev_hash != prev_hash:
                return False
            if entry.entry_hash != expected_hash:
                return False
            prev_hash = entry.entry_hash
        return True


class IncidentManager:
    """Record and manage AI incidents per ISO 42001 Clause 10."""

    def __init__(self) -> None:
        self._incidents: Dict[str, Incident] = {}
        for row in _load_json(_INCIDENTS_FILE):
            inc = Incident(**row)
            self._incidents[inc.incident_id] = inc

    def record(
        self,
        title: str,
        description: str,
        severity: str,
        system_id: Optional[str] = None,
    ) -> Incident:
        """Record a new AI incident."""
        incident_id = f"inc-{uuid.uuid4().hex[:8]}"
        inc = Incident(
            incident_id=incident_id,
            system_id=system_id,
            title=title,
            description=description,
            severity=severity,
            detected_at=time.time(),
            status="open",
        )
        self._incidents[incident_id] = inc
        _save_json(_INCIDENTS_FILE, [i.to_dict() for i in self._incidents.values()])
        return inc

    def get(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def list_all(self) -> List[Incident]:
        return list(self._incidents.values())

    def list_open(self) -> List[Incident]:
        return [i for i in self._incidents.values() if i.status == "open"]

    def resolve(self, incident_id: str, resolution: str) -> bool:
        inc = self._incidents.get(incident_id)
        if inc is None:
            return False
        updated = Incident(
            incident_id=inc.incident_id,
            system_id=inc.system_id,
            title=inc.title,
            description=inc.description,
            severity=inc.severity,
            detected_at=inc.detected_at,
            status="resolved",
            resolution=resolution,
            resolved_at=time.time(),
        )
        self._incidents[incident_id] = updated
        _save_json(_INCIDENTS_FILE, [i.to_dict() for i in self._incidents.values()])
        return True


class ComplianceReporter:
    """Generate ISO 42001 compliance reports."""

    def __init__(
        self,
        registry: Optional[AISystemRegistry] = None,
        assessor: Optional[RiskAssessment] = None,
        controller: Optional[ControlImplementation] = None,
        chain: Optional[AuditEvidenceChain] = None,
        mgr: Optional[IncidentManager] = None,
    ) -> None:
        self.registry = registry or AISystemRegistry()
        self.assessor = assessor or RiskAssessment()
        self.controller = controller or ControlImplementation()
        self.chain = chain or AuditEvidenceChain()
        self.mgr = mgr or IncidentManager()

    def generate(self) -> ComplianceReport:
        """Generate a full ISO 42001 compliance report."""
        systems = self.registry.list_all()
        risks = self.assessor.list_all()
        open_risks = self.assessor.list_open()
        controls = self.controller.list_all()
        implemented = self.controller.list_implemented()
        incidents = self.mgr.list_all()
        open_incidents = self.mgr.list_open()

        total_controls = len(controls)
        impl_controls = len(implemented)
        applicable_controls = [c for c in controls if c.applicable]
        if applicable_controls:
            impl_ratio = impl_controls / len(applicable_controls)
        else:
            impl_ratio = 1.0

        risk_penalty = len(open_risks) * 0.1
        incident_penalty = len(open_incidents) * 0.05
        compliance_pct = max(
            0.0, min(100.0, impl_ratio * 100.0 - risk_penalty * 10 - incident_penalty * 10)
        )

        if compliance_pct >= 90:
            status = "compliant"
        elif compliance_pct >= 60:
            status = "partial"
        else:
            status = "non_compliant"

        return ComplianceReport(
            generated_at=time.time(),
            total_ai_systems=len(systems),
            total_risks=len(risks),
            open_risks=len(open_risks),
            total_controls=len(controls),
            implemented_controls=impl_controls,
            total_incidents=len(incidents),
            open_incidents=len(open_incidents),
            compliance_percentage=round(compliance_pct, 2),
            overall_status=status,
        )
