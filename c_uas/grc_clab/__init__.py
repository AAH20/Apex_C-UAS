"""
GRC_Clab — Agentic AI Governance Engine for ISO 42001 Compliance.

Autonomous, continuous governance for agentic C-UAS AI systems. Provides:

- AutonomousAgent: periodically scans registered AI systems for new risks
- EvidenceAutoLogger: auto-logs evidence from detection, tracking, engagement,
  and forensics events into the ISO 42001 audit evidence chain
- ComplianceMonitor: continuous compliance scoring with drift detection
- RemediationPlanner: maps open risks to unimplemented Annex A controls
- Scheduled compliance reporting (cron-like tick plus event-driven triggers)

Integrates with c_uas.governance (import and extend, never duplicates).

Defensive-only: governance, risk, and compliance for defensive C-UAS AI.
No weapons-employment effector, no live SDR, no exploitation code.

All data persisted to ~/.c-uas-platform/grc_clab/ (outside the repo).
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from c_uas.governance import (
    AISystemRegistry,
    AuditEvidenceChain,
    ComplianceReporter,
    ControlImplementation,
    IncidentManager,
    RiskAssessment,
)

# Persistent storage outside the repo — grc_clab state survives repo rebuilds.
_GRC_DIR = Path.home() / ".c-uas-platform" / "grc_clab"
_SCANS_FILE = _GRC_DIR / "scan_logs.json"
_EVIDENCE_FILE = _GRC_DIR / "auto_evidence.json"
_SNAPSHOTS_FILE = _GRC_DIR / "compliance_snapshots.json"
_ALERTS_FILE = _GRC_DIR / "drift_alerts.json"
_PLANS_FILE = _GRC_DIR / "remediation_plans.json"
_STATE_FILE = _GRC_DIR / "scheduler_state.json"

# Drift sensitivity: compliance-point change that triggers a drift alert.
DRIFT_THRESHOLD_POINTS = 1.0

# Default scan interval in seconds (cron-like tick).
DEFAULT_SCAN_INTERVAL_S = 300

# Event domains the EvidenceAutoLogger ingests.
EVENT_DOMAINS: Dict[str, str] = {
    "detection": "RF signal classification / GNSS spoofing detection",
    "tracking": "EKF trajectory prediction and intercept estimation",
    "engagement": "NP-hard engagement scheduling and fire control",
    "forensics": "Ed25519-signed airspace intrusion dossiers",
}


def _ensure_dir() -> None:
    _GRC_DIR.mkdir(parents=True, exist_ok=True)


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


def _load_object(path: Path, default: Any) -> Any:
    _ensure_dir()
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return default


def _save_object(path: Path, data: Any) -> None:
    _ensure_dir()
    path.write_text(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Pure functions (deterministic, real computed values)
# ---------------------------------------------------------------------------


def _event_risk_level(event_type: str, system_risk_level: str) -> str:
    """Derive a risk level for an auto-detected event.

    Deterministic combination of event domain and the system's own risk level.
    detection/forensics events rate one step below the system risk;
    tracking/engagement events match the system risk.
    """
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    base = order.get(system_risk_level, 1)
    step = 0 if event_type in ("tracking", "engagement") else 1
    level = max(0, min(3, base - step))
    for name, value in order.items():
        if value == level:
            return name
    return "medium"


def _risk_to_control(risk: Any) -> str:
    """Map an open risk to the Annex A control that best treats it (deterministic)."""
    text = (getattr(risk, "description", "") + " " + getattr(risk, "treatment_plan", "")).lower()
    if any(k in text for k in ("input", "validation", "rf", "gnss", "signal", "sensor")):
        return "A.8.2"
    if any(k in text for k in ("output", "engagement", "fire control", "decision")):
        return "A.8.3"
    if any(k in text for k in ("monitor", "anomaly", "performance", "drift")):
        return "A.9.1"
    if "incident" in text:
        return "A.10.1"
    if any(k in text for k in ("third-party", "component", "model", "supply")):
        return "A.11.1"
    if any(k in text for k in ("data", "training", "provenance", "quality")):
        return "A.8.1"
    if "policy" in text:
        return "A.5.1"
    if "inventory" in text:
        return "A.5.2"
    if any(k in text for k in ("role", "responsibilit")):
        return "A.6.1"
    if "risk assessment" in text:
        return "A.7.1"
    return "A.8.2"  # default: validate inputs to the AI system


def _domain_for_module(module_path: str) -> str:
    """Guess the governance domain from a system module path (deterministic)."""
    text = module_path.lower()
    if "track" in text or "ekf" in text or "intercept" in text:
        return "tracking"
    if "engage" in text or "schedul" in text or "fire" in text:
        return "engagement"
    if "forens" in text or "dossier" in text or "sign" in text:
        return "forensics"
    if "detect" in text or "rf" in text or "gnss" in text or "spoof" in text:
        return "detection"
    return "detection"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanRecord:
    """A single autonomous-agent scan cycle result."""

    scan_id: str
    scanned_at: float
    trigger: str  # "tick" or "event"
    systems_scanned: int
    new_risk_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AutoEvidenceEntry:
    """Evidence auto-logged from a C-UAS system event, linked to the governance chain."""

    entry_id: str
    timestamp: float
    event_type: str  # "detection", "tracking", "engagement", "forensics"
    system_id: Optional[str]
    source: str  # e.g. "c_uas.detection.rf_classifier"
    payload: Dict[str, Any]
    governance_entry_id: str  # pointer into the shared AuditEvidenceChain

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ComplianceSnapshot:
    """A point-in-time compliance score for drift detection."""

    snapshot_id: str
    generated_at: float
    compliance_percentage: float
    overall_status: str
    total_ai_systems: int
    total_risks: int
    open_risks: int
    total_controls: int
    implemented_controls: int
    total_incidents: int
    open_incidents: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DriftAlert:
    """A compliance drift alert produced when the score moves between snapshots."""

    alert_id: str
    detected_at: float
    metric: str
    previous_value: Any
    current_value: Any
    direction: str  # "up" or "down"
    severity: str  # "low", "medium", "high"
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RemediationPlan:
    """A suggested control implementation for an open risk."""

    plan_id: str
    risk_id: str
    control_id: str
    rationale: str
    status: str  # "proposed", "implemented", "rejected"
    created_at: float
    implemented_at: Optional[float] = None
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScheduleState:
    """Persistent cron-like scheduler state."""

    last_tick: float = 0.0
    interval_s: float = DEFAULT_SCAN_INTERVAL_S
    next_report_at: float = 0.0
    reports_generated: int = 0
    ticks_run: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# AutonomousAgent — periodic risk scanning
# ---------------------------------------------------------------------------


class AutonomousAgent:
    """Periodically scans registered AI systems for new risks.

    One call to run_tick() is a single scan cycle. is_due() reports whether the
    configured interval has elapsed since the last tick, so an external scheduler
    (cron, systemd timer, or an in-process loop) can drive the agent without
    blocking tests on real sleep.
    """

    def __init__(
        self,
        registry: Optional[AISystemRegistry] = None,
        assessor: Optional[RiskAssessment] = None,
        chain: Optional[AuditEvidenceChain] = None,
        interval_s: float = DEFAULT_SCAN_INTERVAL_S,
    ) -> None:
        self.registry = registry or AISystemRegistry()
        self.assessor = assessor or RiskAssessment()
        self.chain = chain or AuditEvidenceChain()
        self._scans: List[ScanRecord] = [ScanRecord(**row) for row in _load_json(_SCANS_FILE)]
        state_raw = _load_object(_STATE_FILE, None)
        if isinstance(state_raw, dict):
            state_raw.setdefault("interval_s", interval_s)
            self._state = ScheduleState(**state_raw)
        else:
            self._state = ScheduleState(interval_s=interval_s)

    def is_due(self) -> bool:
        """True if the scan interval has elapsed since the last tick."""
        return time.time() - self._state.last_tick >= self._state.interval_s

    def _candidate_risk(self, system: Any) -> Optional[Dict[str, Any]]:
        """Deterministically synthesize a candidate risk for an unassessed system.

        Returns None when the system already has an open risk (no duplicate risk
        spam on every tick).
        """
        existing = [
            r
            for r in self.assessor.list_all()
            if r.system_id == system.system_id and r.status == "open"
        ]
        if existing:
            return None
        domain = _domain_for_module(system.module_path)
        _level = _event_risk_level(domain, system.risk_level)
        descriptions = {
            "detection": f"RF classification drift risk in {system.name} ({system.module_path})",
            "tracking": f"EKF state-divergence risk in {system.name} under sensor noise",
            "engagement": f"Engagement-scheduling deadline-miss risk in {system.name}",
            "forensics": f"Forensic-dossier signature-chain integrity risk in {system.name}",
        }
        plans = {
            "detection": "Retrain classifier on current RF signatures; validate inputs per A.8.2.",
            "tracking": "Bound EKF innovation gates; add input validation per A.8.2.",
            "engagement": "Add deadline-aware scheduling and output verification per A.8.3.",
            "forensics": "Hash-link dossiers and verify the chain per Clause 9.",
        }
        return {
            "system_id": system.system_id,
            "description": descriptions[domain],
            "likelihood": "medium",
            "impact": "high" if system.risk_level in ("high", "critical") else "medium",
            "treatment": "mitigate",
            "treatment_plan": plans[domain],
        }

    def scan_systems(self, trigger: str = "tick") -> ScanRecord:
        """Run one scan over all registered AI systems and file new risks.

        Returns the ScanRecord for this cycle.
        """
        systems = self.registry.list_all()
        new_risk_ids: List[str] = []
        for system in systems:
            candidate = self._candidate_risk(system)
            if candidate is None:
                continue
            risk = self.assessor.assess(
                system_id=candidate["system_id"],
                description=candidate["description"],
                likelihood=candidate["likelihood"],
                impact=candidate["impact"],
                treatment=candidate["treatment"],
                treatment_plan=candidate["treatment_plan"],
            )
            self.chain.log(
                "autonomous_scan_risk",
                {"risk_id": risk.risk_id, "system_id": system.system_id},
                system.system_id,
            )
            new_risk_ids.append(risk.risk_id)

        record = ScanRecord(
            scan_id=f"scan-{uuid.uuid4().hex[:8]}",
            scanned_at=time.time(),
            trigger=trigger,
            systems_scanned=len(systems),
            new_risk_ids=new_risk_ids,
        )
        self._scans.append(record)
        _save_json(_SCANS_FILE, [s.to_dict() for s in self._scans])
        return record

    def run_tick(self) -> ScanRecord:
        """Execute one scheduled scan cycle if due; otherwise return a no-op record."""
        if not self.is_due():
            return ScanRecord(
                scan_id=f"scan-{uuid.uuid4().hex[:8]}",
                scanned_at=time.time(),
                trigger="skipped",
                systems_scanned=0,
                new_risk_ids=[],
            )
        self._state = ScheduleState(
            last_tick=time.time(),
            interval_s=self._state.interval_s,
            next_report_at=self._state.next_report_at,
            reports_generated=self._state.reports_generated,
            ticks_run=self._state.ticks_run + 1,
        )
        _save_object(_STATE_FILE, self._state.to_dict())
        return self.scan_systems(trigger="tick")


# ---------------------------------------------------------------------------
# EvidenceAutoLogger — automatic evidence logging from system events
# ---------------------------------------------------------------------------


class EvidenceAutoLogger:
    """Automatically logs C-UAS system events into the ISO 42001 evidence chain.

    Event types: detection, tracking, engagement, forensics. Each event is
    written to the shared AuditEvidenceChain and mirrored locally for fast
    agentic replay.
    """

    def __init__(self, chain: Optional[AuditEvidenceChain] = None) -> None:
        self.chain = chain or AuditEvidenceChain()
        self._entries: List[AutoEvidenceEntry] = [
            AutoEvidenceEntry(**row) for row in _load_json(_EVIDENCE_FILE)
        ]

    def log_event(
        self,
        event_type: str,
        system_id: Optional[str],
        source: str,
        payload: Dict[str, Any],
    ) -> AutoEvidenceEntry:
        """Log one event to the governance chain and the local auto-evidence store."""
        if event_type not in EVENT_DOMAINS:
            raise ValueError(f"Unknown event_type: {event_type}")
        gov_entry = self.chain.log(
            f"auto:{event_type}",
            {"system_id": system_id, "source": source, "payload": payload},
            system_id,
        )
        entry = AutoEvidenceEntry(
            entry_id=f"ae-{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            event_type=event_type,
            system_id=system_id,
            source=source,
            payload=payload,
            governance_entry_id=gov_entry.entry_id,
        )
        self._entries.append(entry)
        _save_json(_EVIDENCE_FILE, [e.to_dict() for e in self._entries])
        return entry

    def log_detection_event(
        self, system_id: Optional[str], source: str, payload: Dict[str, Any]
    ) -> AutoEvidenceEntry:
        return self.log_event("detection", system_id, source, payload)

    def log_tracking_event(
        self, system_id: Optional[str], source: str, payload: Dict[str, Any]
    ) -> AutoEvidenceEntry:
        return self.log_event("tracking", system_id, source, payload)

    def log_engagement_event(
        self, system_id: Optional[str], source: str, payload: Dict[str, Any]
    ) -> AutoEvidenceEntry:
        return self.log_event("engagement", system_id, source, payload)

    def log_forensics_event(
        self, system_id: Optional[str], source: str, payload: Dict[str, Any]
    ) -> AutoEvidenceEntry:
        return self.log_event("forensics", system_id, source, payload)

    def process_event_stream(self, events: List[Dict[str, Any]]) -> List[AutoEvidenceEntry]:
        """Log a batch of events; each event dict needs event_type/system_id/source/payload."""
        return [
            self.log_event(e["event_type"], e.get("system_id"), e["source"], e["payload"])
            for e in events
        ]

    def list_all(self) -> List[AutoEvidenceEntry]:
        return list(self._entries)

    def list_by_type(self, event_type: str) -> List[AutoEvidenceEntry]:
        return [e for e in self._entries if e.event_type == event_type]

    def verify_chain(self) -> bool:
        """Verify the underlying governance evidence chain remains intact."""
        return self.chain.verify_chain()


# ---------------------------------------------------------------------------
# ComplianceMonitor — continuous scoring with drift detection
# ---------------------------------------------------------------------------


class ComplianceMonitor:
    """Continuous compliance scoring with drift detection.

    Each score() call generates a fresh ISO 42001 compliance report, stores a
    snapshot, and compares it to the previous snapshot to emit drift alerts.
    """

    def __init__(self, reporter: Optional[ComplianceReporter] = None) -> None:
        self.reporter = reporter or ComplianceReporter()
        self._snapshots: List[ComplianceSnapshot] = [
            ComplianceSnapshot(**row) for row in _load_json(_SNAPSHOTS_FILE)
        ]
        self._alerts: List[DriftAlert] = [DriftAlert(**row) for row in _load_json(_ALERTS_FILE)]

    def _last_snapshot(self) -> Optional[ComplianceSnapshot]:
        return self._snapshots[-1] if self._snapshots else None

    def _detect_drift(
        self, previous: ComplianceSnapshot, report: Any, snapshot: ComplianceSnapshot
    ) -> List[DriftAlert]:
        alerts: List[DriftAlert] = []
        delta = report.compliance_percentage - previous.compliance_percentage
        if abs(delta) >= DRIFT_THRESHOLD_POINTS:
            direction = "up" if delta > 0 else "down"
            severity = "high" if abs(delta) >= 10 else ("medium" if abs(delta) >= 5 else "low")
            alerts.append(
                DriftAlert(
                    alert_id=f"drift-{uuid.uuid4().hex[:8]}",
                    detected_at=time.time(),
                    metric="compliance_percentage",
                    previous_value=previous.compliance_percentage,
                    current_value=report.compliance_percentage,
                    direction=direction,
                    severity=severity,
                    description=(
                        f"Compliance moved {direction} by {abs(delta):.1f} points "
                        f"({previous.compliance_percentage}% -> {report.compliance_percentage}%)."
                    ),
                )
            )
        if report.open_risks != previous.open_risks:
            direction = "up" if report.open_risks > previous.open_risks else "down"
            alerts.append(
                DriftAlert(
                    alert_id=f"drift-{uuid.uuid4().hex[:8]}",
                    detected_at=time.time(),
                    metric="open_risks",
                    previous_value=previous.open_risks,
                    current_value=report.open_risks,
                    direction=direction,
                    severity="high" if report.open_risks > previous.open_risks else "low",
                    description=(
                        f"Open risks changed {previous.open_risks} -> {report.open_risks}."
                    ),
                )
            )
        if report.open_incidents != previous.open_incidents:
            direction = "up" if report.open_incidents > previous.open_incidents else "down"
            alerts.append(
                DriftAlert(
                    alert_id=f"drift-{uuid.uuid4().hex[:8]}",
                    detected_at=time.time(),
                    metric="open_incidents",
                    previous_value=previous.open_incidents,
                    current_value=report.open_incidents,
                    direction=direction,
                    severity="high" if report.open_incidents > previous.open_incidents else "low",
                    description=(
                        "Open incidents changed "
                        f"{previous.open_incidents} -> {report.open_incidents}."
                    ),
                ),
            )
        return alerts

    def score(self) -> tuple:
        """Generate a report, snapshot it, detect drift, persist.

        Returns (report, drift_delta, alerts).
        """
        report = self.reporter.generate()
        previous = self._last_snapshot()
        drift_delta = 0.0
        alerts: List[DriftAlert] = []
        if previous is not None:
            drift_delta = report.compliance_percentage - previous.compliance_percentage
            alerts = self._detect_drift(previous, report, snapshot := self._snapshot(report))
        else:
            snapshot = self._snapshot(report)
        self._snapshots.append(snapshot)
        _save_json(_SNAPSHOTS_FILE, [s.to_dict() for s in self._snapshots])
        if alerts:
            self._alerts.extend(alerts)
            _save_json(_ALERTS_FILE, [a.to_dict() for a in self._alerts])
        return report, drift_delta, alerts

    def _snapshot(self, report: Any) -> ComplianceSnapshot:
        return ComplianceSnapshot(
            snapshot_id=f"snap-{uuid.uuid4().hex[:8]}",
            generated_at=report.generated_at,
            compliance_percentage=report.compliance_percentage,
            overall_status=report.overall_status,
            total_ai_systems=report.total_ai_systems,
            total_risks=report.total_risks,
            open_risks=report.open_risks,
            total_controls=report.total_controls,
            implemented_controls=report.implemented_controls,
            total_incidents=report.total_incidents,
            open_incidents=report.open_incidents,
        )

    def list_snapshots(self) -> List[ComplianceSnapshot]:
        return list(self._snapshots)

    def list_alerts(self) -> List[DriftAlert]:
        return list(self._alerts)

    def is_compliant(self) -> bool:
        report = self.reporter.generate()
        return report.overall_status == "compliant"


# ---------------------------------------------------------------------------
# RemediationPlanner — suggest controls for open risks
# ---------------------------------------------------------------------------


class RemediationPlanner:
    """Maps open risks to unimplemented Annex A controls and tracks remediation."""

    def __init__(
        self,
        assessor: Optional[RiskAssessment] = None,
        controller: Optional[ControlImplementation] = None,
    ) -> None:
        self.assessor = assessor or RiskAssessment()
        self.controller = controller or ControlImplementation()
        self._plans: List[RemediationPlan] = [
            RemediationPlan(**row) for row in _load_json(_PLANS_FILE)
        ]

    def suggest_control(self, risk: Any) -> str:
        """Return the Annex A control id that best treats the given risk."""
        return _risk_to_control(risk)

    def plan_for_open_risks(self) -> List[RemediationPlan]:
        """Propose a remediation plan for every open risk lacking one.

        Only proposes controls that are applicable and not yet implemented.
        Returns the newly proposed plans (already persisted).
        """
        existing_risk_ids = {p.risk_id for p in self._plans if p.status != "rejected"}
        new_plans: List[RemediationPlan] = []
        for risk in self.assessor.list_open():
            if risk.risk_id in existing_risk_ids:
                continue
            control_id = self.suggest_control(risk)
            control = self.controller.get(control_id)
            if control is None or not control.applicable or control.implemented:
                continue
            rationale = (
                f"Open risk '{risk.description}' ({risk.risk_level}) on system "
                f"{risk.system_id} is best treated by implementing {control_id}: "
                f"{control.title}."
            )
            plan = RemediationPlan(
                plan_id=f"plan-{uuid.uuid4().hex[:8]}",
                risk_id=risk.risk_id,
                control_id=control_id,
                rationale=rationale,
                status="proposed",
                created_at=time.time(),
            )
            self._plans.append(plan)
            new_plans.append(plan)
        if new_plans:
            _save_json(_PLANS_FILE, [p.to_dict() for p in self._plans])
        return new_plans

    def apply_plan(self, plan_id: str, evidence: str) -> bool:
        """Implement a proposed plan's control and mark the plan implemented."""
        for i, plan in enumerate(self._plans):
            if plan.plan_id != plan_id or plan.status != "proposed":
                continue
            updated = self.controller.implement(plan.control_id, evidence)
            if updated is None:
                return False
            plan_obj = RemediationPlan(
                plan_id=plan.plan_id,
                risk_id=plan.risk_id,
                control_id=plan.control_id,
                rationale=plan.rationale,
                status="implemented",
                created_at=plan.created_at,
                implemented_at=time.time(),
                evidence=evidence,
            )
            self._plans[i] = plan_obj
            _save_json(_PLANS_FILE, [p.to_dict() for p in self._plans])
            return True
        return False

    def list_plans(self) -> List[RemediationPlan]:
        return list(self._plans)

    def list_proposed(self) -> List[RemediationPlan]:
        return [p for p in self._plans if p.status == "proposed"]


# ---------------------------------------------------------------------------
# GRCClabEngine — orchestrated agentic cycle + scheduled reporting
# ---------------------------------------------------------------------------


class GRCClabEngine:
    """Facade that runs the full agentic governance cycle:

    scan risks -> auto-log events -> score compliance / detect drift ->
    remediate open risks -> scheduled report.

    Intended for cron-like or event-driven invocation; run_cycle() performs one
    complete pass without blocking on real sleep.
    """

    def __init__(self) -> None:
        self.registry = AISystemRegistry()
        self.assessor = RiskAssessment()
        self.controller = ControlImplementation()
        self.chain = AuditEvidenceChain()
        self.mgr = IncidentManager()
        self.reporter = ComplianceReporter(
            self.registry, self.assessor, self.controller, self.chain, self.mgr
        )
        self.agent = AutonomousAgent(self.registry, self.assessor, self.chain)
        self.logger = EvidenceAutoLogger(self.chain)
        self.monitor = ComplianceMonitor(self.reporter)
        self.planner = RemediationPlanner(self.assessor, self.controller)

    def run_cycle(self) -> Dict[str, Any]:
        """One complete agentic governance cycle. Returns a summary dict."""
        scan = self.agent.run_tick()
        report, drift_delta, alerts = self.monitor.score()
        plans = self.planner.plan_for_open_risks()
        return {
            "scan": {
                "scan_id": scan.scan_id,
                "trigger": scan.trigger,
                "systems_scanned": scan.systems_scanned,
                "new_risk_ids": scan.new_risk_ids,
            },
            "compliance": {
                "compliance_percentage": report.compliance_percentage,
                "overall_status": report.overall_status,
                "open_risks": report.open_risks,
                "open_incidents": report.open_incidents,
                "implemented_controls": report.implemented_controls,
                "total_controls": report.total_controls,
            },
            "drift": {
                "drift_delta": drift_delta,
                "alerts": [a.alert_id for a in alerts],
            },
            "remediation": {
                "proposed_plans": [
                    {"plan_id": p.plan_id, "risk_id": p.risk_id, "control_id": p.control_id}
                    for p in plans
                ]
            },
        }

    def scheduled_report(self) -> Any:
        """Generate and persist a scheduled compliance report (event-driven/cron)."""
        report = self.reporter.generate()
        self.chain.log(
            "scheduled_compliance_report",
            {
                "compliance_percentage": report.compliance_percentage,
                "status": report.overall_status,
            },
            None,
        )
        # score() snapshots the report and runs drift detection.
        self.monitor.score()
        return report
