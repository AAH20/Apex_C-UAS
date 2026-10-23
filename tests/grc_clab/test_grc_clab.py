"""Deterministic tests for the GRC_Clab agentic governance engine.

Scenarios:
- autonomous agent scans unassessed systems and files new risks
- tick scheduling is due / skipped and persists across instances
- evidence auto-logger ingests detection, tracking, engagement, forensics
- evidence chain stays tamper-evident under auto-logging
- compliance monitor scores and detects drift (up and down)
- remediation planner maps open risks to Annex A controls and applies them
- full agentic cycle runs end to end
- pure risk/control mapping and event risk-level functions are deterministic

All state is isolated to a per-test temp dir under ~/.c-uas-platform/grc_clab
so tests never share or leak persisted data.
"""

from c_uas.governance import (
    AISystemRegistry,
    AuditEvidenceChain,
    ComplianceReporter,
    ControlImplementation,
    IncidentManager,
    Risk,
    RiskAssessment,
)

import c_uas.grc_clab as grc
import c_uas.governance as gov
from c_uas.grc_clab import (
    AutonomousAgent,
    ComplianceMonitor,
    EvidenceAutoLogger,
    GRCClabEngine,
    RemediationPlanner,
)

import pytest


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point every grc_clab and governance persistence path at a fresh temp dir."""
    base = tmp_path / "c-uas-platform"
    gov_dir = base / "governance"
    grc_dir = base / "grc_clab"
    gov_dir.mkdir(parents=True, exist_ok=True)
    grc_dir.mkdir(parents=True, exist_ok=True)

    gov_paths = {
        "_GOV_DIR": gov_dir,
        "_SYSTEMS_FILE": gov_dir / "ai_systems.json",
        "_RISKS_FILE": gov_dir / "risks.json",
        "_CONTROLS_FILE": gov_dir / "controls.json",
        "_EVIDENCE_FILE": gov_dir / "evidence.json",
        "_INCIDENTS_FILE": gov_dir / "incidents.json",
    }
    grc_paths = {
        "_GRC_DIR": grc_dir,
        "_SCANS_FILE": grc_dir / "scan_logs.json",
        "_EVIDENCE_FILE": grc_dir / "auto_evidence.json",
        "_SNAPSHOTS_FILE": grc_dir / "compliance_snapshots.json",
        "_ALERTS_FILE": grc_dir / "drift_alerts.json",
        "_PLANS_FILE": grc_dir / "remediation_plans.json",
        "_STATE_FILE": grc_dir / "scheduler_state.json",
    }
    for attr, path in gov_paths.items():
        monkeypatch.setattr(gov, attr, path)
        if attr != "_GOV_DIR":
            path.write_text("[]")
    for attr, path in grc_paths.items():
        monkeypatch.setattr(grc, attr, path)
        if attr not in ("_GRC_DIR", "_STATE_FILE"):
            path.write_text("[]")
    grc_paths["_STATE_FILE"].write_text("{}")
    return base


# ---------------------------------------------------------------------------
# AutonomousAgent
# ---------------------------------------------------------------------------

def test_agent_scan_creates_risk_for_unassessed_system(isolated):
    reg = AISystemRegistry()
    reg._systems.clear()
    sid = reg.register("EKF Tracking", "c_uas.tracking.ekf_interceptor", "operation", "medium")
    assert sid is not None
    assessor = RiskAssessment()
    assessor._risks.clear()
    chain = AuditEvidenceChain()
    chain._entries.clear()
    agent = AutonomousAgent(reg, assessor, chain)

    record = agent.scan_systems(trigger="tick")

    assert record.systems_scanned == 1
    assert len(record.new_risk_ids) == 1
    risk = assessor.get(record.new_risk_ids[0])
    assert risk is not None
    assert risk.status == "open"
    assert chain.verify_chain() is True


def test_agent_scan_does_not_duplicate_open_risks(isolated):
    reg = AISystemRegistry()
    reg._systems.clear()
    reg.register("EKF Tracking", "c_uas.tracking.ekf_interceptor", "operation", "medium")
    assessor = RiskAssessment()
    assessor._risks.clear()
    chain = AuditEvidenceChain()
    chain._entries.clear()
    agent = AutonomousAgent(reg, assessor, chain)

    agent.scan_systems(trigger="tick")
    first_count = len(assessor.list_open())
    agent.scan_systems(trigger="tick")  # second tick: risk already open, no duplicate

    assert len(assessor.list_open()) == first_count


def test_agent_is_due_and_tick_persists(isolated):
    reg = AISystemRegistry()
    reg._systems.clear()
    reg.register("Sys", "c_uas.detection.rf_classifier", "operation", "medium")
    assessor = RiskAssessment()
    assessor._risks.clear()
    chain = AuditEvidenceChain()
    chain._entries.clear()
    agent = AutonomousAgent(reg, assessor, chain, interval_s=1.0)
    agent._state = grc.ScheduleState(last_tick=0.0, interval_s=1.0)

    assert agent.is_due() is True
    record = agent.run_tick()
    assert record.trigger == "tick"
    assert agent._state.ticks_run == 1

    # Just ticked, so not due again immediately.
    assert agent.is_due() is False
    skipped = agent.run_tick()
    assert skipped.trigger == "skipped"
    assert skipped.systems_scanned == 0


def test_schedule_state_persists_across_instances(isolated):
    reg = AISystemRegistry()
    reg._systems.clear()
    reg.register("Sys", "mod", "operation", "medium")
    assessor = RiskAssessment()
    assessor._risks.clear()
    chain = AuditEvidenceChain()
    chain._entries.clear()
    agent1 = AutonomousAgent(reg, assessor, chain, interval_s=100.0)
    agent1.run_tick()
    assert agent1._state.ticks_run == 1
    assert agent1._state.interval_s == 100.0

    agent2 = AutonomousAgent(reg, assessor, chain)
    assert agent2._state.ticks_run == 1
    assert agent2._state.interval_s == 100.0


# ---------------------------------------------------------------------------
# EvidenceAutoLogger
# ---------------------------------------------------------------------------

def test_evidence_auto_logger_all_event_types(isolated):
    chain = AuditEvidenceChain()
    chain._entries.clear()
    logger = EvidenceAutoLogger(chain)

    events = [
        ("detection", "c_uas.detection.rf_classifier", {"protocol": "DJI_OCUSYNC_4"}),
        ("tracking", "c_uas.tracking.ekf_interceptor", {"horizon_s": 2.0}),
        ("engagement", "c_uas.engagement.scheduler", {"num_drones": 4}),
        ("forensics", "c_uas.forensics.airspace_dossier", {"admissibility": "LEGAL_DEFENSE_GRADE"}),
    ]
    entries = []
    for event_type, source, payload in events:
        entry = logger.log_event(event_type, "ais-1", source, payload)
        entries.append(entry)

    assert len(logger.list_all()) == 4
    assert len(logger.list_by_type("detection")) == 1
    assert len(logger.list_by_type("engagement")) == 1
    assert all(e.governance_entry_id for e in entries)
    assert logger.verify_chain() is True

    # convenience methods
    det = logger.log_detection_event("ais-1", "c_uas.detection.rf_classifier", {"x": 1})
    assert det.event_type == "detection"
    trk = logger.log_tracking_event("ais-1", "c_uas.tracking.ekf_interceptor", {"x": 1})
    assert trk.event_type == "tracking"
    eng = logger.log_engagement_event("ais-1", "c_uas.engagement.scheduler", {"x": 1})
    assert eng.event_type == "engagement"
    for_ = logger.log_forensics_event("ais-1", "c_uas.forensics.airspace_dossier", {"x": 1})
    assert for_.event_type == "forensics"


def test_evidence_auto_logger_rejects_unknown_event_type(isolated):
    logger = EvidenceAutoLogger()
    with pytest.raises(ValueError):
        logger.log_event("bogus", None, "src", {})


# ---------------------------------------------------------------------------
# ComplianceMonitor
# ---------------------------------------------------------------------------

def test_compliance_monitor_first_score_has_no_drift(isolated):
    reg = AISystemRegistry()
    reg._systems.clear()
    reg.register("Sys", "mod", "operation", "medium")
    assessor = RiskAssessment()
    assessor._risks.clear()
    controller = ControlImplementation()
    chain = AuditEvidenceChain()
    chain._entries.clear()
    mgr = IncidentManager()
    mgr._incidents.clear()
    reporter = ComplianceReporter(reg, assessor, controller, chain, mgr)
    monitor = ComplianceMonitor(reporter)

    report, delta, alerts = monitor.score()

    assert delta == 0.0
    assert alerts == []
    assert len(monitor.list_snapshots()) == 1
    assert report.overall_status in ("compliant", "partial", "non_compliant")


def test_compliance_monitor_detects_downward_drift(isolated):
    reg = AISystemRegistry()
    reg._systems.clear()
    reg.register("Sys", "mod", "operation", "medium")
    assessor = RiskAssessment()
    assessor._risks.clear()
    assessor.assess("sys-1", "open risk", "high", "high")
    controller = ControlImplementation()
    chain = AuditEvidenceChain()
    chain._entries.clear()
    mgr = IncidentManager()
    mgr._incidents.clear()
    reporter = ComplianceReporter(reg, assessor, controller, chain, mgr)
    monitor = ComplianceMonitor(reporter)

    # Implement a control so compliance is above the zero floor.
    controller.implement("A.8.2", "input validation added")
    report1, delta1, _ = monitor.score()
    assert delta1 == 0.0
    assert report1.compliance_percentage > 0.0
    assert len(monitor.list_snapshots()) == 1

    # Add an open incident: compliance drops, drift down, an alert fires.
    mgr.record("Incident", "intercept prediction off by 3m", "high")
    report2, delta2, alerts2 = monitor.score()

    assert delta2 < 0.0
    assert report2.compliance_percentage < report1.compliance_percentage
    assert len(alerts2) >= 1
    assert any(a.metric == "open_incidents" and a.direction == "up" for a in alerts2)
    assert len(monitor.list_snapshots()) == 2
    assert len(monitor.list_alerts()) >= 1


def test_compliance_monitor_detects_upward_drift(isolated):
    reg = AISystemRegistry()
    reg._systems.clear()
    reg.register("Sys", "mod", "operation", "medium")
    assessor = RiskAssessment()
    assessor._risks.clear()
    assessor.assess("sys-1", "open risk", "high", "high")
    controller = ControlImplementation()
    chain = AuditEvidenceChain()
    chain._entries.clear()
    mgr = IncidentManager()
    mgr._incidents.clear()
    reporter = ComplianceReporter(reg, assessor, controller, chain, mgr)
    monitor = ComplianceMonitor(reporter)

    report1, _, _ = monitor.score()
    open_risks_before = report1.open_risks
    assert open_risks_before == 1

    controller.implement("A.8.2", "input validation added")
    report2, delta2, alerts2 = monitor.score()

    assert len(monitor.list_snapshots()) == 2
    assert len(alerts2) >= 1


# ---------------------------------------------------------------------------
# RemediationPlanner
# ---------------------------------------------------------------------------

def test_remediation_planner_proposes_and_applies_control(isolated):
    reg = AISystemRegistry()
    reg._systems.clear()
    reg.register("EKF", "c_uas.tracking.ekf_interceptor", "operation", "medium")
    assessor = RiskAssessment()
    assessor._risks.clear()
    risk = assessor.assess("sys-1", "EKF input validation gap", "high", "high")
    controller = ControlImplementation()
    planner = RemediationPlanner(assessor, controller)

    plans = planner.plan_for_open_risks()
    assert len(plans) == 1
    assert plans[0].risk_id == risk.risk_id
    assert plans[0].control_id == "A.8.2"
    assert plans[0].status == "proposed"
    assert "input validation" in plans[0].rationale.lower()

    assert planner.apply_plan(plans[0].plan_id, "ev-999") is True
    updated = planner.list_plans()[0]
    assert updated.status == "implemented"
    assert updated.implemented_at is not None
    assert controller.get("A.8.2").implemented is True

    # Re-planning must not duplicate now that the control is implemented.
    assert len(planner.plan_for_open_risks()) == 0


def test_risk_to_control_mapping_is_deterministic(isolated):
    risk_input = Risk(
        risk_id="r1", system_id="s1", description="EKF input validation gap",
        likelihood="high", impact="high", risk_level="critical",
        treatment="mitigate", treatment_plan="", status="open", identified_at=1.0,
    )
    risk_third = Risk(
        risk_id="r2", system_id="s1", description="third-party model supply chain risk",
        likelihood="medium", impact="medium", risk_level="medium",
        treatment="mitigate", treatment_plan="", status="open", identified_at=1.0,
    )
    risk_incident = Risk(
        risk_id="r3", system_id="s1", description="AI incident response gap",
        likelihood="medium", impact="high", risk_level="high",
        treatment="mitigate", treatment_plan="", status="open", identified_at=1.0,
    )
    assert grc._risk_to_control(risk_input) == "A.8.2"
    assert grc._risk_to_control(risk_third) == "A.11.1"
    assert grc._risk_to_control(risk_incident) == "A.10.1"
    assert grc._risk_to_control(risk_input) == grc._risk_to_control(risk_input)


def test_event_risk_level_is_deterministic():
    assert grc._event_risk_level("detection", "critical") == "high"
    assert grc._event_risk_level("tracking", "critical") == "critical"
    assert grc._event_risk_level("engagement", "low") == "low"
    assert grc._event_risk_level("forensics", "medium") == "low"
    assert grc._event_risk_level("detection", "medium") == "low"


# ---------------------------------------------------------------------------
# GRCClabEngine (full agentic cycle)
# ---------------------------------------------------------------------------

def test_full_agentic_cycle(isolated):
    engine = GRCClabEngine()
    engine.agent._state = grc.ScheduleState(last_tick=0.0, interval_s=1.0)
    engine.registry.register("EKF Tracking", "c_uas.tracking.ekf_interceptor", "operation", "medium")
    engine.registry.register("RF Classifier", "c_uas.detection.rf_classifier", "operation", "high")

    summary = engine.run_cycle()

    assert summary["scan"]["trigger"] == "tick"
    assert summary["scan"]["systems_scanned"] == 2
    assert len(summary["scan"]["new_risk_ids"]) == 2
    assert summary["compliance"]["compliance_percentage"] >= 0.0
    assert summary["compliance"]["overall_status"] in (
        "compliant",
        "partial",
        "non_compliant",
    )
    assert isinstance(summary["drift"]["drift_delta"], float)
    assert isinstance(summary["drift"]["alerts"], list)
    assert isinstance(summary["remediation"]["proposed_plans"], list)


def test_scheduled_report(isolated):
    engine = GRCClabEngine()
    report = engine.scheduled_report()

    assert report.overall_status in ("compliant", "partial", "non_compliant")
    assert len(engine.monitor.list_snapshots()) >= 1
    assert engine.chain.verify_chain() is True
