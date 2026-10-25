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
- hash-linked evidence chain (genesis "0"*64, tamper-evident re-walk)
- autonomous compliance monitoring: fixed interval, violation detection,
  evidence auto-logging, remediation triggering
- remediation planner: priority scoring, estimated effort, dependency ordering
- c-uas grc CLI: --chain, --monitor, --remediate deterministic output

All state is isolated to a per-test temp dir under ~/.c-uas-platform/grc_clab
so tests never share or leak persisted data.
"""

import time

import pytest

import c_uas.governance as gov
import c_uas.grc_clab as grc
import c_uas.grc_clab.autonomous_agent as grc_agent
import c_uas.grc_clab.evidence_chain as grc_chain
import c_uas.grc_clab.remediation as grc_rem
from c_uas.governance import (
    AISystemRegistry,
    AuditEvidenceChain,
    ComplianceReporter,
    ControlImplementation,
    IncidentManager,
    Risk,
    RiskAssessment,
)
from c_uas.grc_clab import (
    AutonomousAgent,
    ComplianceMonitor,
    EvidenceAutoLogger,
    GRCClabEngine,
    RemediationPlanner,
)
from c_uas.grc_clab.autonomous_agent import AutonomousAgent as GrcAutonomousAgent
from c_uas.grc_clab.autonomous_agent import ControlViolation
from c_uas.grc_clab.cli import build_subparser, grc_main
from c_uas.grc_clab.evidence_chain import GENESIS_HASH, EvidenceChain
from c_uas.grc_clab.remediation import (
    RemediationAction,
    dependency_order,
    estimated_effort_hours,
    priority_score,
)
from c_uas.grc_clab.remediation import (
    RemediationPlanner as GrcRemediationPlanner,
)


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


@pytest.fixture
def grc_tmp_dir(tmp_path, monkeypatch):
    """Point the new grc_clab modules at fresh temp persistence dirs."""
    ev_dir = tmp_path / "evidence"
    rem_dir = tmp_path / "remediation"
    ev_dir.mkdir(parents=True, exist_ok=True)
    rem_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(grc_chain, "_CHAIN_DIR", ev_dir)
    monkeypatch.setattr(grc_chain, "_CHAIN_FILE", ev_dir / "chain.json")
    monkeypatch.setattr(grc_rem, "_REMED_DIR", rem_dir)
    monkeypatch.setattr(grc_rem, "_PLANS_FILE", rem_dir / "actions.json")
    return tmp_path


def _fake_control(control_id, title, applicable=True, implemented=False):
    return type(
        "Control",
        (),
        {
            "control_id": control_id,
            "title": title,
            "applicable": applicable,
            "implemented": implemented,
        },
    )()


def _fake_system(system_id="ais-1", module_path="c_uas.detection.rf_classifier"):
    return type("System", (), {"system_id": system_id, "module_path": module_path})()


def _fake_violation(control_id="A.8.2", severity="critical"):
    return type(
        "Violation",
        (),
        {
            "control_id": control_id,
            "severity": severity,
            "description": f"violation {control_id}",
        },
    )()


# ---------------------------------------------------------------------------
# EvidenceChain (hash-linked evidence chain)
# ---------------------------------------------------------------------------


def test_evidence_chain_genesis_hash_is_zero_sixty_four(grc_tmp_dir):
    chain = EvidenceChain()
    assert chain.head_hash() == GENESIS_HASH == "0" * 64
    assert chain.entry_count() == 0
    assert chain.verify_chain() is True


def test_evidence_chain_each_entry_links_prev_hash_to_entry_hash(grc_tmp_dir):
    chain = EvidenceChain()
    e1 = chain.log("risk_assessment", {"risk_id": "r1"}, "sys-1")
    e2 = chain.log("control_implementation", {"control_id": "A.8.2"}, "sys-1")

    assert e2.prev_hash == e1.entry_hash
    assert e1.prev_hash == GENESIS_HASH
    assert len(e1.entry_hash) == 64
    assert len(e2.entry_hash) == 64
    assert e1.entry_hash != e2.entry_hash
    assert chain.verify_chain() is True


def test_evidence_chain_verify_re_walks_and_detects_tampering(grc_tmp_dir):
    chain = EvidenceChain()
    chain.log("risk_assessment", {"risk_id": "r1"}, "sys-1")
    chain.log("control_implementation", {"control_id": "A.8.2"}, "sys-1")
    assert chain.verify_chain() is True

    # Tamper with a stored payload: re-walk must fail.
    entries = chain.list_all()
    tampered = type(entries[0])(**{**entries[0].to_dict(), "payload": {"risk_id": "tampered"}})
    chain._entries[0] = tampered
    assert chain.verify_chain() is False


def test_evidence_chain_re_walk_raises_on_tamper(grc_tmp_dir):
    chain = EvidenceChain()
    chain.log("incident", {"incident_id": "inc-1"}, "sys-1")
    chain._entries[0] = type(chain._entries[0])(
        **{**chain._entries[0].to_dict(), "entry_hash": "0" * 64}
    )
    with pytest.raises(ValueError):
        chain.re_walk()


def test_compute_entry_hash_is_deterministic():
    payload = {"risk_id": "r1", "system_id": "sys-1"}
    h1 = grc_chain.compute_entry_hash(GENESIS_HASH, payload)
    h2 = grc_chain.compute_entry_hash(GENESIS_HASH, payload)
    assert h1 == h2
    assert len(h1) == 64
    # Different payload -> different hash.
    assert grc_chain.compute_entry_hash(GENESIS_HASH, {"risk_id": "r2"}) != h1


def test_evidence_chain_persists_and_reloads(grc_tmp_dir):
    chain = EvidenceChain()
    chain.log("risk_assessment", {"risk_id": "r1"}, "sys-1")
    count = chain.entry_count()

    reloaded = EvidenceChain()
    assert reloaded.entry_count() == count
    assert reloaded.head_hash() == chain.head_hash()
    assert reloaded.verify_chain() is True


# ---------------------------------------------------------------------------
# AutonomousAgent (autonomous compliance monitoring)
# ---------------------------------------------------------------------------


def test_autonomous_agent_not_due_before_first_tick(grc_tmp_dir):
    agent = GrcAutonomousAgent(interval_s=3600.0)
    agent._last_tick = time.time()
    assert agent.is_due() is False


def test_autonomous_agent_detects_unimplemented_applicable_controls(grc_tmp_dir):
    agent = GrcAutonomousAgent(interval_s=3600.0)
    controls = [
        _fake_control("A.8.2", "Input validation", applicable=True, implemented=False),
        _fake_control("A.8.3", "Output verification", applicable=True, implemented=True),
        _fake_control("A.9.1", "Monitoring", applicable=False, implemented=False),
    ]
    violations = agent.detect_violations([_fake_system()], controls)

    assert len(violations) == 1
    assert violations[0].control_id == "A.8.2"
    assert violations[0].severity == "critical"


def test_autonomous_agent_severity_by_control_domain(grc_tmp_dir):
    assert grc_agent._control_severity("A.8.2") == "critical"
    assert grc_agent._control_severity("A.5.1") == "high"
    assert grc_agent._control_severity("A.9.1") == "medium"
    assert grc_agent._control_severity("A.11.1") == "medium"


def test_autonomous_agent_run_tick_logs_evidence_and_triggers_remediation(
    grc_tmp_dir,
):
    agent = GrcAutonomousAgent(interval_s=3600.0)
    controls = [
        _fake_control("A.8.2", "Input validation", applicable=True, implemented=False),
        _fake_control("A.10.1", "Incident management", applicable=True, implemented=False),
    ]
    result = agent.run_tick([_fake_system()], controls)

    assert result.systems_scanned == 1
    assert len(result.violations) == 2
    assert len(result.evidence_entries) == 2
    assert len(result.remediation_actions) == 2
    assert agent.chain.verify_chain() is True
    assert agent.is_due() is False  # just ticked


def test_autonomous_agent_monitor_loop_respects_interval(grc_tmp_dir):
    agent = GrcAutonomousAgent(interval_s=3600.0)
    controls = [_fake_control("A.8.2", "Input validation", applicable=True, implemented=False)]
    results = agent.monitor_loop([_fake_system()], controls, max_iterations=3)
    assert len(results) == 1  # not due again within the same second


def test_control_violation_is_frozen_dataclass():
    v = ControlViolation(
        violation_id="v1",
        detected_at=1.0,
        control_id="A.8.2",
        system_id="sys-1",
        description="input validation missing",
        severity="critical",
    )
    assert v.control_id == "A.8.2"
    with pytest.raises(AttributeError):
        v.severity = "low"  # frozen


# ---------------------------------------------------------------------------
# RemediationPlanner (priority scoring, effort, dependency ordering)
# ---------------------------------------------------------------------------


def test_priority_score_is_deterministic(grc_tmp_dir):
    assert priority_score("A.8.2", "critical", 3) == priority_score("A.8.2", "critical", 3)
    # Higher severity -> higher score.
    assert priority_score("A.8.2", "critical") > priority_score("A.8.2", "low")
    # More open risks -> higher score.
    assert priority_score("A.8.2", "medium", 10) > priority_score("A.8.2", "medium", 0)


def test_estimated_effort_is_deterministic_per_domain(grc_tmp_dir):
    assert estimated_effort_hours("A.8.2") == estimated_effort_hours("A.8.3")
    assert estimated_effort_hours("A.11.1") == 20.0
    assert estimated_effort_hours("A.5.1") == 4.0


def test_remediation_planner_adds_action_for_violation(grc_tmp_dir):
    planner = GrcRemediationPlanner()
    action = planner.add_violation(_fake_violation("A.8.2", "critical"))

    assert action.control_id == "A.8.2"
    assert action.status == "proposed"
    assert action.estimated_effort_hours == 12.0
    assert action.priority_score > 0
    assert len(planner.list_actions()) == 1

    # Re-adding the same control returns the existing action.
    again = planner.add_violation(_fake_violation("A.8.2", "critical"))
    assert again.action_id == action.action_id
    assert len(planner.list_actions()) == 1


def test_remediation_planner_plan_for_controls(grc_tmp_dir):
    planner = GrcRemediationPlanner()
    controls = [
        _fake_control("A.8.2", "Input validation", applicable=True, implemented=False),
        _fake_control("A.10.1", "Incident management", applicable=True, implemented=False),
    ]
    created = planner.plan_for_controls(controls, open_risk_count=2)

    assert len(created) == 2
    assert all(a.status == "proposed" for a in created)
    assert all(a.priority_score > 0 for a in created)


def test_remediation_dependency_order_respects_depends_on(grc_tmp_dir):
    a = RemediationAction(
        action_id="rem-a",
        control_id="A.5.1",
        title="A",
        description="a",
        priority_score=1.0,
        estimated_effort_hours=1.0,
        depends_on=[],
    )
    b = RemediationAction(
        action_id="rem-b",
        control_id="A.8.2",
        title="B",
        description="b",
        priority_score=2.0,
        estimated_effort_hours=2.0,
        depends_on=["rem-a"],
    )
    ordered = dependency_order([b, a])
    ids = [x.action_id for x in ordered]
    assert ids.index("rem-a") < ids.index("rem-b")


def test_remediation_dependency_order_breaks_cycles_deterministically(grc_tmp_dir):
    a = RemediationAction(
        action_id="rem-a",
        control_id="A.5.1",
        title="A",
        description="a",
        priority_score=1.0,
        estimated_effort_hours=1.0,
        depends_on=["rem-b"],
    )
    b = RemediationAction(
        action_id="rem-b",
        control_id="A.8.2",
        title="B",
        description="b",
        priority_score=2.0,
        estimated_effort_hours=2.0,
        depends_on=["rem-a"],
    )
    ordered = dependency_order([a, b])
    assert len(ordered) == 2  # both returned, cycle broken


def test_remediation_ordered_plan_sorted_by_priority(grc_tmp_dir):
    planner = GrcRemediationPlanner()
    planner.add_violation(_fake_violation("A.11.1", "low"))  # lower priority
    planner.add_violation(_fake_violation("A.8.2", "critical"))  # higher priority
    ordered = planner.ordered_plan()
    assert ordered[0].control_id == "A.8.2"


def test_remediation_mark_completed(grc_tmp_dir):
    planner = GrcRemediationPlanner()
    action = planner.add_violation(_fake_violation("A.8.2", "critical"))
    assert planner.mark_completed(action.action_id, "ev-123") is True
    updated = planner.list_actions()[0]
    assert updated.status == "completed"
    assert updated.completed_at is not None
    assert planner.mark_completed("does-not-exist") is False


# ---------------------------------------------------------------------------
# CLI: c-uas grc --chain | --monitor | --remediate
# ---------------------------------------------------------------------------


def test_grc_build_subparser_registers_grc_command():
    import argparse

    parser = argparse.ArgumentParser(prog="c-uas")
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(["grc", "--chain"])
    assert args.command == "grc"
    assert args.chain is True


def test_grc_main_chain_output(grc_tmp_dir, capsys):
    chain = EvidenceChain()
    chain.log("risk_assessment", {"risk_id": "r1"}, "sys-1")
    rc = grc_main(type("NS", (), {"chain": True, "monitor": False, "remediate": False})())
    out = capsys.readouterr().out
    assert rc == 0
    assert "GRC evidence chain" in out
    assert "valid=True" in out
    assert GENESIS_HASH in out


def test_grc_main_remediate_no_actions(grc_tmp_dir, capsys):
    rc = grc_main(type("NS", (), {"chain": False, "monitor": False, "remediate": True})())
    out = capsys.readouterr().out
    assert rc == 0
    assert "no proposed remediation actions" in out


def test_grc_main_monitor_runs_cycle(grc_tmp_dir, capsys):
    rc = grc_main(
        type(
            "NS",
            (),
            {
                "chain": False,
                "monitor": True,
                "remediate": False,
                "interval_s": 3600.0,
            },
        )()
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "GRC autonomous compliance monitor" in out
    assert "Systems scanned" in out


def test_grc_main_requires_subflag(capsys):
    rc = grc_main(type("NS", (), {"chain": False, "monitor": False, "remediate": False})())
    out = capsys.readouterr().out
    assert rc == 1
    assert "specify --chain, --monitor, or --remediate" in out


# ---------------------------------------------------------------------------
# Original GRC_Clab tests (must still pass)
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
        risk_id="r1",
        system_id="s1",
        description="EKF input validation gap",
        likelihood="high",
        impact="high",
        risk_level="critical",
        treatment="mitigate",
        treatment_plan="",
        status="open",
        identified_at=1.0,
    )
    risk_third = Risk(
        risk_id="r2",
        system_id="s1",
        description="third-party model supply chain risk",
        likelihood="medium",
        impact="medium",
        risk_level="medium",
        treatment="mitigate",
        treatment_plan="",
        status="open",
        identified_at=1.0,
    )
    risk_incident = Risk(
        risk_id="r3",
        system_id="s1",
        description="AI incident response gap",
        likelihood="medium",
        impact="high",
        risk_level="high",
        treatment="mitigate",
        treatment_plan="",
        status="open",
        identified_at=1.0,
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


def test_full_agentic_cycle(isolated):
    engine = GRCClabEngine()
    engine.agent._state = grc.ScheduleState(last_tick=0.0, interval_s=1.0)
    engine.registry.register(
        "EKF Tracking", "c_uas.tracking.ekf_interceptor", "operation", "medium"
    )
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
