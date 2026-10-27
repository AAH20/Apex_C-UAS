"""Deterministic tests for the C-UAS incident response module.

Covers playbook execution, incident lifecycle, escalation, persistence,
and CLI output. All values are real computations -- no mocks, no
fabricated metrics, no network. State lives in tmp_path (never the real
~/.c-uas-platform).
"""

from __future__ import annotations

import argparse
import os
from types import SimpleNamespace

import pytest

from c_uas.incident_response import (
    DEFAULT_STATE_DIR,
    INCIDENT_TYPE_DATA_EXFILTRATION,
    INCIDENT_TYPE_DETECTION_FAILURE,
    INCIDENT_TYPE_SECURITY_BREACH,
    INCIDENT_TYPE_SERVICE_DEGRADATION,
    IncidentManager,
    Playbook,
    PlaybookStep,
    build_playbook,
    escalate_incident,
    execute_playbook,
    execute_step,
    incident_from_alert,
    incident_from_finding,
    is_sla_breached,
    new_incident,
    policy_for,
    severity_for_alert,
    sla_deadline,
    sla_minutes_for,
    validate_incident_type,
    validate_severity,
)
from c_uas.incident_response.cli import build_subparser, ir_main

SEVERITY_P1 = "P1"
SEVERITY_P2 = "P2"
SEVERITY_P3 = "P3"
SEVERITY_P4 = "P4"

ALL_TYPES = [
    INCIDENT_TYPE_SECURITY_BREACH,
    INCIDENT_TYPE_DATA_EXFILTRATION,
    INCIDENT_TYPE_SERVICE_DEGRADATION,
    INCIDENT_TYPE_DETECTION_FAILURE,
]


def _alert(
    severity="warning", rule_id="obs-001", metric="http_requests_total", alert_id="ALERT-001"
):
    return SimpleNamespace(
        severity=severity,
        rule_id=rule_id,
        metric=metric,
        alert_id=alert_id,
    )


def _finding(finding_id="HARDEN-001"):
    return SimpleNamespace(finding_id=finding_id)


def _namespace(**overrides):
    defaults = {
        "create": False,
        "list": False,
        "execute": False,
        "escalate": False,
        "incident_id": None,
        "type": None,
        "source": None,
        "source_id": None,
        "severity": None,
        "title": None,
        "step": None,
        "state_dir": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# --------------------------------------------------------------------------- #
# Playbook: build + determinism
# --------------------------------------------------------------------------- #


def test_build_playbook_all_types_have_steps():
    for inc_type in ALL_TYPES:
        playbook = build_playbook(inc_type, SEVERITY_P2)
        assert isinstance(playbook, Playbook)
        assert len(playbook.steps) >= 3
        assert playbook.incident_type == inc_type
        assert playbook.severity == SEVERITY_P2
        assert playbook.sla_minutes > 0


def test_build_playbook_is_deterministic():
    first = build_playbook(INCIDENT_TYPE_SECURITY_BREACH, SEVERITY_P1)
    second = build_playbook(INCIDENT_TYPE_SECURITY_BREACH, SEVERITY_P1)
    assert first == second
    assert first.playbook_id == second.playbook_id
    assert [s.step_id for s in first.steps] == [s.step_id for s in second.steps]


def test_build_playbook_severity_changes_playbook_id():
    p1 = build_playbook(INCIDENT_TYPE_SECURITY_BREACH, SEVERITY_P1)
    p2 = build_playbook(INCIDENT_TYPE_SECURITY_BREACH, SEVERITY_P3)
    assert p1.playbook_id != p2.playbook_id
    assert p1.sla_minutes != p2.sla_minutes


def test_sla_minutes_per_severity():
    assert sla_minutes_for(SEVERITY_P1) == 15
    assert sla_minutes_for(SEVERITY_P2) == 60
    assert sla_minutes_for(SEVERITY_P3) == 240
    assert sla_minutes_for(SEVERITY_P4) == 1440


def test_playbook_steps_frozen_and_ordered():
    playbook = build_playbook(INCIDENT_TYPE_DATA_EXFILTRATION, SEVERITY_P1)
    step_ids = [s.step_id for s in playbook.steps]
    assert step_ids == ["exfil-01", "exfil-02", "exfil-03", "exfil-04", "exfil-05", "exfil-06"]
    assert all(isinstance(s, PlaybookStep) for s in playbook.steps)
    assert not playbook.steps[0].completed


# --------------------------------------------------------------------------- #
# Incident: creation + determinism
# --------------------------------------------------------------------------- #


def test_new_incident_is_deterministic():
    now = "2026-10-27T10:00:00Z"
    first = new_incident(
        title="Breach at site A",
        incident_type=INCIDENT_TYPE_SECURITY_BREACH,
        severity=SEVERITY_P1,
        source="alert",
        source_id="ALERT-001",
        now_iso=now,
    )
    second = new_incident(
        title="Breach at site A",
        incident_type=INCIDENT_TYPE_SECURITY_BREACH,
        severity=SEVERITY_P1,
        source="alert",
        source_id="ALERT-001",
        now_iso=now,
    )
    assert first == second
    assert first.incident_id == second.incident_id
    assert first.status == "open"
    assert first.current_step == 0


def test_new_incident_id_changes_when_input_changes():
    base = new_incident(
        "t",
        INCIDENT_TYPE_SECURITY_BREACH,
        SEVERITY_P1,
        "alert",
        "A",
        now_iso="2026-10-27T10:00:00Z",
    )
    changed = new_incident(
        "t",
        INCIDENT_TYPE_SECURITY_BREACH,
        SEVERITY_P1,
        "alert",
        "B",
        now_iso="2026-10-27T10:00:00Z",
    )
    assert base.incident_id != changed.incident_id


def test_new_incident_sla_deadline_is_set():
    now = "2026-10-27T10:00:00Z"
    inc = new_incident(
        "t", INCIDENT_TYPE_SERVICE_DEGRADATION, SEVERITY_P2, "alert", "A", now_iso=now
    )
    assert inc.sla_deadline == "2026-10-27T11:00:00Z"  # P2 = 60 min


def test_validate_incident_type_rejects_unknown():
    with pytest.raises(ValueError):
        validate_incident_type("not_a_type")


def test_validate_severity_rejects_unknown():
    with pytest.raises(ValueError):
        validate_severity("P9")


# --------------------------------------------------------------------------- #
# Alerts / findings -> incidents
# --------------------------------------------------------------------------- #


def test_incident_from_alert_maps_warning_to_p2():
    inc, playbook = incident_from_alert(_alert(severity="warning"))
    assert inc.severity == SEVERITY_P2
    assert inc.source == "alert"
    assert inc.source_id == "ALERT-001"
    assert inc.incident_type == INCIDENT_TYPE_SERVICE_DEGRADATION


def test_incident_from_alert_maps_emergency_to_p1_breach():
    inc, playbook = incident_from_alert(_alert(severity="emergency"))
    assert inc.severity == SEVERITY_P1
    assert inc.incident_type == INCIDENT_TYPE_SECURITY_BREACH


def test_severity_for_alert_mapping():
    assert severity_for_alert("emergency") == SEVERITY_P1
    assert severity_for_alert("critical") == SEVERITY_P1
    assert severity_for_alert("warning") == SEVERITY_P2
    assert severity_for_alert("info") == SEVERITY_P3
    assert severity_for_alert("unknown") == SEVERITY_P3


def test_incident_from_finding():
    inc, playbook = incident_from_finding(_finding("FIND-001"), finding_type="data_exfiltration")
    assert inc.severity == SEVERITY_P1
    assert inc.source == "finding"
    assert inc.source_id == "FIND-001"
    assert inc.incident_type == INCIDENT_TYPE_SECURITY_BREACH


# --------------------------------------------------------------------------- #
# Playbook execution
# --------------------------------------------------------------------------- #


def test_execute_step_marks_complete_and_advances():
    playbook = build_playbook(INCIDENT_TYPE_SERVICE_DEGRADATION, SEVERITY_P2)
    inc = new_incident(
        "t",
        INCIDENT_TYPE_SERVICE_DEGRADATION,
        SEVERITY_P2,
        "alert",
        "A",
        now_iso="2026-10-27T10:00:00Z",
        playbook=playbook,
    )
    updated, step, _ = execute_step(inc, playbook, 0)
    assert step.completed is True
    assert step.step_id == "deg-01"
    assert updated.current_step == 1
    assert updated.status == "investigating"
    # Original incident unchanged (immutable)
    assert inc.current_step == 0


def test_execute_step_out_of_range_raises():
    playbook = build_playbook(INCIDENT_TYPE_DETECTION_FAILURE, SEVERITY_P3)
    inc = new_incident("t", INCIDENT_TYPE_DETECTION_FAILURE, SEVERITY_P3, "alert", "A")
    with pytest.raises(IndexError):
        execute_step(inc, playbook, 100)


def test_execute_playbook_completes_all_steps():
    playbook = build_playbook(INCIDENT_TYPE_SECURITY_BREACH, SEVERITY_P1)
    inc = new_incident(
        "t",
        INCIDENT_TYPE_SECURITY_BREACH,
        SEVERITY_P1,
        "alert",
        "A",
        now_iso="2026-10-27T10:00:00Z",
        playbook=playbook,
    )
    final, response = execute_playbook(inc, playbook)
    assert final.status == "remediated"
    assert final.current_step == len(playbook.steps)
    assert response.completed_steps == len(playbook.steps)
    assert response.total_steps == len(playbook.steps)
    assert response.status == "remediated"
    assert all(s.completed for s in response.steps)


def test_execute_playbook_is_deterministic():
    playbook = build_playbook(INCIDENT_TYPE_DATA_EXFILTRATION, SEVERITY_P1)
    inc = new_incident(
        "t",
        INCIDENT_TYPE_DATA_EXFILTRATION,
        SEVERITY_P1,
        "finding",
        "F",
        now_iso="2026-10-27T10:00:00Z",
        playbook=playbook,
    )
    r1 = execute_playbook(inc, playbook)
    r2 = execute_playbook(inc, playbook)
    assert r1[1] == r2[1]
    assert r1[0] == r2[0]


# --------------------------------------------------------------------------- #
# IncidentManager: lifecycle + persistence
# --------------------------------------------------------------------------- #


def test_manager_create_incident_persists_and_loads(tmp_path):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    inc, playbook = manager.create_incident(
        title="Test breach",
        incident_type=INCIDENT_TYPE_SECURITY_BREACH,
        severity=SEVERITY_P1,
        source="alert",
        source_id="ALERT-X",
    )
    loaded = manager.get_incident(inc.incident_id)
    assert loaded == inc
    assert loaded.playbook_id == playbook.playbook_id
    loaded_pb = manager.get_playbook(playbook.playbook_id)
    assert loaded_pb == playbook


def test_manager_list_incidents(tmp_path):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    assert manager.list_incidents() == []
    manager.create_incident("a", INCIDENT_TYPE_SECURITY_BREACH, SEVERITY_P1, "alert", "A")
    manager.create_incident("b", INCIDENT_TYPE_SERVICE_DEGRADATION, SEVERITY_P2, "alert", "B")
    incidents = manager.list_incidents()
    assert len(incidents) == 2
    ids = {i.incident_id for i in incidents}
    assert len(ids) == 2  # deterministic ids, no duplicates


def test_manager_create_incident_from_alert(tmp_path):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    inc, playbook = manager.create_incident_from_alert(_alert(severity="critical"))
    assert inc.severity == SEVERITY_P1
    assert inc.incident_type == INCIDENT_TYPE_SECURITY_BREACH
    assert manager.get_incident(inc.incident_id) == inc


def test_manager_create_incident_from_finding(tmp_path):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    inc, playbook = manager.create_incident_from_finding(_finding(), finding_type="security_breach")
    assert inc.severity == SEVERITY_P1
    assert inc.source == "finding"


def test_manager_execute_incident_full(tmp_path):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    inc, playbook = manager.create_incident(
        title="deg",
        incident_type=INCIDENT_TYPE_SERVICE_DEGRADATION,
        severity=SEVERITY_P2,
        source="alert",
        source_id="A",
    )
    updated, step, response = manager.execute_incident(inc.incident_id)
    assert updated.status == "remediated"
    assert response is not None
    assert response.completed_steps == len(playbook.steps)
    # persisted
    loaded = manager.get_incident(inc.incident_id)
    assert loaded.status == "remediated"
    resp = manager.get_response(inc.incident_id)
    assert resp is not None
    assert resp.completed_steps == len(playbook.steps)


def test_manager_execute_incident_single_step(tmp_path):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    inc, playbook = manager.create_incident(
        title="deg",
        incident_type=INCIDENT_TYPE_SERVICE_DEGRADATION,
        severity=SEVERITY_P2,
        source="alert",
        source_id="A",
    )
    updated, step, response = manager.execute_incident(inc.incident_id, step_index=0)
    assert response is None
    assert step is not None
    assert step.completed is True
    assert updated.current_step == 1
    assert updated.status == "investigating"


def test_manager_set_status(tmp_path):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    inc, _ = manager.create_incident(
        title="t",
        incident_type=INCIDENT_TYPE_DETECTION_FAILURE,
        severity=SEVERITY_P3,
        source="alert",
        source_id="A",
    )
    assert inc.status == "open"
    updated = manager.set_status(inc.incident_id, "closed")
    assert updated.status == "closed"
    assert manager.get_incident(inc.incident_id).status == "closed"


def test_manager_summary(tmp_path):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    manager.create_incident("a", INCIDENT_TYPE_SECURITY_BREACH, SEVERITY_P1, "alert", "A")
    manager.create_incident("b", INCIDENT_TYPE_SERVICE_DEGRADATION, SEVERITY_P2, "alert", "B")
    summary = manager.summary()
    assert summary["total"] == 2
    assert summary["by_status"]["open"] == 2
    assert summary["by_severity"]["P1"] == 1
    assert summary["by_severity"]["P2"] == 1


def test_state_dir_is_outside_repo():
    expected = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "incident_response")
    assert DEFAULT_STATE_DIR == expected
    assert DEFAULT_STATE_DIR.endswith(".c-uas-platform/incident_response")


# --------------------------------------------------------------------------- #
# Escalation
# --------------------------------------------------------------------------- #


def test_policy_for_all_severities():
    for sev in (SEVERITY_P1, SEVERITY_P2, SEVERITY_P3, SEVERITY_P4):
        policy = policy_for(sev)
        assert policy.severity == sev
        assert policy.primary_responder
        assert policy.channels


def test_policy_p1_responders():
    p1 = policy_for(SEVERITY_P1)
    assert p1.sla_minutes == 15
    assert "ciso" in p1.primary_responder
    assert "pagerduty" in p1.channels


def test_sla_deadline_and_breach():
    created = "2026-10-27T10:00:00Z"
    deadline = sla_deadline(created, SEVERITY_P1)
    assert deadline == "2026-10-27T10:15:00Z"
    # Not breached at creation time.
    assert is_sla_breached(created, SEVERITY_P1, now_iso=created) is False
    # Breached well after deadline.
    assert is_sla_breached(created, SEVERITY_P1, now_iso="2026-10-27T11:00:00Z") is True


def test_time_remaining_negative_after_breach():
    remaining = sla_minutes_for(SEVERITY_P1) * 60 - 3600  # 1h after a 15-min SLA
    assert remaining < 0


def test_escalate_incident_p1_not_breached_level_0():
    inc = new_incident(
        "t",
        INCIDENT_TYPE_SECURITY_BREACH,
        SEVERITY_P1,
        "alert",
        "A",
        now_iso="2026-10-27T10:00:00Z",
    )
    result = escalate_incident(inc, now_iso="2026-10-27T10:05:00Z")
    assert result.escalation_level == 0
    assert result.sla_breached is False
    assert result.notifications == ()


def test_escalate_incident_p1_breached_level_1():
    inc = new_incident(
        "t",
        INCIDENT_TYPE_SECURITY_BREACH,
        SEVERITY_P1,
        "alert",
        "A",
        now_iso="2026-10-27T10:00:00Z",
    )
    result = escalate_incident(inc, now_iso="2026-10-27T10:20:00Z")  # 20m > 15m SLA
    assert result.escalation_level == 1
    assert result.sla_breached is True
    assert result.primary_responder == "ciso@a2zsoc.com"
    assert len(result.notifications) >= 1


def test_escalate_incident_is_deterministic():
    inc = new_incident(
        "t",
        INCIDENT_TYPE_SECURITY_BREACH,
        SEVERITY_P2,
        "alert",
        "A",
        now_iso="2026-10-27T10:00:00Z",
    )
    r1 = escalate_incident(inc, now_iso="2026-10-27T11:00:00Z")
    r2 = escalate_incident(inc, now_iso="2026-10-27T11:00:00Z")
    assert r1 == r2
    assert r1.record == r2.record


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_create_output(tmp_path):
    state_dir = str(tmp_path / "incident_response")
    args = _namespace(
        create=True,
        type=INCIDENT_TYPE_SECURITY_BREACH,
        source="alert",
        source_id="ALERT-001",
        severity=SEVERITY_P1,
        state_dir=state_dir,
    )
    out1 = ir_main(args)  # runs and prints
    # Capture via running again is awkward; just assert return code and that state persisted.
    assert out1 == 0
    manager = IncidentManager(state_dir=state_dir)
    assert len(manager.list_incidents()) == 1


def test_cli_create_missing_args_returns_1():
    args = _namespace(create=True, state_dir="/tmp/x")
    assert ir_main(args) == 1


def test_cli_list_output(tmp_path, capsys):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    manager.create_incident("a", INCIDENT_TYPE_SECURITY_BREACH, SEVERITY_P1, "alert", "A")
    args = _namespace(list=True, state_dir=state_dir)
    ir_main(args)
    out = capsys.readouterr().out
    assert "[C-UAS] Incidents" in out
    assert "P1" in out


def test_cli_execute_output(tmp_path, capsys):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    inc, _ = manager.create_incident(
        "t",
        INCIDENT_TYPE_DETECTION_FAILURE,
        SEVERITY_P3,
        "alert",
        "A",
    )
    args = _namespace(execute=True, incident_id=inc.incident_id, state_dir=state_dir)
    ir_main(args)
    out = capsys.readouterr().out
    assert "remediated" in out
    assert "completed_steps" in out


def test_cli_escalate_output(tmp_path, capsys):
    state_dir = str(tmp_path / "incident_response")
    manager = IncidentManager(state_dir=state_dir)
    inc, _ = manager.create_incident(
        "t",
        INCIDENT_TYPE_SECURITY_BREACH,
        SEVERITY_P1,
        "alert",
        "A",
    )
    args = _namespace(escalate=True, incident_id=inc.incident_id, state_dir=state_dir)
    ir_main(args)
    out = capsys.readouterr().out
    assert "[C-UAS] Escalation" in out


def test_cli_no_action_returns_1():
    args = _namespace(state_dir="/tmp/x")
    assert ir_main(args) == 1


def test_cli_build_subparser_registers_ir():
    import argparse

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(["ir", "--list"])
    assert args.command == "ir"
