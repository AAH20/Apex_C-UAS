"""Incident Response Playbooks for the C-UAS platform.

Deterministic incident response playbooks that automate response to security
and platform incidents detected by observability alerts, security audits, and
red team findings.

State persists under ``~/.c-uas-platform/incident_response/`` (outside the
repo). All values are computed deterministically: identical inputs produce
identical incidents, playbooks, steps, and responses. No network, no live
credentials, no exploitation.

License: AGPL-3.0.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

INCIDENT_TYPE_SECURITY_BREACH = "security_breach"
INCIDENT_TYPE_DATA_EXFILTRATION = "data_exfiltration"
INCIDENT_TYPE_SERVICE_DEGRADATION = "service_degradation"
INCIDENT_TYPE_DETECTION_FAILURE = "detection_failure"

ALL_INCIDENT_TYPES: Tuple[str, ...] = (
    INCIDENT_TYPE_SECURITY_BREACH,
    INCIDENT_TYPE_DATA_EXFILTRATION,
    INCIDENT_TYPE_SERVICE_DEGRADATION,
    INCIDENT_TYPE_DETECTION_FAILURE,
)

SEVERITY_P1 = "P1"
SEVERITY_P2 = "P2"
SEVERITY_P3 = "P3"
SEVERITY_P4 = "P4"

ALL_SEVERITIES: Tuple[str, ...] = (SEVERITY_P1, SEVERITY_P2, SEVERITY_P3, SEVERITY_P4)

STATUS_OPEN = "open"
STATUS_INVESTIGATING = "investigating"
STATUS_REMEDIATED = "remediated"
STATUS_CLOSED = "closed"

ALL_STATUSES: Tuple[str, ...] = (
    STATUS_OPEN,
    STATUS_INVESTIGATING,
    STATUS_REMEDIATED,
    STATUS_CLOSED,
)

ACTION_CONTAIN = "contain"
ACTION_INVESTIGATE = "investigate"
ACTION_REMEDIATE = "remediate"
ACTION_NOTIFY = "notify"
ACTION_MONITOR = "monitor"
ACTION_CLOSE = "close"

DEFAULT_SLA_MINUTES: Dict[str, int] = {
    SEVERITY_P1: 15,
    SEVERITY_P2: 60,
    SEVERITY_P3: 240,
    SEVERITY_P4: 1440,
}

SOURCE_ALERT = "alert"
SOURCE_FINDING = "finding"
SOURCE_RED_TEAM = "red_team"

# Alert severity -> incident severity mapping.
ALERT_SEVERITY_TO_INCIDENT: Dict[str, str] = {
    "emergency": SEVERITY_P1,
    "critical": SEVERITY_P1,
    "warning": SEVERITY_P2,
    "info": SEVERITY_P3,
}

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_id(prefix: str, parts: Tuple[str, ...]) -> str:
    raw = "|".join(parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def severity_for_alert(alert_severity: str) -> str:
    """Map an observability alert severity to an incident severity (P1-P4)."""
    return ALERT_SEVERITY_TO_INCIDENT.get(alert_severity, SEVERITY_P3)


def sla_minutes_for(severity: str) -> int:
    return DEFAULT_SLA_MINUTES.get(severity, DEFAULT_SLA_MINUTES[SEVERITY_P3])


def validate_incident_type(incident_type: str) -> None:
    if incident_type not in ALL_INCIDENT_TYPES:
        raise ValueError(
            "Unknown incident type: %s (expected %s)"
            % (incident_type, ", ".join(ALL_INCIDENT_TYPES))
        )


def validate_severity(severity: str) -> None:
    if severity not in ALL_SEVERITIES:
        raise ValueError(
            "Unknown severity: %s (expected %s)" % (severity, ", ".join(ALL_SEVERITIES))
        )


def validate_status(status: str) -> None:
    if status not in ALL_STATUSES:
        raise ValueError("Unknown status: %s (expected %s)" % (status, ", ".join(ALL_STATUSES)))


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PlaybookStep:
    """One deterministic response step in a playbook."""

    step_id: str
    title: str
    action: str  # contain | investigate | remediate | notify | monitor | close
    command: str  # deterministic command / procedure string
    expected_output: str  # what a successful execution looks like
    completed: bool = False
    result: Optional[str] = None


@dataclass(frozen=True)
class Playbook:
    """A deterministic response playbook for one incident type + severity."""

    playbook_id: str
    incident_type: str
    name: str
    severity: str  # P1 | P2 | P3 | P4
    steps: Tuple[PlaybookStep, ...]
    sla_minutes: int


@dataclass(frozen=True)
class Incident:
    """A detected incident awaiting / in progress response."""

    incident_id: str
    title: str
    incident_type: str
    severity: str  # P1 | P2 | P3 | P4
    status: str  # open | investigating | remediated | closed
    source: str  # alert | finding | red_team
    source_id: str
    created_at: str
    updated_at: str
    sla_deadline: Optional[str]
    playbook_id: Optional[str] = None
    current_step: int = 0


@dataclass(frozen=True)
class IncidentResponse:
    """Result of executing (part or all of) a playbook against an incident."""

    incident_id: str
    playbook_id: str
    steps: Tuple[PlaybookStep, ...]
    completed_steps: int
    total_steps: int
    status: str
    escalated: bool
    notification_sent: bool


# --------------------------------------------------------------------------- #
# Playbook definitions (pure, deterministic)
# --------------------------------------------------------------------------- #


def _security_breach_steps(severity: str) -> Tuple[PlaybookStep, ...]:
    return (
        PlaybookStep(
            step_id="sec-01",
            title="Contain the breach",
            action=ACTION_CONTAIN,
            command="isolate affected systems; revoke active sessions for involved tenants",
            expected_output="affected systems isolated; sessions revoked",
        ),
        PlaybookStep(
            step_id="sec-02",
            title="Preserve evidence",
            action=ACTION_INVESTIGATE,
            command="capture audit logs, network flows, and disk snapshots of affected hosts",
            expected_output="evidence package stored in evidence/",
        ),
        PlaybookStep(
            step_id="sec-03",
            title="Investigate scope and entry vector",
            action=ACTION_INVESTIGATE,
            command="correlate alerts, authz events, and red-team findings to identify root cause",
            expected_output="root cause and affected asset list documented",
        ),
        PlaybookStep(
            step_id="sec-04",
            title="Remediate vulnerable controls",
            action=ACTION_REMEDIATE,
            command="patch the exploited vulnerability; rotate exposed credentials and keys",
            expected_output="vulnerability patched; credentials rotated",
        ),
        PlaybookStep(
            step_id="sec-05",
            title="Notify stakeholders",
            action=ACTION_NOTIFY,
            command="alert SOC, legal, and affected parties per notification routing",
            expected_output="notifications sent to P1/P2 roster",
        ),
        PlaybookStep(
            step_id="sec-06",
            title="Close with post-incident review",
            action=ACTION_CLOSE,
            command="publish post-mortem; update hardening config and detection rules",
            expected_output="post-incident review recorded; controls updated",
        ),
    )


def _data_exfiltration_steps(severity: str) -> Tuple[PlaybookStep, ...]:
    return (
        PlaybookStep(
            step_id="exfil-01",
            title="Contain exfiltration channels",
            action=ACTION_CONTAIN,
            command="block external destinations in DLP/flow logs; revoke data-access tokens",
            expected_output="exfiltration destinations blocked",
        ),
        PlaybookStep(
            step_id="exfil-02",
            title="Preserve evidence",
            action=ACTION_INVESTIGATE,
            command="capture DNS, proxy, and flow logs for the exfiltration window",
            expected_output="network evidence preserved",
        ),
        PlaybookStep(
            step_id="exfil-03",
            title="Determine exfiltrated data scope",
            action=ACTION_INVESTIGATE,
            command="query DLP matches and object-access logs to enumerate exposed records",
            expected_output="exposed record count and schema documented",
        ),
        PlaybookStep(
            step_id="exfil-04",
            title="Remediate access controls",
            action=ACTION_REMEDIATE,
            command="rotate data-plane credentials; re-encrypt data at rest; tighten RLS policies",
            expected_output="credentials rotated; data re-encrypted",
        ),
        PlaybookStep(
            step_id="exfil-05",
            title="Notify affected parties and regulators",
            action=ACTION_NOTIFY,
            command="issue breach notifications per SLA and data-protection obligations",
            expected_output="breach notifications dispatched",
        ),
        PlaybookStep(
            step_id="exfil-06",
            title="Close with post-incident review",
            action=ACTION_CLOSE,
            command="record lessons learned; tighten DLP and egress controls",
            expected_output="post-incident review recorded",
        ),
    )


def _service_degradation_steps(severity: str) -> Tuple[PlaybookStep, ...]:
    return (
        PlaybookStep(
            step_id="deg-01",
            title="Investigate degradation source",
            action=ACTION_INVESTIGATE,
            command="inspect metrics, health probes, and dependency latency",
            expected_output="degraded component and symptom identified",
        ),
        PlaybookStep(
            step_id="deg-02",
            title="Contain impact",
            action=ACTION_CONTAIN,
            command="fail traffic over to healthy instances; enable circuit breakers",
            expected_output="traffic failing over; circuit breakers engaged",
        ),
        PlaybookStep(
            step_id="deg-03",
            title="Remediate the failing component",
            action=ACTION_REMEDIATE,
            command="restart or scale the degraded service; clear backpressure",
            expected_output="service restored to healthy state",
        ),
        PlaybookStep(
            step_id="deg-04",
            title="Monitor recovery",
            action=ACTION_MONITOR,
            command="track latency/error-rate SLOs until stable within budget",
            expected_output="SLOs compliant; error budget recovering",
        ),
        PlaybookStep(
            step_id="deg-05",
            title="Close incident",
            action=ACTION_CLOSE,
            command="document root cause and capacity/autoscaling adjustments",
            expected_output="incident closed; remediation tracked",
        ),
    )


def _detection_failure_steps(severity: str) -> Tuple[PlaybookStep, ...]:
    return (
        PlaybookStep(
            step_id="det-01",
            title="Investigate detection blind spot",
            action=ACTION_INVESTIGATE,
            command="check sensor health, alert-rule state, and metric pipeline",
            expected_output="blind-spot component identified",
        ),
        PlaybookStep(
            step_id="det-02",
            title="Contain with manual monitoring",
            action=ACTION_CONTAIN,
            command="enable manual watches and fallback alerts for the affected domain",
            expected_output="manual monitoring active",
        ),
        PlaybookStep(
            step_id="det-03",
            title="Remediate detection rules",
            action=ACTION_REMEDIATE,
            command="fix or redeploy alert rules and sensors; backfill missing telemetry",
            expected_output="detection restored; rules validated",
        ),
        PlaybookStep(
            step_id="det-04",
            title="Verify with synthetic events",
            action=ACTION_MONITOR,
            command="inject test detection events to confirm alerting fires",
            expected_output="synthetic events detected and alerted",
        ),
        PlaybookStep(
            step_id="det-05",
            title="Close incident",
            action=ACTION_CLOSE,
            command="document detection gap and add regression coverage",
            expected_output="incident closed; regression test added",
        ),
    )


_PLAYBOOK_STEP_BUILDERS: Dict[str, Callable[[str], Tuple[PlaybookStep, ...]]] = {
    INCIDENT_TYPE_SECURITY_BREACH: _security_breach_steps,
    INCIDENT_TYPE_DATA_EXFILTRATION: _data_exfiltration_steps,
    INCIDENT_TYPE_SERVICE_DEGRADATION: _service_degradation_steps,
    INCIDENT_TYPE_DETECTION_FAILURE: _detection_failure_steps,
}


def build_playbook(incident_type: str, severity: str) -> Playbook:
    """Build the deterministic playbook for an incident type + severity.

    Same inputs always produce the same playbook (fixed step ordering,
    fixed step IDs, fixed SLA).
    """
    validate_incident_type(incident_type)
    validate_severity(severity)
    steps_builder = _PLAYBOOK_STEP_BUILDERS[incident_type]
    steps = steps_builder(severity)
    name = incident_type.replace("_", " ").title() + " Response"
    playbook_id = _hash_id("PLAYBOOK", (incident_type, severity, name, str(len(steps))))
    return Playbook(
        playbook_id=playbook_id,
        incident_type=incident_type,
        name=name,
        severity=severity,
        steps=steps,
        sla_minutes=sla_minutes_for(severity),
    )


# --------------------------------------------------------------------------- #
# Incident construction (pure, deterministic)
# --------------------------------------------------------------------------- #


def new_incident(
    title: str,
    incident_type: str,
    severity: str,
    source: str,
    source_id: str,
    now_iso: Optional[str] = None,
    playbook: Optional[Playbook] = None,
) -> Incident:
    """Create a new incident with deterministic id.

    incident_id is a content hash of (title, type, source, source_id, severity)
    so the same incident reported twice yields the same id.
    """
    validate_incident_type(incident_type)
    validate_severity(severity)
    validate_status(STATUS_OPEN)
    now_iso = now_iso or utc_now_iso()
    incident_id = _hash_id("INC", (title, incident_type, source, source_id, severity))
    sla_deadline = None
    if playbook is not None:
        sla_deadline = _add_minutes(now_iso, playbook.sla_minutes)
    elif severity:
        sla_deadline = _add_minutes(now_iso, sla_minutes_for(severity))
    return Incident(
        incident_id=incident_id,
        title=title,
        incident_type=incident_type,
        severity=severity,
        status=STATUS_OPEN,
        source=source,
        source_id=source_id,
        created_at=now_iso,
        updated_at=now_iso,
        sla_deadline=sla_deadline,
        playbook_id=playbook.playbook_id if playbook else None,
        current_step=0,
    )


def _add_minutes(iso_ts: str, minutes: int) -> str:
    dt = datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    from datetime import timedelta

    dt = dt + timedelta(minutes=minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def incident_from_alert(
    alert: Any,
    now_iso: Optional[str] = None,
) -> Tuple[Incident, Playbook]:
    """Build an incident from an observability Alert.

    Maps alert severity to incident severity; derives title/type from the
    alert rule name and metric.
    """
    now_iso = now_iso or utc_now_iso()
    severity = severity_for_alert(getattr(alert, "severity", "info"))
    rule_name = getattr(alert, "rule_id", "unknown")
    metric = getattr(alert, "metric", "unknown")
    title = "Observability alert: %s (%s)" % (rule_name, metric)
    incident_type = INCIDENT_TYPE_SERVICE_DEGRADATION
    if getattr(alert, "severity", "") in ("emergency", "critical"):
        incident_type = INCIDENT_TYPE_SECURITY_BREACH
    source_id = getattr(alert, "alert_id", rule_name)
    incident = new_incident(
        title=title,
        incident_type=incident_type,
        severity=severity,
        source=SOURCE_ALERT,
        source_id=source_id,
        now_iso=now_iso,
    )
    playbook = build_playbook(incident_type, severity)
    return incident, playbook


def incident_from_finding(
    finding: Any,
    finding_type: str,
    now_iso: Optional[str] = None,
) -> Tuple[Incident, Playbook]:
    """Build an incident from a security finding (hardening / penetration / red team)."""
    now_iso = now_iso or utc_now_iso()
    severity = (
        SEVERITY_P1 if finding_type in ("security_breach", "data_exfiltration") else SEVERITY_P2
    )
    title = "Security finding: %s" % getattr(finding, "finding_id", finding_type)
    incident_type = INCIDENT_TYPE_SECURITY_BREACH
    source_id = getattr(finding, "finding_id", finding_type)
    incident = new_incident(
        title=title,
        incident_type=incident_type,
        severity=severity,
        source=SOURCE_FINDING,
        source_id=source_id,
        now_iso=now_iso,
    )
    playbook = build_playbook(incident_type, severity)
    return incident, playbook


# --------------------------------------------------------------------------- #
# Response execution (pure)
# --------------------------------------------------------------------------- #


def execute_step(
    incident: Incident,
    playbook: Playbook,
    step_index: int,
) -> Tuple[Incident, PlaybookStep, bool]:
    """Execute a single playbook step (pure computation).

    Returns (updated_incident, executed_step, step_was_completed).
    Deterministic: marking a step complete does not depend on any external
    state beyond the step index.
    """
    if step_index < 0 or step_index >= len(playbook.steps):
        raise IndexError(
            "Step index %d out of range (0..%d)" % (step_index, len(playbook.steps) - 1)
        )
    step = playbook.steps[step_index]
    completed_step = PlaybookStep(
        step_id=step.step_id,
        title=step.title,
        action=step.action,
        command=step.command,
        expected_output=step.expected_output,
        completed=True,
        result="completed: %s" % step.expected_output,
    )
    new_status = STATUS_INVESTIGATING
    if step_index == len(playbook.steps) - 1:
        new_status = STATUS_REMEDIATED
    updated = Incident(
        incident_id=incident.incident_id,
        title=incident.title,
        incident_type=incident.incident_type,
        severity=incident.severity,
        status=new_status,
        source=incident.source,
        source_id=incident.source_id,
        created_at=incident.created_at,
        updated_at=utc_now_iso(),
        sla_deadline=incident.sla_deadline,
        playbook_id=incident.playbook_id,
        current_step=step_index + 1,
    )
    return updated, completed_step, True


def execute_playbook(
    incident: Incident,
    playbook: Playbook,
) -> Tuple[Incident, IncidentResponse]:
    """Execute every step of a playbook against an incident (pure).

    Returns (final_incident, response). All steps are marked completed;
    final status is remediated.
    """
    steps: list[PlaybookStep] = []
    current = incident
    for i in range(len(playbook.steps)):
        current, step, _ = execute_step(current, playbook, i)
        steps.append(step)
    response = IncidentResponse(
        incident_id=incident.incident_id,
        playbook_id=playbook.playbook_id,
        steps=tuple(steps),
        completed_steps=len(steps),
        total_steps=len(steps),
        status=STATUS_REMEDIATED,
        escalated=False,
        notification_sent=False,
    )
    return current, response


def asdict_incident(incident: Incident) -> Dict[str, Any]:
    data = asdict(incident)
    return data


def asdict_response(response: IncidentResponse) -> Dict[str, Any]:
    data = asdict(response)
    data["steps"] = [asdict(s) for s in data["steps"]]
    return data
