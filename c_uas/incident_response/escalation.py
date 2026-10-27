"""Escalation Engine for the C-UAS platform.

Severity-based escalation (P1/P2/P3/P4), notification routing, SLA timer
tracking, and an escalation matrix. All computations are deterministic: given
the same incident and clock, the same escalation decision and notifications
are produced.

State (escalation records, SLA snapshots) persists under
``~/.c-uas-platform/incident_response/`` alongside incidents.

License: AGPL-3.0.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from .manager import DEFAULT_STATE_DIR, RESPONSES_SUBDIR
from .playbook import (
    SEVERITY_P1,
    SEVERITY_P2,
    SEVERITY_P3,
    SEVERITY_P4,
    Incident,
)

ALL_SEVERITIES = (SEVERITY_P1, SEVERITY_P2, SEVERITY_P3, SEVERITY_P4)

# SLA minutes per severity (mirrors playbook defaults; single source of truth).
SLA_MINUTES: Dict[str, int] = {
    SEVERITY_P1: 15,
    SEVERITY_P2: 60,
    SEVERITY_P3: 240,
    SEVERITY_P4: 1440,
}

# Escalation matrix: severity -> (primary responder, secondary responder,
# notification channels, auto-escalate after SLA breach in minutes).
ESCALATION_MATRIX: Dict[str, Tuple[str, str, Tuple[str, ...], int]] = {
    SEVERITY_P1: (
        "ciso@a2zsoc.com",
        "vp-engineering@a2zsoc.com",
        ("pagerduty", "sms", "email"),
        15,
    ),
    SEVERITY_P2: (
        "eng-lead@a2zsoc.com",
        "soc-lead@a2zsoc.com",
        ("pagerduty", "email"),
        60,
    ),
    SEVERITY_P3: (
        "soc-team@a2zsoc.com",
        "on-call@a2zsoc.com",
        ("email", "slack"),
        240,
    ),
    SEVERITY_P4: (
        "soc-team@a2zsoc.com",
        "",
        ("email",),
        1440,
    ),
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_id(prefix: str, parts: Tuple[str, ...]) -> str:
    raw = "|".join(parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def sla_minutes_for(severity: str) -> int:
    validate_severity(severity)
    return SLA_MINUTES[severity]


def validate_severity(severity: str) -> None:
    if severity not in ALL_SEVERITIES:
        raise ValueError(
            "Unknown severity: %s (expected %s)" % (severity, ", ".join(ALL_SEVERITIES))
        )


def sla_deadline(created_at: str, severity: str) -> str:
    """Compute the SLA deadline ISO timestamp for an incident."""
    validate_severity(severity)
    dt = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    dt = dt + timedelta(minutes=SLA_MINUTES[severity])
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def time_remaining(created_at: str, severity: str, now_iso: Optional[str] = None) -> float:
    """Seconds remaining until SLA breach (negative means already breached)."""
    deadline = sla_deadline(created_at, severity)
    now = datetime.strptime(now_iso or utc_now_iso(), "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    dl = datetime.strptime(deadline, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (dl - now).total_seconds()


def is_sla_breached(created_at: str, severity: str, now_iso: Optional[str] = None) -> bool:
    return time_remaining(created_at, severity, now_iso) < 0


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EscalationPolicy:
    severity: str
    primary_responder: str
    secondary_responder: str
    channels: Tuple[str, ...]
    auto_escalate_after_minutes: int
    sla_minutes: int


@dataclass(frozen=True)
class Notification:
    notification_id: str
    incident_id: str
    severity: str
    channel: str
    recipient: str
    sent_at: str
    message: str


@dataclass(frozen=True)
class EscalationRecord:
    incident_id: str
    severity: str
    sla_minutes: int
    sla_deadline: str
    sla_breached: bool
    time_remaining_seconds: float
    escalation_level: int  # 0 = initial, 1 = primary, 2 = secondary
    primary_responder: str
    secondary_responder: str
    channels: Tuple[str, ...]
    notifications: Tuple[Notification, ...]
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class EscalationResult:
    incident_id: str
    severity: str
    escalation_level: int
    primary_responder: str
    secondary_responder: str
    channels: Tuple[str, ...]
    notifications: Tuple[Notification, ...]
    sla_breached: bool
    time_remaining_seconds: float
    record: EscalationRecord


# --------------------------------------------------------------------------- #
# Policy lookup
# --------------------------------------------------------------------------- #


def policy_for(severity: str) -> EscalationPolicy:
    validate_severity(severity)
    primary, secondary, channels, auto_escalate = ESCALATION_MATRIX[severity]
    return EscalationPolicy(
        severity=severity,
        primary_responder=primary,
        secondary_responder=secondary,
        channels=channels,
        auto_escalate_after_minutes=auto_escalate,
        sla_minutes=SLA_MINUTES[severity],
    )


# --------------------------------------------------------------------------- #
# Notification routing (pure)
# --------------------------------------------------------------------------- #


def route_notification(
    incident: Incident,
    channel: str,
    now_iso: Optional[str] = None,
) -> Notification:
    """Produce a deterministic notification for one channel."""
    now_iso = now_iso or utc_now_iso()
    recipient = _recipient_for_channel(incident.severity, channel)
    message = "[C-UAS] Incident %s [%s] %s — severity %s, status %s, SLA deadline %s" % (
        incident.incident_id,
        incident.severity,
        incident.title,
        incident.severity,
        incident.status,
        incident.sla_deadline or "n/a",
    )
    notification_id = _hash_id("NOTIF", (incident.incident_id, channel, now_iso, message))
    return Notification(
        notification_id=notification_id,
        incident_id=incident.incident_id,
        severity=incident.severity,
        channel=channel,
        recipient=recipient,
        sent_at=now_iso,
        message=message,
    )


def _recipient_for_channel(severity: str, channel: str) -> str:
    policy = policy_for(severity)
    if channel == "sms":
        return policy.primary_responder
    if channel == "pagerduty":
        return policy.primary_responder
    if channel == "slack":
        return policy.secondary_responder or policy.primary_responder
    # email and anything else
    return policy.primary_responder


def notify_all(
    incident: Incident,
    now_iso: Optional[str] = None,
) -> Tuple[Notification, ...]:
    """Route notifications to every channel in the severity's policy."""
    now_iso = now_iso or utc_now_iso()
    policy = policy_for(incident.severity)
    notifications = tuple(
        route_notification(incident, channel, now_iso=now_iso) for channel in policy.channels
    )
    return notifications


# --------------------------------------------------------------------------- #
# Escalation engine
# --------------------------------------------------------------------------- #


class EscalationEngine:
    """Computes escalation level, SLA status, and notifications for incidents."""

    def __init__(self, state_dir: Optional[str] = None) -> None:
        self.state_dir = state_dir or DEFAULT_STATE_DIR
        self.responses_dir = os.path.join(self.state_dir, RESPONSES_SUBDIR)

    def ensure_dirs(self) -> None:
        os.makedirs(self.responses_dir, exist_ok=True)

    def evaluate(
        self,
        incident: Incident,
        now_iso: Optional[str] = None,
    ) -> EscalationResult:
        """Determine the escalation state for an incident (pure computation).

        Escalation level:
          0 = initial (no breach)
          1 = primary responder notified (SLA breached)
          2 = secondary responder notified (SLA breached + grace period)
        """
        now_iso = now_iso or utc_now_iso()
        validate_severity(incident.severity)
        policy = policy_for(incident.severity)
        deadline = sla_deadline(incident.created_at, incident.severity)
        breached = is_sla_breached(incident.created_at, incident.severity, now_iso=now_iso)
        remaining = time_remaining(incident.created_at, incident.severity, now_iso=now_iso)

        level = 0
        if breached:
            level = 1
            if remaining < -policy.auto_escalate_after_minutes * 60:
                level = 2

        notifications = notify_all(incident, now_iso=now_iso) if breached else ()

        record = EscalationRecord(
            incident_id=incident.incident_id,
            severity=incident.severity,
            sla_minutes=policy.sla_minutes,
            sla_deadline=deadline,
            sla_breached=breached,
            time_remaining_seconds=remaining,
            escalation_level=level,
            primary_responder=policy.primary_responder,
            secondary_responder=policy.secondary_responder,
            channels=policy.channels,
            notifications=notifications,
            created_at=incident.created_at,
            updated_at=now_iso,
        )
        result = EscalationResult(
            incident_id=incident.incident_id,
            severity=incident.severity,
            escalation_level=level,
            primary_responder=policy.primary_responder,
            secondary_responder=policy.secondary_responder,
            channels=policy.channels,
            notifications=notifications,
            sla_breached=breached,
            time_remaining_seconds=remaining,
            record=record,
        )
        return result

    def save_record(self, record: EscalationRecord) -> str:
        self.ensure_dirs()
        data = {
            "incident_id": record.incident_id,
            "severity": record.severity,
            "sla_minutes": record.sla_minutes,
            "sla_deadline": record.sla_deadline,
            "sla_breached": record.sla_breached,
            "time_remaining_seconds": record.time_remaining_seconds,
            "escalation_level": record.escalation_level,
            "primary_responder": record.primary_responder,
            "secondary_responder": record.secondary_responder,
            "channels": list(record.channels),
            "notifications": [asdict(n) for n in record.notifications],
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }
        path = os.path.join(self.responses_dir, record.incident_id + ".escalation.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp, path)
        return record.incident_id

    def load_record(self, incident_id: str) -> Optional[EscalationRecord]:
        path = os.path.join(self.responses_dir, incident_id + ".escalation.json")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return _record_from_dict(data)


def _notification_from_dict(data: Dict[str, Any]) -> Notification:
    return Notification(
        notification_id=data["notification_id"],
        incident_id=data["incident_id"],
        severity=data["severity"],
        channel=data["channel"],
        recipient=data["recipient"],
        sent_at=data["sent_at"],
        message=data["message"],
    )


def _record_from_dict(data: Dict[str, Any]) -> EscalationRecord:
    return EscalationRecord(
        incident_id=data["incident_id"],
        severity=data["severity"],
        sla_minutes=int(data["sla_minutes"]),
        sla_deadline=data["sla_deadline"],
        sla_breached=bool(data["sla_breached"]),
        time_remaining_seconds=float(data["time_remaining_seconds"]),
        escalation_level=int(data["escalation_level"]),
        primary_responder=data["primary_responder"],
        secondary_responder=data["secondary_responder"],
        channels=tuple(data["channels"]),
        notifications=tuple(_notification_from_dict(n) for n in data["notifications"]),
        created_at=data["created_at"],
        updated_at=data["updated_at"],
    )


def escalate_incident(
    incident: Incident,
    now_iso: Optional[str] = None,
    engine: Optional[EscalationEngine] = None,
) -> EscalationResult:
    """Convenience: evaluate and persist an escalation record."""
    now_iso = now_iso or utc_now_iso()
    eng = engine or EscalationEngine()
    result = eng.evaluate(incident, now_iso=now_iso)
    eng.save_record(result.record)
    return result
