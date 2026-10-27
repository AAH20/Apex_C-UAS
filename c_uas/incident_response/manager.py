"""Incident Manager for the C-UAS platform.

Creates incidents from observability alerts and security findings, executes
playbooks step-by-step, tracks incident status (open / investigating /
remediated / closed), and persists all state under
``~/.c-uas-platform/incident_response/`` (outside the repo).

All persistence is deterministic JSON; incident ids are content hashes so the
same incident reported twice resolves to the same record. No network, no live
credentials.

License: AGPL-3.0.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .playbook import (
    Incident,
    IncidentResponse,
    Playbook,
    PlaybookStep,
    build_playbook,
    execute_playbook,
    execute_step,
    incident_from_alert,
    incident_from_finding,
    new_incident,
    validate_incident_type,
    validate_severity,
)

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "incident_response")
INCIDENTS_SUBDIR = "incidents"
PLAYBOOKS_SUBDIR = "playbooks"
RESPONSES_SUBDIR = "responses"
LATEST_FILENAME = "latest_incidents.json"


def utc_now_iso_local() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Persistence store
# --------------------------------------------------------------------------- #


class IncidentStore:
    """Save/load incidents, playbooks, and responses under <state_dir>/."""

    def __init__(self, state_dir: str = DEFAULT_STATE_DIR) -> None:
        self.dir = state_dir
        self.incidents_dir = os.path.join(state_dir, INCIDENTS_SUBDIR)
        self.playbooks_dir = os.path.join(state_dir, PLAYBOOKS_SUBDIR)
        self.responses_dir = os.path.join(state_dir, RESPONSES_SUBDIR)

    def ensure_dirs(self) -> None:
        for d in (self.incidents_dir, self.playbooks_dir, self.responses_dir):
            os.makedirs(d, exist_ok=True)

    # -- incidents ---------------------------------------------------------- #

    def _incident_path(self, incident_id: str) -> str:
        return os.path.join(self.incidents_dir, incident_id + ".json")

    def save_incident(self, incident: Incident) -> str:
        self.ensure_dirs()
        data = asdict(incident)
        tmp_path = self._incident_path(incident.incident_id) + ".tmp"
        final_path = self._incident_path(incident.incident_id)
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp_path, final_path)
        self._write_latest()
        return incident.incident_id

    def load_incident(self, incident_id: str) -> Incident:
        with open(self._incident_path(incident_id), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return _incident_from_dict(data)

    def latest_incident_ids(self) -> List[str]:
        self.ensure_dirs()
        ids: List[str] = []
        if os.path.isdir(self.incidents_dir):
            for name in sorted(os.listdir(self.incidents_dir)):
                if name.endswith(".json"):
                    ids.append(name[:-5])
        return ids

    def all_incidents(self) -> List[Incident]:
        return [self.load_incident(iid) for iid in self.latest_incident_ids()]

    def _write_latest(self) -> None:
        latest_path = os.path.join(self.dir, LATEST_FILENAME)
        tmp = latest_path + ".tmp"
        ids = self.latest_incident_ids()
        payload = {"incident_ids": ids, "count": len(ids)}
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        os.replace(tmp, latest_path)

    # -- playbooks ---------------------------------------------------------- #

    def _playbook_path(self, playbook_id: str) -> str:
        return os.path.join(self.playbooks_dir, playbook_id + ".json")

    def save_playbook(self, playbook: Playbook) -> str:
        self.ensure_dirs()
        data = {
            "playbook_id": playbook.playbook_id,
            "incident_type": playbook.incident_type,
            "name": playbook.name,
            "severity": playbook.severity,
            "steps": [asdict(s) for s in playbook.steps],
            "sla_minutes": playbook.sla_minutes,
        }
        tmp_path = self._playbook_path(playbook.playbook_id) + ".tmp"
        final_path = self._playbook_path(playbook.playbook_id)
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp_path, final_path)
        return playbook.playbook_id

    def load_playbook(self, playbook_id: str) -> Playbook:
        with open(self._playbook_path(playbook_id), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return _playbook_from_dict(data)

    # -- responses ---------------------------------------------------------- #

    def _response_path(self, response_id: str) -> str:
        return os.path.join(self.responses_dir, response_id + ".json")

    def save_response(self, response: IncidentResponse) -> str:
        self.ensure_dirs()
        data = {
            "incident_id": response.incident_id,
            "playbook_id": response.playbook_id,
            "steps": [asdict(s) for s in response.steps],
            "completed_steps": response.completed_steps,
            "total_steps": response.total_steps,
            "status": response.status,
            "escalated": response.escalated,
            "notification_sent": response.notification_sent,
        }
        tmp_path = self._response_path(response.incident_id) + ".tmp"
        final_path = self._response_path(response.incident_id)
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp_path, final_path)
        return response.incident_id

    def load_response(self, incident_id: str) -> IncidentResponse:
        with open(self._response_path(incident_id), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return _response_from_dict(data)


# --------------------------------------------------------------------------- #
# Dict <-> dataclass conversions
# --------------------------------------------------------------------------- #


def _step_from_dict(data: Dict[str, Any]) -> PlaybookStep:
    return PlaybookStep(
        step_id=data["step_id"],
        title=data["title"],
        action=data["action"],
        command=data["command"],
        expected_output=data["expected_output"],
        completed=bool(data.get("completed", False)),
        result=data.get("result"),
    )


def _playbook_from_dict(data: Dict[str, Any]) -> Playbook:
    return Playbook(
        playbook_id=data["playbook_id"],
        incident_type=data["incident_type"],
        name=data["name"],
        severity=data["severity"],
        steps=tuple(_step_from_dict(s) for s in data["steps"]),
        sla_minutes=data["sla_minutes"],
    )


def _incident_from_dict(data: Dict[str, Any]) -> Incident:
    return Incident(
        incident_id=data["incident_id"],
        title=data["title"],
        incident_type=data["incident_type"],
        severity=data["severity"],
        status=data["status"],
        source=data["source"],
        source_id=data["source_id"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
        sla_deadline=data.get("sla_deadline"),
        playbook_id=data.get("playbook_id"),
        current_step=int(data.get("current_step", 0)),
    )


def _response_from_dict(data: Dict[str, Any]) -> IncidentResponse:
    return IncidentResponse(
        incident_id=data["incident_id"],
        playbook_id=data["playbook_id"],
        steps=tuple(_step_from_dict(s) for s in data["steps"]),
        completed_steps=int(data["completed_steps"]),
        total_steps=int(data["total_steps"]),
        status=data["status"],
        escalated=bool(data.get("escalated", False)),
        notification_sent=bool(data.get("notification_sent", False)),
    )


# --------------------------------------------------------------------------- #
# IncidentManager
# --------------------------------------------------------------------------- #


class IncidentManager:
    """Coordinates incident creation, playbook execution, and persistence."""

    def __init__(self, state_dir: Optional[str] = None) -> None:
        self.state_dir = state_dir or DEFAULT_STATE_DIR
        self.store = IncidentStore(state_dir=self.state_dir)

    # -- creation ----------------------------------------------------------- #

    def create_incident(
        self,
        title: str,
        incident_type: str,
        severity: str,
        source: str,
        source_id: str,
        now_iso: Optional[str] = None,
        auto_playbook: bool = True,
    ) -> Tuple[Incident, Optional[Playbook]]:
        """Create and persist a new incident (and its playbook)."""
        validate_incident_type(incident_type)
        validate_severity(severity)
        incident = new_incident(
            title=title,
            incident_type=incident_type,
            severity=severity,
            source=source,
            source_id=source_id,
            now_iso=now_iso,
        )
        playbook: Optional[Playbook] = None
        if auto_playbook:
            playbook = build_playbook(incident_type, severity)
            incident = Incident(
                incident_id=incident.incident_id,
                title=incident.title,
                incident_type=incident.incident_type,
                severity=incident.severity,
                status=incident.status,
                source=incident.source,
                source_id=incident.source_id,
                created_at=incident.created_at,
                updated_at=incident.updated_at,
                sla_deadline=incident.sla_deadline,
                playbook_id=playbook.playbook_id,
                current_step=incident.current_step,
            )
            self.store.save_playbook(playbook)
        self.store.save_incident(incident)
        return incident, playbook

    def create_incident_from_alert(
        self,
        alert: Any,
        now_iso: Optional[str] = None,
    ) -> Tuple[Incident, Playbook]:
        """Create an incident from an observability alert and persist it."""
        incident, playbook = incident_from_alert(alert, now_iso=now_iso)
        self.store.save_playbook(playbook)
        self.store.save_incident(incident)
        return incident, playbook

    def create_incident_from_finding(
        self,
        finding: Any,
        finding_type: str,
        now_iso: Optional[str] = None,
    ) -> Tuple[Incident, Playbook]:
        """Create an incident from a security finding and persist it."""
        incident, playbook = incident_from_finding(finding, finding_type, now_iso=now_iso)
        self.store.save_playbook(playbook)
        self.store.save_incident(incident)
        return incident, playbook

    # -- retrieval ---------------------------------------------------------- #

    def get_incident(self, incident_id: str) -> Incident:
        return self.store.load_incident(incident_id)

    def list_incidents(self) -> List[Incident]:
        return self.store.all_incidents()

    def get_playbook(self, playbook_id: str) -> Playbook:
        return self.store.load_playbook(playbook_id)

    def get_response(self, incident_id: str) -> Optional[IncidentResponse]:
        path = os.path.join(self.state_dir, RESPONSES_SUBDIR, incident_id + ".json")
        if not os.path.exists(path):
            return None
        return self.store.load_response(incident_id)

    # -- execution ---------------------------------------------------------- #

    def execute_incident(
        self,
        incident_id: str,
        step_index: Optional[int] = None,
    ) -> Tuple[Incident, Optional[PlaybookStep], Optional[IncidentResponse]]:
        """Execute a playbook for an incident.

        If step_index is given, execute only that step (returns step result).
        Otherwise execute the whole playbook (returns full response).
        Persists updated incident and response.
        """
        incident = self.store.load_incident(incident_id)
        if incident.playbook_id is None:
            raise ValueError("Incident %s has no playbook" % incident_id)
        playbook = self.store.load_playbook(incident.playbook_id)

        if step_index is not None:
            updated, step, _ = execute_step(incident, playbook, step_index)
            self.store.save_incident(updated)
            return updated, step, None

        updated, response = execute_playbook(incident, playbook)
        self.store.save_incident(updated)
        self.store.save_playbook(playbook)
        self.store.save_response(response)
        return updated, None, response

    # -- status transitions ------------------------------------------------- #

    def set_status(self, incident_id: str, status: str) -> Incident:
        from .playbook import validate_status

        validate_status(status)
        incident = self.store.load_incident(incident_id)
        updated = Incident(
            incident_id=incident.incident_id,
            title=incident.title,
            incident_type=incident.incident_type,
            severity=incident.severity,
            status=status,
            source=incident.source,
            source_id=incident.source_id,
            created_at=incident.created_at,
            updated_at=utc_now_iso_local(),
            sla_deadline=incident.sla_deadline,
            playbook_id=incident.playbook_id,
            current_step=incident.current_step,
        )
        self.store.save_incident(updated)
        return updated

    def summary(self) -> Dict[str, Any]:
        incidents = self.list_incidents()
        by_status: Dict[str, int] = {
            s: 0 for s in ("open", "investigating", "remediated", "closed")
        }
        by_severity: Dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for inc in incidents:
            by_status[inc.status] = by_status.get(inc.status, 0) + 1
            by_severity[inc.severity] = by_severity.get(inc.severity, 0) + 1
        return {
            "total": len(incidents),
            "by_status": by_status,
            "by_severity": by_severity,
            "state_dir": self.state_dir,
        }
