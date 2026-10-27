"""``c-uas ir`` subcommand: Incident Response Playbooks.

Usage:
    c-uas ir --create --type <type> --source <source> --source-id <id> --severity <P1|P2|P3|P4>
    c-uas ir --list
    c-uas ir --execute --incident-id <id> [--step <index>]
    c-uas ir --escalate --incident-id <id>

All output is deterministic. State persists under
~/.c-uas-platform/incident_response/ (outside the repo).

Integrates with c_uas.observability.alerts (alerts -> incidents) and
c_uas.security (findings -> incidents).

License: AGPL-3.0.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, List, Optional

from .escalation import escalate_incident
from .manager import (
    DEFAULT_STATE_DIR,
    IncidentManager,
)
from .playbook import (
    INCIDENT_TYPE_DATA_EXFILTRATION,
    INCIDENT_TYPE_DETECTION_FAILURE,
    INCIDENT_TYPE_SECURITY_BREACH,
    INCIDENT_TYPE_SERVICE_DEGRADATION,
    Incident,
    Playbook,
    validate_incident_type,
    validate_severity,
)

ALL_INCIDENT_TYPES_FOR_CLI: tuple[str, ...] = (
    INCIDENT_TYPE_SECURITY_BREACH,
    INCIDENT_TYPE_DATA_EXFILTRATION,
    INCIDENT_TYPE_SERVICE_DEGRADATION,
    INCIDENT_TYPE_DETECTION_FAILURE,
)


def build_subparser(subparsers: Any) -> Any:
    """Register the ``ir`` subcommand on a parent parser (e.g. c_uas.cli)."""
    parser = subparsers.add_parser(
        "ir",
        help=(
            "Incident Response: create incidents from alerts/findings, "
            "execute playbooks, track status, and escalate by SLA"
        ),
    )
    parser.add_argument(
        "--create",
        action="store_true",
        help="Create a new incident (requires --type, --source, --source-id)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all persisted incidents with status and severity",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute a playbook for an incident (requires --incident-id)",
    )
    parser.add_argument(
        "--escalate",
        action="store_true",
        help="Evaluate and persist escalation for an incident (requires --incident-id)",
    )
    parser.add_argument(
        "--incident-id",
        type=str,
        default=None,
        help="Incident id (for --execute / --escalate)",
    )
    parser.add_argument(
        "--type",
        type=str,
        default=None,
        help="Incident type (%s)" % ", ".join(ALL_INCIDENT_TYPES_FOR_CLI),
    )
    parser.add_argument(
        "--source",
        type=str,
        default=None,
        help="Source: alert | finding | red_team",
    )
    parser.add_argument(
        "--source-id",
        type=str,
        default=None,
        help="Source id (alert id, finding id, or red-team scenario id)",
    )
    parser.add_argument(
        "--severity",
        type=str,
        default=None,
        help="Severity: P1 | P2 | P3 | P4",
    )
    parser.add_argument(
        "--title",
        type=str,
        default=None,
        help="Incident title (default: derived from source)",
    )
    parser.add_argument(
        "--step",
        type=int,
        default=None,
        help="Execute only this step index (with --execute)",
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default=None,
        help="Incident response state dir (default: ~/.c-uas-platform/incident_response/)",
    )
    return parser


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #


def _render_incident(incident: Incident) -> List[str]:
    lines: List[str] = []
    lines.append("[C-UAS] Incident %s" % incident.incident_id)
    lines.append("  title        : %s" % incident.title)
    lines.append("  type         : %s" % incident.incident_type)
    lines.append("  severity     : %s" % incident.severity)
    lines.append("  status       : %s" % incident.status)
    lines.append("  source       : %s (%s)" % (incident.source, incident.source_id))
    lines.append("  created_at   : %s" % incident.created_at)
    lines.append("  updated_at   : %s" % incident.updated_at)
    lines.append("  sla_deadline : %s" % (incident.sla_deadline or "n/a"))
    lines.append("  playbook_id  : %s" % (incident.playbook_id or "none"))
    lines.append("  current_step : %d" % incident.current_step)
    return lines


def _render_incidents(incidents: List[Incident]) -> str:
    lines: List[str] = ["[C-UAS] Incidents (%d total)" % len(incidents)]
    if not incidents:
        lines.append("  (none)")
    for inc in incidents:
        lines.append("")
        lines.extend(_render_incident(inc))
    return "\n".join(lines)


def _render_playbook(playbook: Playbook) -> List[str]:
    lines: List[str] = []
    lines.append("[C-UAS] Playbook %s" % playbook.playbook_id)
    lines.append("  name         : %s" % playbook.name)
    lines.append("  type         : %s" % playbook.incident_type)
    lines.append("  severity     : %s" % playbook.severity)
    lines.append("  sla_minutes  : %d" % playbook.sla_minutes)
    lines.append("  steps        : %d" % len(playbook.steps))
    for step in playbook.steps:
        lines.append("    [%s] %s: %s" % (step.step_id, step.action.upper(), step.title))
        lines.append("          command : %s" % step.command)
        lines.append("          expect  : %s" % step.expected_output)
    return lines


def _render_response(response) -> str:
    lines: List[str] = []
    lines.append("[C-UAS] Incident Response %s" % response.incident_id)
    lines.append("  playbook_id    : %s" % response.playbook_id)
    lines.append("  completed_steps: %d / %d" % (response.completed_steps, response.total_steps))
    lines.append("  status         : %s" % response.status)
    lines.append("  escalated      : %s" % response.escalated)
    lines.append("  notifications  : %s" % response.notification_sent)
    return "\n".join(lines)


def _render_escalation(result) -> str:
    lines: List[str] = []
    lines.append("[C-UAS] Escalation %s" % result.incident_id)
    lines.append("  severity          : %s" % result.severity)
    lines.append("  escalation_level  : %d" % result.escalation_level)
    lines.append("  primary_responder : %s" % result.primary_responder)
    lines.append("  secondary_responder: %s" % result.secondary_responder or "(none)")
    lines.append("  channels          : %s" % ", ".join(result.channels))
    lines.append("  sla_breached      : %s" % result.sla_breached)
    lines.append("  time_remaining_s  : %.1f" % result.time_remaining_seconds)
    lines.append("  notifications     : %d" % len(result.notifications))
    for n in result.notifications:
        lines.append("    - [%s] %s -> %s: %s" % (n.channel, n.recipient, n.sent_at, n.message))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #


def handle_create(args: argparse.Namespace, manager: IncidentManager) -> str:
    if not args.type or not args.source or not args.source_id:
        raise ValueError("--type, --source, and --source-id are required for --create")
    validate_incident_type(args.type)
    severity = args.severity
    if severity is None:
        # Default severity by source type.
        severity = "P2"
    validate_severity(severity)
    title = args.title or "%s: %s" % (args.type, args.source_id)
    incident, playbook = manager.create_incident(
        title=title,
        incident_type=args.type,
        severity=severity,
        source=args.source,
        source_id=args.source_id,
        auto_playbook=True,
    )
    lines: List[str] = []
    lines.append("[C-UAS] Incident created")
    lines.append("  incident_id : %s" % incident.incident_id)
    lines.append("  playbook_id : %s" % (playbook.playbook_id if playbook else "none"))
    lines.append("  status      : %s" % incident.status)
    lines.append("  severity    : %s" % incident.severity)
    return "\n".join(lines)


def handle_list(manager: IncidentManager) -> str:
    incidents = manager.list_incidents()
    return _render_incidents(incidents)


def handle_execute(args: argparse.Namespace, manager: IncidentManager) -> str:
    if not args.incident_id:
        raise ValueError("--incident-id is required for --execute")
    updated, step, response = manager.execute_incident(args.incident_id, step_index=args.step)
    lines: List[str] = []
    lines.append("[C-UAS] Incident executed: %s" % updated.incident_id)
    lines.append("  status : %s" % updated.status)
    lines.append("  step   : %d" % updated.current_step)
    if step is not None:
        lines.append("  executed_step : %s" % step.step_id)
        lines.append("  action       : %s" % step.action)
        lines.append("  completed    : %s" % step.completed)
    if response is not None:
        lines.append(_render_response(response))
    return "\n".join(lines)


def handle_escalate(args: argparse.Namespace, manager: IncidentManager) -> str:
    if not args.incident_id:
        raise ValueError("--incident-id is required for --escalate")
    incident = manager.get_incident(args.incident_id)
    result = escalate_incident(incident)
    return _render_escalation(result)


def ir_main(args: argparse.Namespace) -> int:
    state_dir = args.state_dir or DEFAULT_STATE_DIR
    manager = IncidentManager(state_dir=state_dir)

    try:
        if args.create:
            print(handle_create(args, manager))
            return 0
        if args.list:
            print(handle_list(manager))
            return 0
        if args.execute:
            print(handle_execute(args, manager))
            return 0
        if args.escalate:
            print(handle_escalate(args, manager))
            return 0
    except (ValueError, KeyError, FileNotFoundError) as exc:
        print("[C-UAS] ir: %s" % exc)
        return 1

    print("[C-UAS] ir: specify --create, --list, --execute, or --escalate")
    print("  c-uas ir --create --type security_breach --source alert --source-id ALERT-001")
    print("  c-uas ir --list")
    print("  c-uas ir --execute --incident-id <id>")
    print("  c-uas ir --escalate --incident-id <id>")
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    """Standalone entry point: ``python -m c_uas.incident_response.cli``."""
    parser = argparse.ArgumentParser(
        prog="c-uas ir",
        description="Incident Response Playbooks for the C-UAS platform",
    )
    build_subparser(parser.add_subparsers(dest="command"))
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 1
    return ir_main(args)


if __name__ == "__main__":
    sys.exit(main())
