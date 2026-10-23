"""
Real-time alert engine for critical C-UAS events.

The AlertEngine evaluates incoming detection events, incidents, and
compliance drops against a set of alert rules and dispatches matching
alerts to configured channels:

* console   - print to stdout
* webhook   - HTTP POST JSON payload to a URL
* email     - SMTP-free log-only stub (writes to the alert log)

Severity ordering: INFO < LOW < MEDIUM < HIGH < CRITICAL. An alert fires
when the event's threat level is at or above the rule's min_severity.

Pure Python; webhook uses urllib (stdlib) so no new runtime dependency.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .models import Alert, AlertRule, ChannelConfig, DetectionEvent

_SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

DEFAULT_RULES: List[AlertRule] = [
    AlertRule(
        rule_id="spoof_detection",
        event_type="spoof_detection",
        min_severity="CRITICAL",
    ),
    AlertRule(
        rule_id="high_confidence_track",
        event_type="high_confidence_track",
        min_severity="HIGH",
    ),
    AlertRule(
        rule_id="incident",
        event_type="incident",
        min_severity="MEDIUM",
    ),
    AlertRule(
        rule_id="compliance_drop",
        event_type="compliance_drop",
        min_severity="HIGH",
    ),
]


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get((severity or "INFO").upper(), 0)


def _alert_id(severity: str, event_type: str, target_id: str, timestamp: str) -> str:
    payload = f"{severity}|{event_type}|{target_id}|{timestamp}"
    return "alert--" + hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass
class Channel:
    """An alert delivery channel with a send callable."""

    config: ChannelConfig
    send: Callable[[Alert], None]


class ConsoleChannel:
    """Print alerts to stdout."""

    def send(self, alert: Alert) -> None:
        print(
            f"[C-UAS ALERT] {alert.severity} | {alert.event_type} | "
            f"{alert.message} | source={alert.source} | "
            f"target={alert.target_id or '-'} | {alert.timestamp}"
        )


class WebhookChannel:
    """POST alert JSON to a webhook URL (urllib, stdlib)."""

    def __init__(self, url: str, timeout_s: float = 5.0) -> None:
        self.url = url
        self.timeout_s = timeout_s

    def send(self, alert: Alert) -> None:
        data = json.dumps(alert.to_dict()).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                resp.read()  # consume body
        except (urllib.error.URLError, OSError) as exc:
            # Webhook failures must not kill the alert loop; log and continue.
            print(f"[C-UAS ALERT] webhook delivery failed ({self.url}): {exc}")


class EmailStubChannel:
    """SMTP-free log-only email stub. Writes the would-be email to stdout."""

    def __init__(self, email_to: Optional[str] = None) -> None:
        self.email_to = email_to or "soc@example.com"

    def send(self, alert: Alert) -> None:
        print(
            "[C-UAS ALERT EMAIL STUB] to={} subject='[C-UAS] {} alert: {}'\n"
            "  body: {} | {} | target={} | {}".format(
                self.email_to,
                alert.severity,
                alert.event_type,
                alert.timestamp,
                alert.message,
                alert.target_id or "-",
                alert.source,
            )
        )


class AlertEngine:
    """Evaluate events against rules and dispatch alerts to channels."""

    def __init__(
        self,
        rules: Optional[List[AlertRule]] = None,
        channels: Optional[List[Channel]] = None,
    ) -> None:
        self.rules: List[AlertRule] = list(rules or DEFAULT_RULES)
        self.channels: List[Channel] = list(channels or [])
        self.alerts: List[Alert] = []
        self._dispatch_hooks: List[Callable[[Alert], None]] = []

    # ---- channel management -----------------------------------------
    def add_channel(self, channel: Channel) -> None:
        self.channels.append(channel)

    def add_dispatch_hook(self, hook: Callable[[Alert], None]) -> None:
        self._dispatch_hooks.append(hook)

    # ---- rule evaluation --------------------------------------------
    def should_alert(self, event: DetectionEvent) -> List[AlertRule]:
        """Return rules whose min_severity is at or below the event level."""
        level = (event.threat_level or "NONE").upper()
        matched: List[AlertRule] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if _severity_rank(level) < _severity_rank(rule.min_severity):
                continue
            matched.append(rule)
        return matched

    # ---- alert emission ---------------------------------------------
    def emit(
        self,
        severity: str,
        event_type: str,
        message: str,
        source: str,
        target_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """Create and dispatch an alert."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        alert = Alert(
            alert_id=_alert_id(severity, event_type, target_id or "-", timestamp),
            timestamp=timestamp,
            severity=severity,
            event_type=event_type,
            message=message,
            source=source,
            target_id=target_id,
            metadata=metadata or {},
        )
        self.alerts.append(alert)
        for channel in self.channels:
            try:
                channel.send(alert)
            except Exception as exc:  # never let one channel break the rest
                print(f"[C-UAS ALERT] channel error: {exc}")
        for hook in self._dispatch_hooks:
            try:
                hook(alert)
            except Exception as exc:
                print(f"[C-UAS ALERT] dispatch hook error: {exc}")
        return alert

    def process_event(self, event: DetectionEvent) -> List[Alert]:
        """Evaluate a detection event against rules; emit alerts for matches.

        Critical events (CRITICAL threat level or spoof detection) always
        raise an alert even without an explicit rule match.
        """
        emitted: List[Alert] = []
        matched = self.should_alert(event)

        # Always alert on CRITICAL threat level or spoof detection.
        always = (event.threat_level or "NONE").upper() == "CRITICAL" or "spoof" in (
            event.source or ""
        ).lower()
        if not matched and not always:
            return emitted

        level = (event.threat_level or "NONE").upper()
        sev = "CRITICAL" if level == "CRITICAL" else "HIGH" if level == "HIGH" else "MEDIUM"
        etype = event.source or "detection"
        protocol = event.protocol or "-"
        msg = "{} detected {} ({}; protocol={})".format(
            event.source, event.target_id, level, protocol
        )
        if event.anomalies:
            msg += "; anomalies=" + ",".join(event.anomalies)

        alert = self.emit(
            severity=sev,
            event_type=etype,
            message=msg,
            source=event.source,
            target_id=event.target_id,
            metadata={
                "threat_level": level,
                "protocol": event.protocol,
                "anomalies": list(event.anomalies),
            },
        )
        emitted.append(alert)
        return emitted
