"""``c-uas notify`` subcommand: alert notification delivery.

Usage:
    c-uas notify --channels
    c-uas notify --test
    c-uas notify --send

All output is deterministic. State persists under
~/.c-uas-platform/notifications/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, List, Optional, Sequence

from .channel import (
    CHANNEL_EMAIL,
    CHANNEL_SLACK,
    CHANNEL_WEBHOOK,
    EmailConfig,
    NotificationChannel,
    SlackConfig,
    WebhookConfig,
)
from .router import NotificationRouter, RouterConfig, RouteRule


def _default_channels() -> List[NotificationChannel]:
    """Example channels used when no persisted channel config exists.

    These are intentionally safe defaults: the SMTP host and webhook URLs are
    placeholders so --test / --send run deterministically (delivery will report
    connection errors rather than hitting the network).
    """
    return [
        NotificationChannel(
            channel_id="smtp-alerts",
            channel_type=CHANNEL_EMAIL,
            enabled=True,
            email_config=EmailConfig(
                smtp_host="smtp.example.invalid",
                smtp_port=587,
                username="",
                password="",
                from_email="alerts@c-uas-platform.example",
                to_emails=("soc@example.example",),
                use_tls=True,
            ),
        ),
        NotificationChannel(
            channel_id="webhook-alerts",
            channel_type=CHANNEL_WEBHOOK,
            enabled=True,
            webhook_config=WebhookConfig(
                url="http://127.0.0.1:9/discard/invalid",
                method="POST",
                headers=(("Content-Type", "application/json"),),
                timeout_s=3.0,
                max_retries=1,
                backoff_s=0.1,
            ),
        ),
        NotificationChannel(
            channel_id="slack-alerts",
            channel_type=CHANNEL_SLACK,
            enabled=True,
            slack_config=SlackConfig(
                webhook_url="http://127.0.0.1:9/slack/invalid",
                channel="#alerts",
                username="c-uas",
                icon_emoji=":warning:",
            ),
        ),
    ]


def _load_channels(state_dir) -> List[NotificationChannel]:
    """Load channels from a persisted channels.json, else return defaults."""
    import json
    from pathlib import Path

    path = Path(state_dir) / "channels.json"
    if not path.exists():
        return _default_channels()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (ValueError, OSError):
        return _default_channels()
    channels: List[NotificationChannel] = []
    for entry in data.get("channels", []):
        ctype = entry.get("type", "")
        cid = entry.get("channel_id", "")
        enabled = bool(entry.get("enabled", True))
        if ctype == CHANNEL_EMAIL:
            channels.append(
                NotificationChannel(
                    channel_id=cid,
                    channel_type=CHANNEL_EMAIL,
                    enabled=enabled,
                    email_config=EmailConfig(
                        smtp_host=entry.get("smtp_host", ""),
                        smtp_port=int(entry.get("smtp_port", 587)),
                        username=entry.get("username", ""),
                        password=entry.get("password", ""),
                        from_email=entry.get("from_email", ""),
                        to_emails=tuple(entry.get("to_emails", [])),
                        use_tls=bool(entry.get("use_tls", True)),
                    ),
                )
            )
        elif ctype == CHANNEL_WEBHOOK:
            channels.append(
                NotificationChannel(
                    channel_id=cid,
                    channel_type=CHANNEL_WEBHOOK,
                    enabled=enabled,
                    webhook_config=WebhookConfig(
                        url=entry.get("url", ""),
                        method=entry.get("method", "POST"),
                        timeout_s=float(entry.get("timeout_s", 10.0)),
                        max_retries=int(entry.get("max_retries", 3)),
                        backoff_s=float(entry.get("backoff_s", 1.0)),
                    ),
                )
            )
        elif ctype == CHANNEL_SLACK:
            channels.append(
                NotificationChannel(
                    channel_id=cid,
                    channel_type=CHANNEL_SLACK,
                    enabled=enabled,
                    slack_config=SlackConfig(
                        webhook_url=entry.get("webhook_url", ""),
                        channel=entry.get("channel", ""),
                        username=entry.get("username", "c-uas"),
                        icon_emoji=entry.get("icon_emoji", ":warning:"),
                    ),
                )
            )
    return channels or _default_channels()


def build_subparser(subparsers: Any) -> Any:
    """Register the ``notify`` subcommand on a parent parser."""
    parser = subparsers.add_parser(
        "notify",
        help="Alert notification delivery: email, webhook, Slack",
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="Evaluate observability alerts and deliver firing ones to routed channels",
    )
    parser.add_argument(
        "--channels",
        action="store_true",
        help="List configured notification channels and their types",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Send a deterministic test notification to each configured channel",
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default=None,
        help="Notification state directory (default: ~/.c-uas-platform/notifications)",
    )
    return parser


def _render_channels(channels: List[NotificationChannel]) -> str:
    lines: List[str] = ["[C-UAS] Notification Channels", "=" * 44]
    for channel in sorted(channels, key=lambda c: c.channel_id):
        lines.append("Channel : %s" % channel.channel_id)
        lines.append("Type    : %s" % channel.channel_type)
        lines.append("Enabled : %s" % channel.enabled)
        if channel.channel_type == "email" and channel.email_config is not None:
            email_cfg = channel.email_config
            lines.append(
                "SMTP    : %s:%s (tls=%s)"
                % (email_cfg.smtp_host, email_cfg.smtp_port, email_cfg.use_tls)
            )
            lines.append("From    : %s" % email_cfg.from_email)
            lines.append("To      : %s" % ", ".join(email_cfg.to_emails))
        elif channel.channel_type == "webhook" and channel.webhook_config is not None:
            webhook_cfg = channel.webhook_config
            lines.append("URL     : %s" % webhook_cfg.url)
            lines.append("Retries : %s" % webhook_cfg.max_retries)
        elif channel.channel_type == "slack" and channel.slack_config is not None:
            slack_cfg = channel.slack_config
            lines.append("URL     : %s" % slack_cfg.webhook_url)
            lines.append("Channel : %s" % slack_cfg.channel)
        lines.append("-")
    return "\n".join(lines)


def notify_main(args: argparse.Namespace) -> int:
    """Handle the ``notify`` subcommand from a parsed namespace."""
    state_dir = args.state_dir
    channels = _load_channels(state_dir) if state_dir else _default_channels()
    config = RouterConfig(
        routes=(
            RouteRule(
                severity="emergency",
                channel_ids=("smtp-alerts", "webhook-alerts", "slack-alerts"),
            ),
            RouteRule(
                severity="critical",
                channel_ids=("smtp-alerts", "webhook-alerts", "slack-alerts"),
            ),
            RouteRule(
                severity="warning",
                channel_ids=("smtp-alerts", "webhook-alerts", "slack-alerts"),
            ),
            RouteRule(severity="info", channel_ids=("slack-alerts",)),
        ),
        default_channels=("smtp-alerts", "webhook-alerts", "slack-alerts"),
    )
    router = NotificationRouter(channels=channels, config=config, state_dir=state_dir)

    if args.channels:
        print(_render_channels(channels))
        return 0

    if args.test:
        from .channel import NotificationMessage

        test_message = NotificationMessage(
            message_id="test-0000000000000000",
            alert_id="test-alert",
            severity="warning",
            title="c-uas notification test",
            body="This is a deterministic test notification from the notify subcommand.",
            channels=tuple(c.channel_id for c in channels),
            created_at="1970-01-01T00:00:00Z",
        )
        results: List = []
        for channel in channels:
            result = router._send_one(test_message, channel)  # type: ignore[attr-defined]
            results.append(result)
        print("[C-UAS] Notification Test")
        print("=" * 44)
        for r in results:
            status = "OK " if r.delivered else "FAIL"
            print(
                "  [%s] %s (%s): %s"
                % (status, r.channel_id, r.channel_type, r.error or "delivered")
            )
        return 0

    if args.send:
        # Integrate with the observability alerting engine: evaluate firing
        # alerts and deliver each to its routed channels.
        from c_uas.observability.alerts import (
            AlertSeverity,
            ThresholdRule,
            new_engine,
        )
        from c_uas.observability.metrics import MetricType, new_registry

        registry = new_registry()
        engine = new_engine(registry)

        # Register a representative threshold rule so the engine has something
        # to evaluate against a sample metric.
        engine.add_threshold_rule(
            ThresholdRule(
                rule_id="sample-high-latency",
                name="High detection latency",
                metric="detection_latency_ms",
                threshold=100.0,
                severity=AlertSeverity.CRITICAL,
                comparison="gt",
            )
        )
        registry.register("detection_latency_ms", MetricType.GAUGE)
        gauge = registry.gauge("detection_latency_ms")
        gauge.set(250.0)

        changed = engine.evaluate(now_iso="2026-10-27T00:00:00Z")
        firing = engine.firing_alerts()
        print("[C-UAS] Alert Notification Dispatch")
        print("=" * 44)
        print("Firing alerts : %s" % len(firing))
        total_delivered = 0
        for alert in changed:
            results = router.deliver_alert(alert)
            delivered = sum(1 for r in results if r.delivered)
            total_delivered += delivered
            print(
                "  Alert %s (%s): %s/%s delivered"
                % (alert.alert_id, alert.severity, delivered, len(results))
            )
        print("Total delivered : %s" % total_delivered)
        return 0

    print("[C-UAS] notify: specify --send, --channels, or --test")
    print("  c-uas notify --channels")
    print("  c-uas notify --test")
    print("  c-uas notify --send")
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Standalone entry point: ``python -m c_uas.notifications.cli``."""
    parser = argparse.ArgumentParser(prog="c-uas notify")
    build_subparser(parser.add_subparsers(dest="command"))
    args = parser.parse_args(argv)
    return notify_main(args)


if __name__ == "__main__":
    sys.exit(main())
