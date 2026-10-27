"""Notification router: match alerts to channels, dedupe, rate-limit.

Given a set of :class:`NotificationChannel` objects and a :class:`RouterConfig`,
the router:

* matches alerts to channels by severity via :class:`RouteRule` entries,
* deduplicates repeat deliveries of the same alert to the same channel within
  a time window,
* rate-limits the number of deliveries per channel within a time window.

All decisions are deterministic given the same alert, channel set, config, and
clock. State (delivery times + dedupe ledger) is persisted under
~/.c-uas-platform/notifications/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import email as email_channel
from . import slack as slack_channel
from . import webhook as webhook_channel
from .channel import (
    CHANNEL_EMAIL,
    CHANNEL_SLACK,
    CHANNEL_WEBHOOK,
    DeliveryResult,
    NotificationChannel,
    NotificationMessage,
)

NOTIFICATIONS_DIR = Path(
    os.environ.get(
        "C_UAS_NOTIFICATIONS_DIR",
        str(Path.home() / ".c-uas-platform" / "notifications"),
    )
)


@dataclass(frozen=True)
class RouteRule:
    """Map a severity level to the channel IDs that should receive it."""

    severity: str
    channel_ids: Tuple[str, ...]


@dataclass(frozen=True)
class RouterConfig:
    """Router configuration: routes, defaults, rate-limit and dedupe windows."""

    routes: Tuple[RouteRule, ...] = ()
    default_channels: Tuple[str, ...] = ()
    rate_limit_per_window: int = 10
    rate_window_s: float = 60.0
    dedupe_window_s: float = 300.0


class NotificationRouter:
    """Route and deliver alert notifications to channels."""

    def __init__(
        self,
        channels: List[NotificationChannel],
        config: Optional[RouterConfig] = None,
        state_dir: Optional[str] = None,
        now: Optional[Callable[[], float]] = None,
    ) -> None:
        self.channels: Dict[str, NotificationChannel] = {c.channel_id: c for c in channels}
        self.config = config or RouterConfig()
        self.state_dir = Path(state_dir) if state_dir is not None else NOTIFICATIONS_DIR
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._now = now or time.time
        # channel_id -> delivery timestamps
        self._delivery_times: Dict[str, List[float]] = {}
        # (alert_id, channel_id) -> last delivery timestamp
        self._delivered: Dict[Tuple[str, str], float] = {}
        self._load()
        self._persist()

    # ------------------------------------------------------------------ #
    # persistence
    # ------------------------------------------------------------------ #
    def _state_path(self) -> Path:
        return self.state_dir / "router_state.json"

    def _load(self) -> None:
        path = self._state_path()
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (ValueError, OSError):
            return
        self._delivery_times = {
            str(k): [float(t) for t in v] for k, v in (data.get("delivery_times") or {}).items()
        }
        self._delivered = {}
        for raw_key, ts in (data.get("delivered") or {}).items():
            try:
                alert_id, channel_id = raw_key.split("|", 1)
                self._delivered[(alert_id, channel_id)] = float(ts)
            except (ValueError, AttributeError):
                continue

    def _persist(self) -> None:
        path = self._state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: Dict[str, Any] = {
            "delivery_times": {k: sorted(v) for k, v in self._delivery_times.items()},
            "delivered": {
                "%s|%s" % (alert_id, channel_id): ts
                for (alert_id, channel_id), ts in sorted(self._delivered.items())
            },
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)

    # ------------------------------------------------------------------ #
    # routing
    # ------------------------------------------------------------------ #
    def route_channels(self, severity: str) -> Tuple[str, ...]:
        """Return channel IDs matched to ``severity``, or the defaults."""
        for rule in self.config.routes:
            if rule.severity == severity:
                return rule.channel_ids
        return self.config.default_channels

    def build_message(self, alert: Any, channel_ids: Tuple[str, ...]) -> NotificationMessage:
        """Build a deterministic :class:`NotificationMessage` from an alert.

        The message id is a hash of alert_id + severity; created_at is taken from
        the alert's fired_at so the same alert always renders identically.
        """
        message_id = hashlib.sha256(
            ("%s|%s" % (getattr(alert, "alert_id", ""), getattr(alert, "severity", "info"))).encode(
                "utf-8"
            )
        ).hexdigest()[:16]
        title = "[c-uas] %s" % getattr(alert, "name", "alert")
        body = "%s metric '%s' = %s (threshold %s)\n%s" % (
            getattr(alert, "severity", "info").upper(),
            getattr(alert, "metric", ""),
            getattr(alert, "value", 0.0),
            getattr(alert, "threshold", 0.0),
            getattr(alert, "message", ""),
        )
        return NotificationMessage(
            message_id=message_id,
            alert_id=getattr(alert, "alert_id", ""),
            severity=getattr(alert, "severity", "info"),
            title=title,
            body=body,
            channels=tuple(channel_ids),
            created_at=getattr(alert, "fired_at", "") or "",
        )

    # ------------------------------------------------------------------ #
    # rate limit / dedupe
    # ------------------------------------------------------------------ #
    def _rate_limited(self, channel_id: str) -> bool:
        now = self._now()
        window_start = now - self.config.rate_window_s
        times = [t for t in self._delivery_times.get(channel_id, []) if t > window_start]
        self._delivery_times[channel_id] = times
        return len(times) >= self.config.rate_limit_per_window

    def _deduped(self, alert_id: str, channel_id: str) -> bool:
        now = self._now()
        window_start = now - self.config.dedupe_window_s
        key = (alert_id, channel_id)
        last = self._delivered.get(key)
        if last is not None and last > window_start:
            return True
        return False

    # ------------------------------------------------------------------ #
    # delivery
    # ------------------------------------------------------------------ #
    def _send_one(
        self,
        message: NotificationMessage,
        channel: NotificationChannel,
    ) -> DeliveryResult:
        ctype = channel.channel_type
        if ctype == CHANNEL_EMAIL:
            email_config = channel.email_config
            if email_config is None:
                return DeliveryResult(
                    channel_id=channel.channel_id,
                    channel_type=ctype,
                    delivered=False,
                    message_id=message.message_id,
                    error="email channel has no config",
                )
            return email_channel.send_email(message, email_config, channel.channel_id)
        if ctype == CHANNEL_WEBHOOK:
            webhook_config = channel.webhook_config
            if webhook_config is None:
                return DeliveryResult(
                    channel_id=channel.channel_id,
                    channel_type=ctype,
                    delivered=False,
                    message_id=message.message_id,
                    error="webhook channel has no config",
                )
            return webhook_channel.send_webhook(message, webhook_config, channel.channel_id)
        if ctype == CHANNEL_SLACK:
            slack_config = channel.slack_config
            if slack_config is None:
                return DeliveryResult(
                    channel_id=channel.channel_id,
                    channel_type=ctype,
                    delivered=False,
                    message_id=message.message_id,
                    error="slack channel has no config",
                )
            return slack_channel.send_slack(message, slack_config, channel.channel_id)
        return DeliveryResult(
            channel_id=channel.channel_id,
            channel_type=ctype,
            delivered=False,
            message_id=message.message_id,
            error="unknown channel type: %s" % ctype,
        )

    def deliver(
        self,
        alert: Any,
        channel_ids: Optional[Tuple[str, ...]] = None,
    ) -> List[DeliveryResult]:
        """Route ``alert`` to channels and deliver, applying dedupe + rate-limit."""
        if channel_ids is None:
            channel_ids = self.route_channels(getattr(alert, "severity", "info"))
        message = self.build_message(alert, channel_ids)
        results: List[DeliveryResult] = []
        for channel_id in channel_ids:
            channel = self.channels.get(channel_id)
            if channel is None:
                results.append(
                    DeliveryResult(
                        channel_id=channel_id,
                        channel_type="unknown",
                        delivered=False,
                        message_id=message.message_id,
                        error="channel not found",
                    )
                )
                continue
            if not channel.enabled:
                results.append(
                    DeliveryResult(
                        channel_id=channel.channel_id,
                        channel_type=channel.channel_type,
                        delivered=False,
                        message_id=message.message_id,
                        error="channel disabled",
                    )
                )
                continue
            if self._rate_limited(channel.channel_id):
                results.append(
                    DeliveryResult(
                        channel_id=channel.channel_id,
                        channel_type=channel.channel_type,
                        delivered=False,
                        message_id=message.message_id,
                        error="rate limited",
                    )
                )
                continue
            if self._deduped(alert.alert_id, channel.channel_id):
                results.append(
                    DeliveryResult(
                        channel_id=channel.channel_id,
                        channel_type=channel.channel_type,
                        delivered=False,
                        message_id=message.message_id,
                        error="deduplicated",
                    )
                )
                continue
            result = self._send_one(message, channel)
            self._delivery_times.setdefault(channel.channel_id, []).append(self._now())
            if result.delivered:
                self._delivered[(alert.alert_id, channel.channel_id)] = self._now()
            results.append(result)
        self._persist()
        return results

    def deliver_alert(self, alert: Any) -> List[DeliveryResult]:
        """Convenience alias for :meth:`deliver`."""
        return self.deliver(alert)
