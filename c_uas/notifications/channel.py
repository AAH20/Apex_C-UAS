"""
Notification channel dataclasses: channel, message, delivery result, config.

All types are frozen dataclasses so they are immutable and hashable-safe, which
makes routing and dedupe decisions deterministic. Channel types: email, webhook,
slack.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

CHANNEL_EMAIL = "email"
CHANNEL_WEBHOOK = "webhook"
CHANNEL_SLACK = "slack"

CHANNEL_TYPES = (CHANNEL_EMAIL, CHANNEL_WEBHOOK, CHANNEL_SLACK)


@dataclass(frozen=True)
class EmailConfig:
    """SMTP configuration for the email channel."""

    smtp_host: str
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    from_email: str = ""
    to_emails: Tuple[str, ...] = ()
    use_tls: bool = True


@dataclass(frozen=True)
class WebhookConfig:
    """HTTP webhook delivery configuration."""

    url: str
    method: str = "POST"
    headers: Tuple[Tuple[str, str], ...] = ()
    timeout_s: float = 10.0
    max_retries: int = 3
    backoff_s: float = 1.0


@dataclass(frozen=True)
class SlackConfig:
    """Slack incoming webhook configuration."""

    webhook_url: str
    channel: str = ""
    username: str = "c-uas"
    icon_emoji: str = ":warning:"


@dataclass(frozen=True)
class ChannelConfig:
    """Aggregate per-channel configuration (one entry per channel type)."""

    email: Optional[EmailConfig] = None
    webhook: Optional[WebhookConfig] = None
    slack: Optional[SlackConfig] = None


@dataclass(frozen=True)
class NotificationChannel:
    """A single notification delivery destination of a given type."""

    channel_id: str
    channel_type: str
    enabled: bool = True
    email_config: Optional[EmailConfig] = None
    webhook_config: Optional[WebhookConfig] = None
    slack_config: Optional[SlackConfig] = None


@dataclass(frozen=True)
class NotificationMessage:
    """A deterministic notification message derived from an alert."""

    message_id: str
    alert_id: str
    severity: str
    title: str
    body: str
    channels: Tuple[str, ...] = ()
    created_at: str = ""


@dataclass(frozen=True)
class DeliveryResult:
    """Result of delivering a message to one channel."""

    channel_id: str
    channel_type: str
    delivered: bool
    message_id: str
    error: Optional[str] = None
    attempt: int = 1
