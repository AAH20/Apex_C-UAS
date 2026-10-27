"""Notification delivery channels for observability alerts.

Delivers fired alerts via email (SMTP), HTTP webhook, and Slack (incoming
webhook with Block Kit). All message construction is deterministic: the same
alert always produces the same message content and the same delivery decisions.

State persists under ~/.c-uas-platform/notifications/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from .channel import (
    CHANNEL_EMAIL,
    CHANNEL_SLACK,
    CHANNEL_WEBHOOK,
    ChannelConfig,
    DeliveryResult,
    EmailConfig,
    NotificationChannel,
    NotificationMessage,
    SlackConfig,
    WebhookConfig,
)
from .router import NotificationRouter, RouterConfig, RouteRule

__all__ = [
    "CHANNEL_EMAIL",
    "CHANNEL_SLACK",
    "CHANNEL_WEBHOOK",
    "ChannelConfig",
    "DeliveryResult",
    "EmailConfig",
    "NotificationChannel",
    "NotificationMessage",
    "NotificationRouter",
    "RouterConfig",
    "RouteRule",
    "SlackConfig",
    "WebhookConfig",
]
