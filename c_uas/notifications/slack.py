"""Slack notification channel: webhook-based delivery with Block Kit formatting.

Builds a Slack Block Kit payload deterministically from the alert fields and
delivers it to a Slack incoming webhook URL. Delivery is verified on a 2xx
response and an ``ok`` body.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from .channel import (
    CHANNEL_SLACK,
    DeliveryResult,
    NotificationChannel,
    NotificationMessage,
    SlackConfig,
)

SLACK_DIR = Path(
    os.environ.get(
        "C_UAS_SLACK_DIR",
        str(Path.home() / ".c-uas-platform" / "notifications" / "slack"),
    )
)

HttpPost = Callable[
    [str, Dict[str, Any], float, Tuple[Tuple[str, str], ...]], Tuple[int, str, Dict[str, str]]
]


def _default_http_post(
    url: str,
    payload: Dict[str, Any],
    timeout_s: float,
    headers: Tuple[Tuple[str, str], ...],
) -> Tuple[int, str, Dict[str, str]]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers=dict(headers),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            body = response.read().decode("utf-8")
            return response.status, body, dict(response.headers)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8") if exc.fp is not None else ""
        return exc.code, body, dict(exc.headers)


def build_slack_payload(message: NotificationMessage, config: SlackConfig) -> Dict[str, Any]:
    """Deterministically build a Slack Block Kit payload."""
    blocks: list = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "[c-uas] %s" % message.title,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Severity:* %s" % message.severity.upper(),
                },
                {
                    "type": "mrkdwn",
                    "text": "*Alert ID:* %s" % message.alert_id,
                },
            ],
        },
    ]
    if message.body:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message.body,
                },
            }
        )
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "C-UAS Platform • %s" % message.created_at,
                },
            ],
        }
    )
    return {
        "channel": config.channel,
        "username": config.username,
        "icon_emoji": config.icon_emoji,
        "blocks": blocks,
        "text": "%s: %s" % (message.title, message.body),
    }


def _persist_slack(message: NotificationMessage, payload: Dict[str, Any]) -> Path:
    """Write a deterministic copy of the dispatched payload to disk."""
    SLACK_DIR.mkdir(parents=True, exist_ok=True)
    safe = hashlib.sha256(message.message_id.encode("utf-8")).hexdigest()[:16]
    path = SLACK_DIR / ("%s.json" % safe)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return path


def send_slack(
    message: NotificationMessage,
    config: SlackConfig,
    channel_id: str,
    http_post: Optional[HttpPost] = None,
    timeout_s: Optional[float] = None,
) -> DeliveryResult:
    """POST a Block Kit payload to the Slack webhook and verify delivery.

    Delivery is verified as a 2xx status code with a truthy ``ok`` field in the
    JSON body (Slack's webhook convention). Returns a :class:`DeliveryResult`.
    """
    post = http_post or _default_http_post
    timeout = 10.0
    if timeout_s is not None:
        timeout = timeout_s
    attempt = 1
    try:
        status_code, body, _headers = post(
            config.webhook_url,
            build_slack_payload(message, config),
            timeout,
            (("Content-Type", "application/json"),),
        )
        ok = False
        try:
            ok = bool(json.loads(body).get("ok")) if body else False
        except (ValueError, TypeError):
            ok = False
        delivered = 200 <= status_code < 300 and ok
        if delivered:
            _persist_slack(message, build_slack_payload(message, config))
        return DeliveryResult(
            channel_id=channel_id,
            channel_type=CHANNEL_SLACK,
            delivered=delivered,
            message_id=message.message_id,
            error=None if delivered else "HTTP %s: %s" % (status_code, body[:200]),
            attempt=attempt,
        )
    except Exception as exc:  # noqa: BLE001 - transport errors are reported, not raised
        return DeliveryResult(
            channel_id=channel_id,
            channel_type=CHANNEL_SLACK,
            delivered=False,
            message_id=message.message_id,
            error="%s: %s" % (type(exc).__name__, exc),
            attempt=attempt,
        )


def make_channel(
    channel_id: str,
    config: SlackConfig,
    enabled: bool = True,
) -> NotificationChannel:
    """Build an :class:`NotificationChannel` of type ``slack``."""
    return NotificationChannel(
        channel_id=channel_id,
        channel_type=CHANNEL_SLACK,
        enabled=enabled,
        slack_config=config,
    )
