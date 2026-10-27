"""Webhook notification channel: HTTP POST with JSON payload, retries, verification.

The webhook payload is built deterministically from the alert fields. Delivery
performs an HTTP POST (via stdlib :mod:`urllib.request`) and verifies success on
a 2xx status code. Failed deliveries are retried with exponential backoff; the
sleep function is injectable so tests stay fast and deterministic.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from .channel import (
    CHANNEL_WEBHOOK,
    DeliveryResult,
    NotificationChannel,
    NotificationMessage,
    WebhookConfig,
)

WEBHOOK_DIR = Path(
    os.environ.get(
        "C_UAS_WEBHOOK_DIR",
        str(Path.home() / ".c-uas-platform" / "notifications" / "webhook"),
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


def build_webhook_payload(message: NotificationMessage, config: WebhookConfig) -> Dict[str, Any]:
    """Deterministically build the JSON webhook payload."""
    return {
        "message_id": message.message_id,
        "alert_id": message.alert_id,
        "severity": message.severity,
        "title": message.title,
        "body": message.body,
        "channels": list(message.channels),
        "created_at": message.created_at,
    }


def _persist_webhook(message: NotificationMessage, payload: Dict[str, Any]) -> Path:
    """Write a deterministic copy of the dispatched payload to disk."""
    WEBHOOK_DIR.mkdir(parents=True, exist_ok=True)
    safe = hashlib.sha256(message.message_id.encode("utf-8")).hexdigest()[:16]
    path = WEBHOOK_DIR / ("%s.json" % safe)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return path


def send_webhook(
    message: NotificationMessage,
    config: WebhookConfig,
    channel_id: str,
    http_post: Optional[HttpPost] = None,
    sleep: Callable[[float], None] = time.sleep,
    max_retries: Optional[int] = None,
    backoff_s: Optional[float] = None,
    timeout_s: Optional[float] = None,
) -> DeliveryResult:
    """POST ``message`` to the webhook URL with retry and delivery verification.

    Returns a :class:`DeliveryResult`. Delivery is verified as a 2xx status
    code; anything else is retried up to the configured max attempts.
    """
    post = http_post or _default_http_post
    attempt = 0
    max_attempts = (config.max_retries + 1) if max_retries is None else (max_retries + 1)
    backoff = config.backoff_s if backoff_s is None else backoff_s
    timeout = config.timeout_s if timeout_s is None else timeout_s
    headers = config.headers
    last_error: Optional[str] = None

    while attempt < max_attempts:
        attempt += 1
        try:
            status_code, body, _headers = post(
                config.url,
                build_webhook_payload(message, config),
                timeout,
                headers,
            )
            if 200 <= status_code < 300:
                _persist_webhook(message, build_webhook_payload(message, config))
                return DeliveryResult(
                    channel_id=channel_id,
                    channel_type=CHANNEL_WEBHOOK,
                    delivered=True,
                    message_id=message.message_id,
                    attempt=attempt,
                )
            last_error = "HTTP %s: %s" % (status_code, body[:200])
        except Exception as exc:  # noqa: BLE001 - transport errors are reported, not raised
            last_error = "%s: %s" % (type(exc).__name__, exc)
        if attempt < max_attempts:
            sleep(backoff * attempt)

    return DeliveryResult(
        channel_id=channel_id,
        channel_type=CHANNEL_WEBHOOK,
        delivered=False,
        message_id=message.message_id,
        error=last_error or "delivery failed",
        attempt=attempt,
    )


def make_channel(
    channel_id: str,
    config: WebhookConfig,
    enabled: bool = True,
) -> NotificationChannel:
    """Build an :class:`NotificationChannel` of type ``webhook``."""
    return NotificationChannel(
        channel_id=channel_id,
        channel_type=CHANNEL_WEBHOOK,
        enabled=enabled,
        webhook_config=config,
    )
