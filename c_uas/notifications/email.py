"""Email notification channel: deterministic message construction + SMTP/TLS delivery.

The email body is built from the alert fields only, so the same alert always
renders the same message. Delivery uses smtplib with optional STARTTLS; a
caller-supplied SMTP factory makes the channel testable without a real server.

State (sent message copies) is persisted under
~/.c-uas-platform/notifications/email/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import hashlib
import os
import smtplib
from pathlib import Path
from typing import Any, Callable, Optional

from .channel import (
    CHANNEL_EMAIL,
    DeliveryResult,
    EmailConfig,
    NotificationChannel,
    NotificationMessage,
)

EMAIL_DIR = Path(
    os.environ.get(
        "C_UAS_EMAIL_DIR",
        str(Path.home() / ".c-uas-platform" / "notifications" / "email"),
    )
)

SMTPFactory = Callable[[str, int], Any]


def _default_smtp_factory(host: str, port: int) -> Any:
    return smtplib.SMTP(host, port)


def build_email_message(message: NotificationMessage, config: EmailConfig) -> str:
    """Deterministically render the full RFC-5322-style email message."""
    lines: list = []
    lines.append("From: %s" % config.from_email)
    lines.append("To: %s" % ", ".join(config.to_emails))
    lines.append("Subject: [c-uas] %s (%s)" % (message.title, message.severity.upper()))
    lines.append("Message-Id: <%s@c-uas-platform>" % message.message_id)
    lines.append("Date: %s" % message.created_at)
    lines.append("MIME-Version: 1.0")
    lines.append("Content-Type: text/plain; charset=utf-8")
    lines.append("Content-Transfer-Encoding: 7bit")
    lines.append("X-C-UAS-Alert-Id: %s" % message.alert_id)
    lines.append("X-C-UAS-Severity: %s" % message.severity.upper())
    lines.append("")
    lines.append(message.body)
    return "\r\n".join(lines)


def persist_email_copy(message: NotificationMessage, config: EmailConfig) -> Path:
    """Write a deterministic copy of the composed message to disk."""
    EMAIL_DIR.mkdir(parents=True, exist_ok=True)
    safe = hashlib.sha256(message.message_id.encode("utf-8")).hexdigest()[:16]
    path = EMAIL_DIR / ("%s.eml" % safe)
    payload = build_email_message(message, config)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload)
    return path


def send_email(
    message: NotificationMessage,
    config: EmailConfig,
    channel_id: str,
    smtp_factory: Optional[SMTPFactory] = None,
) -> DeliveryResult:
    """Deliver ``message`` to ``config`` via SMTP with optional STARTTLS.

    Returns a :class:`DeliveryResult`. Any delivery exception is captured and
    reported as ``delivered=False`` with the error text, so delivery never
    raises to the caller.
    """
    factory = smtp_factory or _default_smtp_factory
    attempt = 1
    smtp: Any = None
    try:
        smtp = factory(config.smtp_host, config.smtp_port)
        try:
            if config.use_tls:
                smtp.starttls()  # type: ignore[attr-defined]
            if config.username:
                smtp.login(config.username, config.password)  # type: ignore[attr-defined]
            payload = build_email_message(message, config)
            smtp.sendmail(  # type: ignore[attr-defined]
                config.from_email, list(config.to_emails), payload
            )
            smtp.quit()  # type: ignore[attr-defined]
        except Exception:
            try:
                smtp.quit()  # type: ignore[attr-defined]
            except Exception:
                pass
            raise
        persist_email_copy(message, config)
        return DeliveryResult(
            channel_id=channel_id,
            channel_type=CHANNEL_EMAIL,
            delivered=True,
            message_id=message.message_id,
            attempt=attempt,
        )
    except Exception as exc:  # noqa: BLE001 - delivery failures are reported, not raised
        return DeliveryResult(
            channel_id=channel_id,
            channel_type=CHANNEL_EMAIL,
            delivered=False,
            message_id=message.message_id,
            error="%s: %s" % (type(exc).__name__, exc),
            attempt=attempt,
        )


def make_channel(
    channel_id: str,
    config: EmailConfig,
    enabled: bool = True,
) -> NotificationChannel:
    """Build an :class:`NotificationChannel` of type ``email``."""
    return NotificationChannel(
        channel_id=channel_id,
        channel_type=CHANNEL_EMAIL,
        enabled=enabled,
        email_config=config,
    )
