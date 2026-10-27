"""Deterministic notification channel tests.

Covers channel dataclasses, message formatting, email/webhook/slack delivery,
routing, dedupe, and rate-limiting. All values computed from real execution —
no mocks, no network. Transports are replaced with deterministic fakes.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from typing import Any, Dict, List, Tuple

from c_uas.notifications.channel import (
    CHANNEL_EMAIL,
    CHANNEL_SLACK,
    CHANNEL_TYPES,
    CHANNEL_WEBHOOK,
    DeliveryResult,
    EmailConfig,
    NotificationChannel,
    NotificationMessage,
    SlackConfig,
    WebhookConfig,
)
from c_uas.notifications.email import build_email_message, send_email
from c_uas.notifications.router import (
    NotificationRouter,
    RouterConfig,
    RouteRule,
)
from c_uas.notifications.slack import build_slack_payload, send_slack
from c_uas.notifications.webhook import build_webhook_payload, send_webhook
from c_uas.observability.alerts import Alert, AlertSeverity

EMAIL_CONFIG = EmailConfig(
    smtp_host="smtp.example.invalid",
    smtp_port=587,
    username="user",
    password="pass",
    from_email="alerts@example.example",
    to_emails=("soc@example.example",),
    use_tls=True,
)

WEBHOOK_CONFIG = WebhookConfig(
    url="http://127.0.0.1:9/hooks/alert",
    method="POST",
    headers=(("Content-Type", "application/json"),),
    timeout_s=5.0,
    max_retries=2,
    backoff_s=0.1,
)

SLACK_CONFIG = SlackConfig(
    webhook_url="https://hooks.slack.com/services/T00000000/B00000000/XXXX",
    channel="#alerts",
    username="c-uas",
    icon_emoji=":warning:",
)


def _alert(
    alert_id: str = "alert-001",
    severity: str = AlertSeverity.CRITICAL,
    fired_at: str = "2026-10-27T00:00:00Z",
) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="rule-latency",
        name="High detection latency",
        metric="detection_latency_ms",
        severity=severity,
        state="firing",
        value=250.0,
        threshold=100.0,
        labels=(("site", "alpha"),),
        fired_at=fired_at,
        resolved_at=None,
        message="Metric 'detection_latency_ms' > 100.0 (current 250.000000) — critical",
    )


def _make_message() -> NotificationMessage:
    return NotificationMessage(
        message_id="msg-deterministic",
        alert_id="alert-001",
        severity="critical",
        title="High detection latency",
        body="Metric 'detection_latency_ms' > 100.0 (current 250.0)",
        channels=("smtp-alerts", "webhook-alerts", "slack-alerts"),
        created_at="2026-10-27T00:00:00Z",
    )


class Clock:
    """Injectable, manually-advanced clock for deterministic router tests."""

    def __init__(self, start: float) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


# --------------------------------------------------------------------------- #
# Dataclasses / channel types
# --------------------------------------------------------------------------- #


def test_channel_types_constants() -> None:
    assert CHANNEL_TYPES == (CHANNEL_EMAIL, CHANNEL_WEBHOOK, CHANNEL_SLACK)
    assert CHANNEL_EMAIL == "email"
    assert CHANNEL_WEBHOOK == "webhook"
    assert CHANNEL_SLACK == "slack"


def test_channel_dataclasses_are_frozen() -> None:
    channel = NotificationChannel(
        channel_id="c1",
        channel_type=CHANNEL_EMAIL,
        enabled=True,
        email_config=EMAIL_CONFIG,
    )
    try:
        channel.channel_id = "c2"  # type: ignore[attr-defined]
    except Exception:
        pass
    else:
        raise AssertionError("frozen dataclass should reject field assignment")


def test_notification_message_equality_deterministic() -> None:
    a = NotificationMessage(
        message_id="m1",
        alert_id="a1",
        severity="critical",
        title="t",
        body="b",
        channels=("c1", "c2"),
        created_at="2026-10-27T00:00:00Z",
    )
    b = NotificationMessage(
        message_id="m1",
        alert_id="a1",
        severity="critical",
        title="t",
        body="b",
        channels=("c1", "c2"),
        created_at="2026-10-27T00:00:00Z",
    )
    assert a == b


def test_delivery_result_defaults() -> None:
    result = DeliveryResult(
        channel_id="c1",
        channel_type=CHANNEL_EMAIL,
        delivered=True,
        message_id="m1",
    )
    assert result.error is None
    assert result.attempt == 1


# --------------------------------------------------------------------------- #
# Email channel
# --------------------------------------------------------------------------- #


def test_email_message_deterministic() -> None:
    message = _make_message()
    first = build_email_message(message, EMAIL_CONFIG)
    second = build_email_message(message, EMAIL_CONFIG)
    assert first == second
    assert "Subject: [c-uas] High detection latency (CRITICAL)" in first
    assert "Message-Id: <msg-deterministic@c-uas-platform>" in first
    assert "X-C-UAS-Alert-Id: alert-001" in first
    assert "X-C-UAS-Severity: CRITICAL" in first


def test_email_delivery_success_with_fake_smtp() -> None:
    class FakeSMTP:
        def __init__(self, host: str, port: int) -> None:
            self.host = host
            self.port = port
            self.started_tls = False
            self.logged_in = False
            self.sent: List[Tuple[str, List[str], str]] = []

        def starttls(self) -> None:
            self.started_tls = True

        def login(self, user: str, password: str) -> None:
            self.logged_in = True

        def sendmail(self, from_addr: str, to_addrs: List[str], msg: str) -> None:
            self.sent.append((from_addr, list(to_addrs), msg))

        def quit(self) -> None:
            pass

    message = _make_message()
    smtp = FakeSMTP(EMAIL_CONFIG.smtp_host, EMAIL_CONFIG.smtp_port)
    result = send_email(message, EMAIL_CONFIG, "smtp-alerts", smtp_factory=lambda h, p: smtp)

    assert result.delivered is True
    assert result.channel_id == "smtp-alerts"
    assert result.channel_type == CHANNEL_EMAIL
    assert result.message_id == message.message_id
    assert result.attempt == 1
    assert smtp.host == EMAIL_CONFIG.smtp_host
    assert smtp.port == EMAIL_CONFIG.smtp_port
    assert smtp.started_tls is True
    assert smtp.logged_in is True
    assert len(smtp.sent) == 1
    assert smtp.sent[0][0] == EMAIL_CONFIG.from_email
    assert smtp.sent[0][1] == list(EMAIL_CONFIG.to_emails)


def test_email_delivery_failure_with_fake_smtp() -> None:
    class BoomSMTP:
        def __init__(self, host: str, port: int) -> None:
            raise ConnectionRefusedError("connection refused")

    message = _make_message()
    result = send_email(
        message, EMAIL_CONFIG, "smtp-alerts", smtp_factory=lambda h, p: BoomSMTP(h, p)
    )
    assert result.delivered is False
    assert result.channel_type == CHANNEL_EMAIL
    assert "ConnectionRefusedError" in (result.error or "")
    assert result.attempt == 1


# --------------------------------------------------------------------------- #
# Webhook channel
# --------------------------------------------------------------------------- #


def test_webhook_payload_deterministic() -> None:
    message = _make_message()
    first = build_webhook_payload(message, WEBHOOK_CONFIG)
    second = build_webhook_payload(message, WEBHOOK_CONFIG)
    assert first == second
    assert first["alert_id"] == message.alert_id
    assert first["severity"] == message.severity
    assert first["title"] == message.title
    assert json.dumps(first, sort_keys=True) == json.dumps(first, sort_keys=True)


def test_webhook_delivery_success() -> None:
    calls: List[Dict[str, Any]] = []

    def fake_post(
        url: str, payload: Dict[str, Any], timeout: float, headers: Tuple[Tuple[str, str], ...]
    ) -> Tuple[int, str, Dict[str, str]]:
        calls.append({"url": url, "payload": payload, "timeout": timeout, "headers": headers})
        return 200, "ok", {}

    message = _make_message()
    result = send_webhook(
        message, WEBHOOK_CONFIG, "webhook-alerts", http_post=fake_post, sleep=lambda _s: None
    )

    assert result.delivered is True
    assert result.channel_type == CHANNEL_WEBHOOK
    assert result.attempt == 1
    assert len(calls) == 1
    assert calls[0]["url"] == WEBHOOK_CONFIG.url


def test_webhook_delivery_retry_then_success() -> None:
    states = [False, True]  # fail once, then succeed

    def fake_post(
        url: str, payload: Dict[str, Any], timeout: float, headers: Tuple[Tuple[str, str], ...]
    ) -> Tuple[int, str, Dict[str, str]]:
        ok = states.pop(0)
        if ok:
            return 200, "ok", {}
        return 500, "server error", {}

    message = _make_message()
    result = send_webhook(
        message, WEBHOOK_CONFIG, "webhook-alerts", http_post=fake_post, sleep=lambda _s: None
    )

    assert result.delivered is True
    assert result.attempt == 2


def test_webhook_delivery_exhausts_retries() -> None:
    def fake_post(
        url: str, payload: Dict[str, Any], timeout: float, headers: Tuple[Tuple[str, str], ...]
    ) -> Tuple[int, str, Dict[str, str]]:
        return 502, "bad gateway", {}

    config = WebhookConfig(
        url=WEBHOOK_CONFIG.url,
        max_retries=2,
        backoff_s=0.1,
        timeout_s=WEBHOOK_CONFIG.timeout_s,
    )
    message = _make_message()
    result = send_webhook(
        message, config, "webhook-alerts", http_post=fake_post, sleep=lambda _s: None
    )

    assert result.delivered is False
    assert result.attempt == 3  # 1 initial + 2 retries
    assert "HTTP 502" in (result.error or "")


# --------------------------------------------------------------------------- #
# Slack channel
# --------------------------------------------------------------------------- #


def test_slack_payload_block_kit() -> None:
    message = _make_message()
    payload = build_slack_payload(message, SLACK_CONFIG)
    assert payload["channel"] == SLACK_CONFIG.channel
    assert payload["username"] == SLACK_CONFIG.username
    assert payload["icon_emoji"] == SLACK_CONFIG.icon_emoji
    blocks = payload["blocks"]
    assert any(b.get("type") == "header" for b in blocks)
    assert any(b.get("type") == "section" for b in blocks)
    assert json.dumps(build_slack_payload(message, SLACK_CONFIG), sort_keys=True) == json.dumps(
        payload, sort_keys=True
    )


def test_slack_delivery_success() -> None:
    def fake_post(
        url: str, payload: Dict[str, Any], timeout: float, headers: Tuple[Tuple[str, str], ...]
    ) -> Tuple[int, str, Dict[str, str]]:
        return 200, '{"ok": true}', {}

    message = _make_message()
    result = send_slack(message, SLACK_CONFIG, "slack-alerts", http_post=fake_post)
    assert result.delivered is True
    assert result.channel_type == CHANNEL_SLACK


def test_slack_delivery_failure_non_ok() -> None:
    def fake_post(
        url: str, payload: Dict[str, Any], timeout: float, headers: Tuple[Tuple[str, str], ...]
    ) -> Tuple[int, str, Dict[str, str]]:
        return 200, '{"ok": false}', {}

    message = _make_message()
    result = send_slack(message, SLACK_CONFIG, "slack-alerts", http_post=fake_post)
    assert result.delivered is False
    assert result.channel_type == CHANNEL_SLACK


# --------------------------------------------------------------------------- #
# Router: routing, dedupe, rate-limit
# --------------------------------------------------------------------------- #


def _channels() -> List[NotificationChannel]:
    return [
        NotificationChannel(
            channel_id="smtp-alerts",
            channel_type=CHANNEL_EMAIL,
            enabled=True,
            email_config=EMAIL_CONFIG,
        ),
        NotificationChannel(
            channel_id="webhook-alerts",
            channel_type=CHANNEL_WEBHOOK,
            enabled=True,
            webhook_config=WEBHOOK_CONFIG,
        ),
        NotificationChannel(
            channel_id="slack-alerts",
            channel_type=CHANNEL_SLACK,
            enabled=True,
            slack_config=SLACK_CONFIG,
        ),
        NotificationChannel(
            channel_id="disabled-alerts",
            channel_type=CHANNEL_EMAIL,
            enabled=False,
            email_config=EMAIL_CONFIG,
        ),
    ]


def _fake_result(delivered: bool, error: str = "") -> DeliveryResult:
    return DeliveryResult(
        channel_id="x",
        channel_type=CHANNEL_EMAIL,
        delivered=delivered,
        message_id="msg-deterministic",
        error=error,
    )


def _router(clock: Clock) -> NotificationRouter:
    # Each router gets an isolated state dir so dedupe/rate-limit state never
    # leaks between tests.
    return NotificationRouter(
        channels=_channels(),
        config=RouterConfig(
            routes=(
                RouteRule(severity="critical", channel_ids=("smtp-alerts", "webhook-alerts")),
                RouteRule(severity="warning", channel_ids=("slack-alerts",)),
            ),
            default_channels=("slack-alerts",),
            rate_limit_per_window=2,
            rate_window_s=60.0,
            dedupe_window_s=300.0,
        ),
        state_dir=tempfile.mkdtemp(prefix="notify-test-"),
        now=clock,
    )


def _patch_send(router: NotificationRouter, outcomes: Dict[str, DeliveryResult]) -> None:
    def send_one(message: NotificationMessage, channel: NotificationChannel) -> DeliveryResult:
        return outcomes.get(
            channel.channel_id,
            _fake_result(True, ""),
        )

    router._send_one = send_one  # type: ignore[method-assign]


def test_router_route_by_severity() -> None:
    router = _router(Clock(1000.0))
    assert router.route_channels("critical") == ("smtp-alerts", "webhook-alerts")
    assert router.route_channels("warning") == ("slack-alerts",)
    assert router.route_channels("info") == ("slack-alerts",)  # defaults


def test_router_build_message_deterministic() -> None:
    router = _router(Clock(1000.0))
    alert = _alert()
    m1 = router.build_message(alert, ("smtp-alerts", "webhook-alerts"))
    m2 = router.build_message(alert, ("smtp-alerts", "webhook-alerts"))
    assert m1 == m2
    expected_id = hashlib.sha256(b"alert-001|critical").hexdigest()[:16]
    assert m1.message_id == expected_id
    assert m1.created_at == "2026-10-27T00:00:00Z"


def test_router_deliver_success_all_channels() -> None:
    clock = Clock(1000.0)
    router = _router(clock)
    outcomes = {cid: _fake_result(True, "") for cid in ("smtp-alerts", "webhook-alerts")}
    _patch_send(router, outcomes)
    results = router.deliver(_alert())
    delivered = [r for r in results if r.delivered]
    assert len(delivered) == 2
    assert all(r.error in (None, "") for r in delivered)


def test_router_disabled_channel_not_delivered() -> None:
    clock = Clock(1000.0)
    router = _router(clock)
    router.config = RouterConfig(
        routes=(RouteRule(severity="critical", channel_ids=("disabled-alerts",)),),
        default_channels=(),
    )
    results = router.deliver(_alert())
    assert len(results) == 1
    assert results[0].delivered is False
    assert results[0].error == "channel disabled"


def test_router_unknown_channel_error() -> None:
    clock = Clock(1000.0)
    router = _router(clock)
    router.config = RouterConfig(
        routes=(RouteRule(severity="critical", channel_ids=("no-such-channel",)),),
        default_channels=(),
    )
    results = router.deliver(_alert())
    assert results[0].delivered is False
    assert results[0].error == "channel not found"


def test_router_dedupe_within_window() -> None:
    clock = Clock(1000.0)
    router = _router(clock)
    outcomes = {cid: _fake_result(True, "") for cid in ("smtp-alerts", "webhook-alerts")}
    _patch_send(router, outcomes)

    first = router.deliver(_alert())
    assert all(r.delivered for r in first)

    # Same alert, same clock (still inside 300s dedupe window) -> deduped.
    second = router.deliver(_alert())
    assert all(not r.delivered for r in second)
    assert all(r.error == "deduplicated" for r in second)


def test_router_dedupe_expires_after_window() -> None:
    clock = Clock(1000.0)
    router = _router(clock)
    outcomes = {cid: _fake_result(True, "") for cid in ("smtp-alerts", "webhook-alerts")}
    _patch_send(router, outcomes)

    first = router.deliver(_alert())
    assert all(r.delivered for r in first)

    clock.now = 1301.0  # past the 300s dedupe window
    second = router.deliver(_alert())
    assert all(r.delivered for r in second)


def test_router_rate_limit() -> None:
    # rate_limit_per_window=2: third delivery to smtp-alerts within 60s is limited.
    clock = Clock(1000.0)
    router = _router(clock)
    outcomes = {cid: _fake_result(True, "") for cid in ("smtp-alerts", "webhook-alerts")}
    _patch_send(router, outcomes)

    router.deliver(_alert())  # smtp delivery #1
    alert2 = Alert(
        alert_id="alert-002",
        rule_id="rule-latency",
        name="High detection latency",
        metric="detection_latency_ms",
        severity="critical",
        state="firing",
        value=260.0,
        threshold=100.0,
        labels=(("site", "alpha"),),
        fired_at="2026-10-27T00:00:00Z",
        resolved_at=None,
        message="m",
    )
    router.deliver(alert2)  # smtp delivery #2 (different alert id, not deduped)
    alert3 = Alert(
        alert_id="alert-003",
        rule_id="rule-latency",
        name="High detection latency",
        metric="detection_latency_ms",
        severity="critical",
        state="firing",
        value=270.0,
        threshold=100.0,
        labels=(("site", "alpha"),),
        fired_at="2026-10-27T00:00:00Z",
        resolved_at=None,
        message="m",
    )
    results = router.deliver(alert3)  # smtp should be rate limited
    smtp_results = [r for r in results if r.channel_id == "smtp-alerts"]
    assert any(not r.delivered and r.error == "rate limited" for r in smtp_results)


def test_router_delivery_result_fields() -> None:
    result = DeliveryResult(
        channel_id="smtp-alerts",
        channel_type=CHANNEL_EMAIL,
        delivered=True,
        message_id="msg-123",
        error=None,
        attempt=1,
    )
    assert result.channel_id == "smtp-alerts"
    assert result.delivered is True
    assert result.message_id == "msg-123"
