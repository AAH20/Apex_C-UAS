"""
Production ASGI middleware for the C-UAS platform API.

- AuthMiddleware: enforces X-API-Key authentication when keys are configured;
  passes requests through unauthenticated when no keys exist (dev mode).
- RateLimitMiddleware: token-bucket rate limiting per API key client.
- StructuredLoggingMiddleware: one JSON log record per request.
- MetricsMiddleware: Prometheus counters for requests, errors, latency, and
  active connections.

All middleware is raw ASGI middleware so request bodies are never touched,
and every layer is safe to stack on the platform FastAPI app.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional, Tuple

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import DeploymentConfig
from .metrics import (
    HTTP_ACTIVE_CONNECTIONS,
    HTTP_ERRORS_TOTAL,
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_TOTAL,
)
from .ratelimit import RateLimiter

LOGGER = logging.getLogger("c_uas.deployment")

# Health/metrics endpoints stay reachable without an API key so infrastructure
# probes and scrapers can work when credentials cannot be injected.
_PUBLIC_PATHS = {"/healthz", "/metrics"}


class _RawJsonHandler(logging.StreamHandler):
    """Emits log records as raw single-line JSON (no formatter wrapping)."""

    def emit(self, record: logging.LogRecord) -> None:
        self.stream.write(self.format(record) + self.terminator)
        self.flush()


_ACCESS_LOGGER = logging.getLogger("c_uas.deployment.access")
_ACCESS_LOGGER.setLevel(logging.INFO)
_ACCESS_LOGGER.propagate = False
if not _ACCESS_LOGGER.handlers:
    _handler = _RawJsonHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _ACCESS_LOGGER.addHandler(_handler)


def _api_key(scope: Scope) -> Optional[str]:
    for name, value in scope.get("headers", []):
        if name.lower() == b"x-api-key":
            return value.decode("latin-1").strip()
    return None


async def _send_json(
    send: Send,
    status: int,
    body: Dict[str, Any],
    extra_headers: Optional[list] = None,
) -> None:
    headers = [[b"content-type", b"application/json"]]
    if extra_headers:
        headers.extend(extra_headers)
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        }
    )
    await send({"type": "http.response.body", "body": json.dumps(body).encode("utf-8")})


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)
        return json.dumps(payload)


def configure_logging(level: str = "INFO", structured: bool = True) -> None:
    """Configure the root logger; structured mode emits JSON lines."""
    root = logging.getLogger()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if structured else logging.Formatter())
    root.handlers = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


class AuthMiddleware:
    def __init__(self, app: ASGIApp, api_keys: Tuple[str, ...]) -> None:
        self.app = app
        self._keys = set(api_keys)
        self.enabled = len(self._keys) > 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return
        if scope["path"] in _PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return
        key = _api_key(scope)
        if key is None or key not in self._keys:
            await _send_json(send, 401, {"detail": "unauthorized"})
            return
        await self.app(scope, receive, send)


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, limiter: Any) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.limiter is None:
            await self.app(scope, receive, send)
            return
        client_id = _api_key(scope) or "anonymous"
        if not self.limiter.allow(client_id):
            await _send_json(
                send,
                429,
                {"detail": "rate limited"},
                extra_headers=[[b"retry-after", b"1"]],
            )
            return
        await self.app(scope, receive, send)


class MetricsMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope["method"]
        path = scope["path"]
        HTTP_ACTIVE_CONNECTIONS.inc(1)
        start = time.monotonic()
        status = "500"

        async def wrapped_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = str(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        finally:
            duration = time.monotonic() - start
            labels = {"method": method, "path": path}
            HTTP_REQUESTS_TOTAL.inc(labels={**labels, "status": status})
            HTTP_REQUEST_DURATION_SECONDS.observe(duration, labels=labels)
            if status.startswith(("4", "5")):
                HTTP_ERRORS_TOTAL.inc(labels={**labels, "status": status})
            HTTP_ACTIVE_CONNECTIONS.inc(-1)


class StructuredLoggingMiddleware:
    def __init__(self, app: ASGIApp, enabled: bool = True) -> None:
        self.app = app
        self.enabled = enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return
        method = scope["method"]
        path = scope["path"]
        client = scope.get("client")
        client_addr = f"{client[0]}:{client[1]}" if client else "unknown"
        start = time.monotonic()
        status = "500"

        async def wrapped_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = str(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        finally:
            duration_ms = (time.monotonic() - start) * 1000
            _ACCESS_LOGGER.info(
                json.dumps(
                    {
                        "ts": time.time(),
                        "level": "INFO",
                        "logger": "c_uas.deployment.access",
                        "msg": "http_request",
                        "method": method,
                        "path": path,
                        "status": status,
                        "duration_ms": round(duration_ms, 2),
                        "client": client_addr,
                    }
                )
            )


def wrap_app(app: ASGIApp, config: DeploymentConfig) -> ASGIApp:
    """Wrap an ASGI app with the production middleware stack.

    Order (outermost first): metrics, structured logging, auth, rate limit.
    Rate limiting only applies when authentication is enabled, so clients are
    identified by their API key rather than by source address.
    """
    wrapped: ASGIApp = app
    wrapped = MetricsMiddleware(wrapped)
    wrapped = StructuredLoggingMiddleware(wrapped, enabled=config.structured_logging)
    limiter = None
    if config.auth_required:
        wrapped = AuthMiddleware(wrapped, config.api_keys)
        limiter = RateLimiter(rate=config.rate_limit_rps, burst=config.rate_limit_burst)
        wrapped = RateLimitMiddleware(wrapped, limiter)
    return wrapped
