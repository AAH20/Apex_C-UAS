"""
Production app factory for the C-UAS platform.

Builds an outer FastAPI app that mounts the platform app
(c_uas.api.server.app) and adds authentication, rate limiting, structured
logging, Prometheus metrics, /healthz, and /metrics endpoints.

Graceful shutdown: uvicorn drains in-flight connections when should_exit is
set, which is the graceful-shutdown path for SIGTERM/SIGINT.

Configuration is loaded from environment variables (see c_uas.deployment.config);
nothing is hardcoded.
"""

from __future__ import annotations

import os
import signal
from pathlib import Path
from typing import Any, Optional

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse

from c_uas.api.server import app as platform_app

from .config import DeploymentConfig, load_config
from .metrics import metrics
from .middleware import (
    AuthMiddleware,
    MetricsMiddleware,
    RateLimitMiddleware,
    StructuredLoggingMiddleware,
    configure_logging,
)
from .ratelimit import RateLimiter

_HEALTH_PATH = "/healthz"
_METRICS_PATH = "/metrics"


def _register_health_and_metrics(app: FastAPI, config: DeploymentConfig) -> None:
    if not _route_exists(app, _HEALTH_PATH):

        @app.get(_HEALTH_PATH)
        def healthz() -> Any:
            """Liveness + readiness. 503 when the state directory is unwritable."""
            checks = {"liveness": "ok", "readiness": "ok"}
            ready = True
            try:
                state_dir = Path.home() / ".c-uas-platform"
                state_dir.mkdir(parents=True, exist_ok=True)
                if not os.access(state_dir, os.W_OK):
                    ready = False
                    checks["readiness"] = "state_dir_not_writable"
            except OSError:
                ready = False
                checks["readiness"] = "state_dir_unreachable"
            if not ready:
                return JSONResponse({"status": "not_ready", "checks": checks}, status_code=503)
            return {"status": "ok", "checks": checks}

    if not _route_exists(app, _METRICS_PATH):

        @app.get(_METRICS_PATH)
        def metrics_output() -> Any:
            if not config.metrics_enabled:
                return JSONResponse({"detail": "metrics disabled"}, status_code=404)
            return PlainTextResponse(
                metrics.render(),
                media_type="text/plain; version=0.0.4; charset=utf-8",
            )


def _route_exists(app: FastAPI, path: str) -> bool:
    for route in app.routes:
        if getattr(route, "path", None) == path:
            return True
    return False


def create_app(config: Optional[DeploymentConfig] = None) -> FastAPI:
    """Build the production app.

    The platform app is mounted at "/"; the outer app carries the production
    middleware stack and the /healthz and /metrics routes. A fresh outer app
    is built on every call, so the shared platform app object stays pristine
    and tests remain deterministic regardless of call order.
    """
    if config is None:
        config = load_config()
    configure_logging(level=config.log_level, structured=config.structured_logging)

    outer = FastAPI(
        title=platform_app.title,
        description=platform_app.description,
        version=platform_app.version,
    )
    # Outermost first: metrics -> logging -> auth -> rate limit -> platform app.
    outer.add_middleware(MetricsMiddleware)
    outer.add_middleware(StructuredLoggingMiddleware, enabled=config.structured_logging)
    if config.auth_required:
        outer.add_middleware(AuthMiddleware, api_keys=config.api_keys)
        outer.add_middleware(
            RateLimitMiddleware,
            limiter=RateLimiter(rate=config.rate_limit_rps, burst=config.rate_limit_burst),
        )
    _register_health_and_metrics(outer, config)
    outer.mount("/", platform_app)
    return outer


def run(host: Optional[str] = None, port: Optional[int] = None) -> None:
    """Serve the production app with graceful shutdown on SIGTERM/SIGINT."""
    config = load_config() if host is None or port is None else None
    app = create_app(config)
    resolved_host = host or (config.host if config else "127.0.0.1")
    resolved_port = port or (config.port if config else 8000)

    server_config = uvicorn.Config(
        app, host=resolved_host, port=resolved_port, log_config=None, access_log=False
    )
    server = uvicorn.Server(server_config)

    previous_handlers = {
        signal.SIGTERM: signal.getsignal(signal.SIGTERM),
        signal.SIGINT: signal.getsignal(signal.SIGINT),
    }

    def handle_signal(signum: int, frame: Any) -> None:
        server.should_exit = True

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    try:
        server.run()
    finally:
        signal.signal(signal.SIGTERM, previous_handlers[signal.SIGTERM])
        signal.signal(signal.SIGINT, previous_handlers[signal.SIGINT])
