"""
FastAPI surface for the API Gateway.

Mounts status, route, and health endpoints so the gateway can be operated over
HTTP in addition to the `c-uas gateway` CLI. State is shared with the CLI via
~/.c-uas-platform/gateway/.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from .gateway import Gateway

app = FastAPI(
    title="C-UAS API Gateway",
    description="Multi-backend routing with health checks and circuit breakers "
    "for detection / tracking / engagement backends.",
    version="0.1.0",
)

_gateway = Gateway()


class RouteRequest(BaseModel):
    role: Optional[str] = None
    backend_id: Optional[str] = None


class RouteResponse(BaseModel):
    backend_id: Optional[str]
    strategy: str
    reason: str
    candidates: int
    seed: int


@app.get("/gateway/status")
def gateway_status() -> dict[str, Any]:
    return _gateway.status()


@app.post("/gateway/route", response_model=RouteResponse)
def gateway_route(req: RouteRequest) -> RouteResponse:
    decision = _gateway.route(role=req.role, backend_id=req.backend_id)
    _gateway.save()
    return RouteResponse(
        backend_id=decision.backend.backend_id if decision.backend else None,
        strategy=decision.strategy,
        reason=decision.reason,
        candidates=decision.candidates,
        seed=decision.seed,
    )


@app.get("/gateway/health")
def gateway_health(backend_id: Optional[str] = None) -> dict[str, Any]:
    results = _gateway.probe(backend_id)
    _gateway.save()
    if isinstance(results, list):
        return {
            "probes": [
                {
                    "backend_id": r.backend_id,
                    "healthy": r.healthy,
                    "latency_ms": r.latency_ms,
                    "probed_at": r.probed_at,
                    "error": r.error,
                }
                for r in results
            ]
        }
    r = results
    return {
        "backend_id": r.backend_id,
        "healthy": r.healthy,
        "latency_ms": r.latency_ms,
        "probed_at": r.probed_at,
        "error": r.error,
    }
