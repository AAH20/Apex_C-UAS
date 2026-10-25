"""
Contract verifier: load an OpenAPI spec (YAML or JSON), extract all
(method, path) routes, compare them against the FastAPI app route table,
and report missing / extra / mismatched routes.

All functions are pure: identical inputs produce an identical report. No
network access. Route comparison keys on (HTTP method, path template).
HEAD and OPTIONS are infrastructure methods added automatically by
FastAPI and are excluded from the app route table.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import yaml  # type: ignore[import-untyped]

HTTP_METHODS = ("get", "head", "post", "put", "delete", "options", "patch", "trace")
# Infrastructure methods FastAPI derives automatically; not part of a contract.
_EXCLUDED_METHODS = frozenset({"HEAD", "OPTIONS"})


@dataclass(frozen=True)
class RouteEntry:
    """A single API route: HTTP method plus path template."""

    method: str
    path: str


@dataclass(frozen=True)
class ContractReport:
    """Deterministic comparison of OpenAPI spec routes vs app routes."""

    spec_path: str
    spec_routes: Tuple[RouteEntry, ...]
    app_routes: Tuple[RouteEntry, ...]
    missing: Tuple[RouteEntry, ...]  # in spec, not in app
    extra: Tuple[RouteEntry, ...]  # in app, not in spec
    mismatched: Tuple[Tuple[str, Tuple[str, ...], Tuple[str, ...]], ...]
    # (path, spec methods, app methods) where both exist but differ
    ok: bool


def load_spec(path: str) -> Dict[str, Any]:
    """Load an OpenAPI spec from a YAML or JSON file."""
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if path.lower().endswith((".json",)):
        return json.loads(text)  # type: ignore[return-value]
    return yaml.safe_load(text)  # type: ignore[return-value]


def extract_spec_routes(spec: Optional[Dict[str, Any]]) -> List[RouteEntry]:
    """All (method, path) routes declared under spec['paths']."""
    if not spec:
        return []
    routes: Set[RouteEntry] = set()
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for key, value in item.items():
            if key.lower() not in HTTP_METHODS:
                continue
            if not isinstance(value, dict):
                continue
            routes.add(RouteEntry(method=key.upper(), path=path))
    return sorted(routes, key=lambda route: (route.path, route.method))


def extract_app_routes(app: Any) -> List[RouteEntry]:
    """HTTP (method, path) routes mounted on a FastAPI app."""
    router = getattr(app, "router", None)
    routes_iter = getattr(router, "routes", None) if router is not None else None
    if routes_iter is None:
        return []
    routes: Set[RouteEntry] = set()
    for route in routes_iter:
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", None)
        if methods is None or path is None:
            continue
        for method in methods:
            if method in _EXCLUDED_METHODS:
                continue
            routes.add(RouteEntry(method=str(method).upper(), path=str(path)))
    return sorted(routes, key=lambda route: (route.path, route.method))


def load_app_routes() -> List[RouteEntry]:
    """Extract the route table of the platform API app (c_uas.api.server)."""
    from c_uas.api.server import app

    return extract_app_routes(app)


def _methods_by_path(routes: Sequence[RouteEntry]) -> Dict[str, Tuple[str, ...]]:
    by_path: Dict[str, Set[str]] = {}
    for route in routes:
        by_path.setdefault(route.path, set()).add(route.method)
    return {path: tuple(sorted(methods)) for path, methods in by_path.items()}


def verify_contract(spec_path: str, app_routes: Sequence[RouteEntry]) -> ContractReport:
    """Compare spec routes against app routes; deterministic report."""
    spec = load_spec(spec_path)
    spec_routes = extract_spec_routes(spec)
    spec_set = set(spec_routes)
    app_set = set(app_routes)

    missing = tuple(route for route in spec_routes if route not in app_set)
    extra = tuple(
        route
        for route in sorted(app_set, key=lambda route: (route.path, route.method))
        if route not in spec_set
    )

    spec_by_path = _methods_by_path(spec_routes)
    app_by_path = _methods_by_path(list(app_routes))
    mismatched: List[Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = []
    for path in sorted(set(spec_by_path) & set(app_by_path)):
        spec_methods = spec_by_path[path]
        app_methods = app_by_path[path]
        if spec_methods != app_methods:
            mismatched.append((path, spec_methods, app_methods))

    ok = not (missing or extra or mismatched)
    return ContractReport(
        spec_path=spec_path,
        spec_routes=tuple(spec_routes),
        app_routes=tuple(sorted(app_set, key=lambda route: (route.path, route.method))),
        missing=missing,
        extra=extra,
        mismatched=tuple(mismatched),
        ok=ok,
    )


def contract_report_to_dict(report: ContractReport) -> Dict[str, Any]:
    """JSON-serializable rendering of a ContractReport (tuples become lists)."""
    return {
        "spec_path": report.spec_path,
        "spec_routes": [asdict(route) for route in report.spec_routes],
        "app_routes": [asdict(route) for route in report.app_routes],
        "missing": [asdict(route) for route in report.missing],
        "extra": [asdict(route) for route in report.extra],
        "mismatched": [
            {"path": path, "spec_methods": list(spec_methods), "app_methods": list(app_methods)}
            for path, spec_methods, app_methods in report.mismatched
        ],
        "ok": report.ok,
    }
