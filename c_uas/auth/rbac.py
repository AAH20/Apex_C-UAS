"""Role-based access control for the C-UAS platform API.

Roles:
  admin     - read, write, deploy, admin (full platform access)
  operator  - read, write, deploy (operate detection and engagement)
  viewer    - read (read-only dashboards and reports)
  auditor   - read (read-only compliance and audit review)

Permissions: read, write, deploy, admin.

Every route exposed by c_uas.api.server maps to exactly one required
permission per HTTP method. Decisions are pure functions of
(roles, method, path, tenant) — same inputs always yield the same decision.
No randomness, no secrets module.
"""

from __future__ import annotations

from typing import Dict, Iterable, Optional, Tuple

from .models import APIKey, AuthResponse, Permission, Role, TenantContext

# ---------------------------------------------------------------------------
# Role definitions
# ---------------------------------------------------------------------------

ROLES: Tuple[Role, ...] = (
    Role(
        name="admin",
        permissions=("read", "write", "deploy", "admin"),
        description="Full platform access",
    ),
    Role(
        name="operator",
        permissions=("read", "write", "deploy"),
        description="Operate detection and engagement",
    ),
    Role(
        name="viewer",
        permissions=("read",),
        description="Read-only dashboards and reports",
    ),
    Role(
        name="auditor",
        permissions=("read",),
        description="Read-only compliance and audit review",
    ),
)

ROLE_BY_NAME: Dict[str, Role] = {role.name: role for role in ROLES}

ALL_PERMISSIONS: Tuple[str, ...] = ("read", "write", "deploy", "admin")

# ---------------------------------------------------------------------------
# Permission definitions
# ---------------------------------------------------------------------------

PERMISSIONS: Tuple[Permission, ...] = (
    Permission(
        name="read",
        description="Read-only queries and health/status endpoints",
        routes=(),
    ),
    Permission(
        name="write",
        description="Create or modify platform resources",
        routes=(),
    ),
    Permission(
        name="deploy",
        description="Run detection scans, scheduling, and model actions",
        routes=(),
    ),
    Permission(
        name="admin",
        description="Administrative actions (implied by admin role)",
        routes=(),
    ),
)

PERMISSION_BY_NAME: Dict[str, Permission] = {perm.name: perm for perm in PERMISSIONS}

# ---------------------------------------------------------------------------
# Route -> required permission, keyed by (HTTP method, path template).
# Path templates support {param} segments that match any single path segment.
# ---------------------------------------------------------------------------

_ROUTE_PERMISSION: Dict[Tuple[str, str], str] = {
    # Health / status (read-only)
    ("GET", "/"): "read",
    ("GET", "/status"): "read",
    # Governance
    ("GET", "/systems"): "read",
    ("POST", "/systems"): "write",
    ("GET", "/risks"): "read",
    ("POST", "/risks"): "write",
    ("GET", "/controls"): "read",
    ("POST", "/controls/{control_id}/implement"): "write",
    ("POST", "/incidents"): "write",
    ("GET", "/compliance"): "read",
    ("GET", "/evidence/verify"): "read",
    # Detection (queries are read; active scans/models are deploy actions)
    ("POST", "/detection/scan-rf"): "deploy",
    ("POST", "/detection/spoof"): "deploy",
    # Engagement (deploy actions)
    ("POST", "/engagement/schedule"): "deploy",
    ("POST", "/engagement/backtest"): "deploy",
    ("POST", "/swarm/simulate"): "deploy",
    ("POST", "/dew/model"): "deploy",
    # Catalogs and reports (read-only)
    ("GET", "/competitive-landscape"): "read",
    ("POST", "/unit-economics"): "read",
    ("GET", "/benchmarks"): "read",
    ("GET", "/performance/benchmark"): "read",
    ("GET", "/performance/profile"): "read",
    ("GET", "/performance/sla"): "read",
    ("GET", "/security/audit"): "read",
    ("GET", "/security/penetrate"): "read",
    ("GET", "/security/compliance"): "read",
    ("GET", "/observability/metrics"): "read",
    ("GET", "/observability/alerts"): "read",
    ("GET", "/observability/health"): "read",
    ("GET", "/observability/slo"): "read",
    ("GET", "/datacenter/capacity"): "read",
    ("GET", "/datacenter/lifecycle"): "read",
    ("GET", "/datacenter/efficiency"): "read",
    ("GET", "/edge/tenant"): "read",
    ("GET", "/edge/fleet"): "read",
    ("GET", "/edge/zero-trust"): "read",
}

# Default permission required for any route not explicitly mapped. Every
# platform route is mapped above; this is a conservative fallback.
DEFAULT_PERMISSION = "read"

# ---------------------------------------------------------------------------
# Pure decision functions
# ---------------------------------------------------------------------------


def role_permissions(role_name: str) -> Tuple[str, ...]:
    """Return the permissions granted to a role, empty tuple if unknown."""
    role = ROLE_BY_NAME.get(role_name)
    if role is None:
        return ()
    return role.permissions


def has_permission(roles: Iterable[str], permission: str) -> bool:
    """True when any granted role carries the permission."""
    for role_name in roles:
        if permission in role_permissions(role_name):
            return True
    return False


def _path_matches(template: str, path: str) -> bool:
    """Segment-wise match where ``{param}`` template segments match anything."""
    template_parts = template.split("/")
    path_parts = path.split("/")
    if len(template_parts) != len(path_parts):
        return False
    for t_part, p_part in zip(template_parts, path_parts):
        if t_part != p_part and not (t_part.startswith("{") and t_part.endswith("}")):
            return False
    return True


def route_permission(method: str, path: str) -> Optional[str]:
    """Required permission for an HTTP route, or None when unmapped."""
    method = method.upper()
    for (route_method, template), permission in _ROUTE_PERMISSION.items():
        if route_method == method and _path_matches(template, path):
            return permission
    return None


def route_requires(method: str, path: str) -> str:
    """Required permission for a route, falling back to read-only."""
    required = route_permission(method, path)
    if required is None:
        return DEFAULT_PERMISSION
    return required


def context_for_key(api_key: APIKey) -> TenantContext:
    """Build a tenant context from an API key record."""
    return TenantContext(
        tenant_id=api_key.tenant_id,
        authenticated=not api_key.revoked,
        roles=api_key.roles,
        permissions=api_key.permissions,
    )


def tenant_scoped(context: TenantContext, tenant_id: str) -> bool:
    """True when the context belongs to the requested tenant."""
    return context.tenant_id == tenant_id


def authorize(
    context: TenantContext,
    method: str,
    path: str,
    tenant_id: Optional[str] = None,
) -> AuthResponse:
    """Authorize a request.

    Denied with 403 when the context lacks the route permission or fails the
    tenant scoping check. Allowed with 200 otherwise.
    """
    if tenant_id is not None and not tenant_scoped(context, tenant_id):
        return AuthResponse(
            authorized=False,
            status_code=403,
            detail="forbidden: tenant mismatch",
            tenant_context=context,
        )
    required = route_requires(method, path)
    if not has_permission(context.roles, required):
        return AuthResponse(
            authorized=False,
            status_code=403,
            detail="forbidden: missing permission '{}'".format(required),
            tenant_context=context,
        )
    return AuthResponse(
        authorized=True,
        status_code=200,
        detail="authorized",
        tenant_context=context,
    )
