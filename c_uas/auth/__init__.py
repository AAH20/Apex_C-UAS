"""C-UAS platform API authentication and RBAC.

Modules:
  models      - frozen dataclasses (APIKey, Role, Permission, TenantContext,
                AuthRequest, AuthResponse)
  api_keys    - deterministic API key generation, hashing, validation,
                rotation, persistence under ~/.c-uas-platform/auth/keys/
  rbac        - role-based access control with route-to-permission mapping
                and tenant scoping
  middleware  - FastAPI middleware: Bearer key validation, tenant context,
                401/403 rejections
  cli         - ``c-uas auth`` subcommand (build_subparser + auth_main)

State persists under ~/.c-uas-platform/auth/ (outside the repo). All output
is deterministic: same inputs yield the same keys and decisions.
"""

from __future__ import annotations

from .api_keys import (
    FIXED_SEED,
    APIKey,
    KeyStore,
    create_key,
    default_key_store,
    derive_key_id,
    generate_api_key,
    hash_key,
    list_keys,
    revoke_key,
    rotate_key,
    validate_key,
)
from .middleware import AuthMiddleware, tenant_context
from .models import AuthRequest, AuthResponse, Permission, Role, TenantContext
from .rbac import (
    ALL_PERMISSIONS,
    PERMISSIONS,
    ROLE_BY_NAME,
    ROLES,
    authorize,
    context_for_key,
    has_permission,
    role_permissions,
    route_permission,
    route_requires,
    tenant_scoped,
)

__all__ = [
    "FIXED_SEED",
    "APIKey",
    "AuthRequest",
    "AuthResponse",
    "KeyStore",
    "Permission",
    "Role",
    "TenantContext",
    "create_key",
    "default_key_store",
    "derive_key_id",
    "generate_api_key",
    "hash_key",
    "list_keys",
    "revoke_key",
    "rotate_key",
    "validate_key",
    "AuthMiddleware",
    "tenant_context",
    "ROLES",
    "ALL_PERMISSIONS",
    "PERMISSIONS",
    "ROLE_BY_NAME",
    "authorize",
    "context_for_key",
    "has_permission",
    "role_permissions",
    "route_permission",
    "route_requires",
    "tenant_scoped",
]
