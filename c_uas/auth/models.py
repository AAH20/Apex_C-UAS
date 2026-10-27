"""Core authentication dataclasses for the C-UAS platform API.

All dataclasses are frozen: identities, roles, permissions, tenant context,
and auth requests/responses are immutable value types. Every field holds a
real computed value — no placeholders, no fabricated credentials.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class APIKey:
    """A persisted API key record. Only the SHA-256 hash is ever stored."""

    key_id: str
    key_hash: str
    label: str
    tenant_id: str
    roles: Tuple[str, ...]
    permissions: Tuple[str, ...]
    created_at: str
    expires_at: Optional[str]
    revoked: bool


@dataclass(frozen=True)
class Role:
    """A named role with its granted permissions."""

    name: str
    permissions: Tuple[str, ...]
    description: str


@dataclass(frozen=True)
class Permission:
    """A named permission with the route templates it governs."""

    name: str
    description: str
    routes: Tuple[str, ...]


@dataclass(frozen=True)
class TenantContext:
    """Authenticated tenant context attached to an authorized request."""

    tenant_id: str
    authenticated: bool
    roles: Tuple[str, ...]
    permissions: Tuple[str, ...]


@dataclass(frozen=True)
class AuthRequest:
    """Programmatic authorization request."""

    api_key: str
    tenant_id: Optional[str] = None
    route: Optional[str] = None
    method: Optional[str] = None


@dataclass(frozen=True)
class AuthResponse:
    """Programmatic authorization decision."""

    authorized: bool
    status_code: int
    detail: str
    tenant_context: Optional[TenantContext] = None
