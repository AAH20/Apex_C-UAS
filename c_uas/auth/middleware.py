"""FastAPI authentication middleware for the C-UAS platform API.

Extracts the API key from the ``Authorization: Bearer <key>`` header,
validates it against the key store, attaches a ``TenantContext`` to
``request.state.tenant_context``, and rejects unauthenticated or
insufficiently-privileged requests with 401 / 403.

When no keys are configured the middleware is a pass-through (dev mode),
matching the deployment module convention: authentication is enforced only
once at least one key exists.
"""

from __future__ import annotations

from typing import Awaitable, Callable, Optional, Set

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .api_keys import APIKey, KeyStore, default_key_store, validate_key
from .models import TenantContext
from .rbac import authorize, context_for_key

_FRAMEWORK_PUBLIC_PATHS: Set[str] = {
    "/docs",
    "/docs/oauth2-redirect",
    "/openapi.json",
    "/redoc",
}

_TENANT_HEADER = "X-Tenant-Id"
_AUTH_HEADER = "Authorization"
_BEARER_PREFIX = "Bearer "


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        key_store: Optional[KeyStore] = None,
        public_paths: Optional[Set[str]] = None,
    ) -> None:
        super().__init__(app)
        self._store = key_store
        self._public: Set[str] = (
            set(public_paths) if public_paths is not None else _FRAMEWORK_PUBLIC_PATHS
        )

    def _key_store(self) -> KeyStore:
        if self._store is not None:
            return self._store
        return default_key_store()

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path

        # Framework routes (docs, OpenAPI) stay reachable without credentials.
        if path in self._public:
            return await call_next(request)

        store = self._key_store()
        # Dev mode: no keys configured -> authentication not yet enabled.
        if not store.has_any_keys():
            return await call_next(request)

        key = self._extract_key(request)
        if key is None:
            return JSONResponse({"detail": "unauthorized"}, status_code=401)

        record: Optional[APIKey] = validate_key(key)
        if record is None:
            return JSONResponse({"detail": "unauthorized"}, status_code=401)

        context: TenantContext = context_for_key(record)

        # Tenant scoping: an explicit tenant header must match the key's tenant.
        requested_tenant = request.headers.get(_TENANT_HEADER)
        if requested_tenant is not None and requested_tenant != context.tenant_id:
            return JSONResponse({"detail": "forbidden"}, status_code=403)

        decision = authorize(context, request.method, path)
        if not decision.authorized:
            return JSONResponse({"detail": "forbidden"}, status_code=403)

        request.state.tenant_context = context
        return await call_next(request)

    @staticmethod
    def _extract_key(request: Request) -> Optional[str]:
        auth = request.headers.get(_AUTH_HEADER)
        if auth is not None and auth.startswith(_BEARER_PREFIX):
            return auth[len(_BEARER_PREFIX) :].strip()
        return None


def tenant_context(request: Request) -> Optional[TenantContext]:
    """Read the tenant context attached by AuthMiddleware (None if absent)."""
    return getattr(request.state, "tenant_context", None)
