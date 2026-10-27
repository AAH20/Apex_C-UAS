"""Deterministic tests for API key authentication and RBAC.

Covers key generation/validation/persistence, RBAC decisions, middleware
behavior (401/403, tenant context, pass-through mode), and the auth CLI.
All values are computed from real execution; no mocks, no secrets.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from c_uas.api.server import app as server_app
from c_uas.auth.api_keys import (
    FIXED_SEED,
    APIKey,
    KeyStore,
    create_key,
    derive_key_id,
    generate_api_key,
    hash_key,
    list_keys,
    validate_key,
)
from c_uas.auth.middleware import AuthMiddleware
from c_uas.auth.models import TenantContext
from c_uas.auth.rbac import (
    ALL_PERMISSIONS,
    ROLES,
    authorize,
    context_for_key,
    has_permission,
    role_permissions,
    route_permission,
    route_requires,
    tenant_scoped,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _use_tmp_store(tmp_path, monkeypatch) -> KeyStore:
    """Point the default key store at a throwaway directory."""
    keys_dir = tmp_path / "auth" / "keys"
    monkeypatch.setenv("CUAS_AUTH_KEYS_DIR", str(keys_dir))
    return KeyStore()


def _make_app(store: KeyStore) -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthMiddleware, key_store=store)

    @app.get("/systems")
    def list_systems() -> dict:
        return {"ok": True}

    @app.post("/systems")
    def create_system() -> dict:
        return {"ok": True}

    @app.post("/engagement/schedule")
    def schedule() -> dict:
        return {"ok": True}

    @app.post("/incidents")
    def record_incident() -> dict:
        return {"ok": True}

    @app.get("/compliance")
    def compliance() -> dict:
        return {"ok": True}

    return app


def _create_key(store: KeyStore, tenant: str = "default", roles=("admin",)) -> str:
    _, plain = store.create_api_key(label="test", tenant_id=tenant, roles=roles)
    return plain


def _header(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


# ---------------------------------------------------------------------------
# API key generation (deterministic, no secrets module)
# ---------------------------------------------------------------------------


def test_generate_api_key_is_deterministic() -> None:
    first = generate_api_key(seed=FIXED_SEED, label="prod", index=1)
    second = generate_api_key(seed=FIXED_SEED, label="prod", index=1)
    assert first == second
    assert first.startswith("cuas_live_")
    assert len(first) == len("cuas_live_") + 64


def test_generate_api_key_changes_with_inputs() -> None:
    base = generate_api_key(seed=FIXED_SEED, label="prod", index=1)
    assert generate_api_key(seed=FIXED_SEED, label="prod", index=2) != base
    assert generate_api_key(seed=FIXED_SEED, label="other", index=1) != base
    assert generate_api_key(seed="other-seed", label="prod", index=1) != base


def test_hash_key_is_deterministic() -> None:
    key = generate_api_key()
    assert hash_key(key) == hash_key(key)
    assert hash_key(key) != hash_key("a-different-key")
    assert len(hash_key(key)) == 64


def test_derive_key_id_is_deterministic() -> None:
    key = generate_api_key()
    assert derive_key_id(key) == derive_key_id(key)
    assert derive_key_id(key).startswith("cuas_")
    assert len(derive_key_id(key)) == len("cuas_") + 32


def test_api_keys_module_avoids_secrets() -> None:
    import c_uas.auth.api_keys as api_keys_module

    path = Path(api_keys_module.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.name for alias in node.names]
            assert "secrets" not in names


# ---------------------------------------------------------------------------
# Key persistence: create / validate / revoke / rotate
# ---------------------------------------------------------------------------


def test_create_and_validate_key(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    record, plain = create_key(label="prod", tenant_id="acme", roles=("admin",))

    assert isinstance(record, APIKey)
    assert record.key_hash == hash_key(plain)
    assert record.key_id == derive_key_id(plain)
    assert record.tenant_id == "acme"
    assert record.roles == ("admin",)
    assert record.permissions == ALL_PERMISSIONS
    assert not record.revoked
    assert record.created_at  # real UTC timestamp

    validated = validate_key(plain)
    assert validated is not None
    assert validated.key_id == record.key_id
    assert validated.tenant_id == "acme"

    # Plaintext never persisted; only the hash is on disk.
    stored = (store._dir / (record.key_id + ".json")).read_text(encoding="utf-8")
    assert plain not in stored
    assert hash_key(plain) in stored


def test_validate_rejects_wrong_and_unknown_keys(tmp_path, monkeypatch) -> None:
    _use_tmp_store(tmp_path, monkeypatch)
    create_key(label="prod", tenant_id="acme", roles=("admin",))
    assert validate_key("cuas_live_wrong") is None
    assert validate_key(generate_api_key(seed=FIXED_SEED, label="x", index=99)) is None


def test_revoke_key_blocks_validation(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    record, plain = create_key(label="prod", tenant_id="acme", roles=("viewer",))
    assert validate_key(plain) is not None

    assert store.revoke_key(record.key_id) is True
    assert store.revoke_key("cuas_does_not_exist") is False
    assert validate_key(plain) is None

    reloaded = store.load(record.key_id)
    assert reloaded is not None and reloaded.revoked is True


def test_rotate_key_issues_replacement(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    record, plain = create_key(label="prod", tenant_id="acme", roles=("viewer",))

    new_record, new_plain = store.rotate_key(record.key_id)
    assert new_record is not None
    assert new_record.key_id != record.key_id
    assert new_record.tenant_id == "acme"
    assert new_record.roles == ("viewer",)
    assert new_plain != plain

    assert validate_key(plain) is None
    assert validate_key(new_plain) is not None
    assert store.load(record.key_id) is not None and store.load(record.key_id).revoked


def test_persistence_survives_store_reload(tmp_path, monkeypatch) -> None:
    keys_dir = tmp_path / "auth" / "keys"
    monkeypatch.setenv("CUAS_AUTH_KEYS_DIR", str(keys_dir))
    record, plain = create_key(label="prod", tenant_id="acme", roles=("operator",))

    reloaded_store = KeyStore(str(keys_dir))
    keys = reloaded_store.list_keys()
    assert len(keys) == 1
    assert keys[0].key_id == record.key_id
    assert reloaded_store.validate_key(plain) is not None


def test_list_keys_is_sorted_and_metadata_only(tmp_path, monkeypatch) -> None:
    _use_tmp_store(tmp_path, monkeypatch)
    create_key(label="b", tenant_id="acme", roles=("viewer",))
    create_key(label="a", tenant_id="acme", roles=("admin",))

    keys = list_keys()
    assert len(keys) == 2
    assert keys[0].key_id < keys[1].key_id
    for key in keys:
        assert key.key_hash  # hash present
        # list_keys returns full records; CLI shows metadata only (no plaintext)


# ---------------------------------------------------------------------------
# RBAC decisions
# ---------------------------------------------------------------------------


def test_role_permissions() -> None:
    assert role_permissions("admin") == ("read", "write", "deploy", "admin")
    assert role_permissions("operator") == ("read", "write", "deploy")
    assert role_permissions("viewer") == ("read",)
    assert role_permissions("auditor") == ("read",)
    assert role_permissions("no-such-role") == ()


def test_role_hierarchy() -> None:
    assert {role.name for role in ROLES} == {
        "admin",
        "operator",
        "viewer",
        "auditor",
    }
    for role in ROLES:
        assert "read" in role.permissions
    assert "admin" in role_permissions("admin")
    assert "admin" not in role_permissions("operator")
    assert "admin" not in role_permissions("viewer")
    assert "admin" not in role_permissions("auditor")


def test_has_permission() -> None:
    assert has_permission(("viewer",), "read") is True
    assert has_permission(("viewer",), "write") is False
    assert has_permission(("operator",), "deploy") is True
    assert has_permission(("auditor",), "admin") is False
    assert has_permission(("admin",), "admin") is True
    assert has_permission((), "read") is False


def test_route_permission_map_covers_platform_routes() -> None:
    assert route_permission("GET", "/systems") == "read"
    assert route_permission("POST", "/systems") == "write"
    assert route_permission("POST", "/risks") == "write"
    assert route_permission("POST", "/controls/{control_id}/implement") == "write"
    assert route_permission("POST", "/incidents") == "write"
    assert route_permission("POST", "/detection/scan-rf") == "deploy"
    assert route_permission("POST", "/detection/spoof") == "deploy"
    assert route_permission("POST", "/engagement/schedule") == "deploy"
    assert route_permission("POST", "/engagement/backtest") == "deploy"
    assert route_permission("POST", "/swarm/simulate") == "deploy"
    assert route_permission("POST", "/dew/model") == "deploy"
    assert route_permission("GET", "/status") == "read"
    assert route_permission("GET", "/observability/health") == "read"
    assert route_permission("GET", "/edge/zero-trust") == "read"


def test_route_requires_falls_back_to_read() -> None:
    assert route_requires("GET", "/anything-else") == "read"


def test_authorize_grants_and_denies() -> None:
    admin_ctx = TenantContext("acme", True, ("admin",), ALL_PERMISSIONS)
    viewer_ctx = TenantContext("acme", True, ("viewer",), ("read",))

    decision = authorize(admin_ctx, "POST", "/systems")
    assert decision.authorized is True
    assert decision.status_code == 200
    assert decision.detail == "authorized"

    decision = authorize(viewer_ctx, "POST", "/systems")
    assert decision.authorized is False
    assert decision.status_code == 403
    assert "write" in decision.detail

    decision = authorize(viewer_ctx, "GET", "/systems")
    assert decision.authorized is True
    assert decision.status_code == 200


def test_authorize_tenant_scoping() -> None:
    ctx = TenantContext("acme", True, ("admin",), ALL_PERMISSIONS)
    assert authorize(ctx, "GET", "/", tenant_id="acme").authorized is True
    decision = authorize(ctx, "GET", "/", tenant_id="other")
    assert decision.authorized is False
    assert decision.status_code == 403
    assert tenant_scoped(ctx, "acme") is True
    assert tenant_scoped(ctx, "other") is False


def test_context_for_key() -> None:
    record = APIKey(
        key_id="cuas_test",
        key_hash=hash_key("secret"),
        label="t",
        tenant_id="tenant-1",
        roles=("operator",),
        permissions=("read", "write", "deploy"),
        created_at="2026-01-01T00:00:00+00:00",
        expires_at=None,
        revoked=False,
    )
    context = context_for_key(record)
    assert isinstance(context, TenantContext)
    assert context.tenant_id == "tenant-1"
    assert context.authenticated is True
    assert context.roles == ("operator",)


# ---------------------------------------------------------------------------
# Middleware behavior
# ---------------------------------------------------------------------------


def test_middleware_pass_through_without_keys(tmp_path, monkeypatch) -> None:
    keys_dir = tmp_path / "empty"
    monkeypatch.setenv("CUAS_AUTH_KEYS_DIR", str(keys_dir))
    app = _make_app(KeyStore(str(keys_dir)))
    client = TestClient(app)
    assert client.get("/systems").status_code == 200


def test_middleware_missing_key_returns_401(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    _create_key(store, tenant="acme", roles=("admin",))
    client = TestClient(_make_app(store))
    assert client.get("/systems").status_code == 401
    assert client.get("/systems").json() == {"detail": "unauthorized"}


def test_middleware_invalid_key_returns_401(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    _create_key(store, tenant="acme", roles=("admin",))
    client = TestClient(_make_app(store))
    assert client.get("/systems", headers=_header("cuas_live_bogus")).status_code == 401


def test_middleware_valid_key_viewer_get_200(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    plain = _create_key(store, tenant="acme", roles=("viewer",))
    client = TestClient(_make_app(store))
    resp = client.get("/systems", headers=_header(plain))
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_middleware_attaches_tenant_context(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    seen = {}

    app = _make_app(store)

    @app.get("/probe")
    def probe(request: Request) -> dict:
        from c_uas.auth.middleware import tenant_context

        seen["ctx"] = tenant_context(request)
        return {"ok": True}

    plain = _create_key(store, tenant="acme", roles=("viewer",))
    client = TestClient(app)
    assert client.get("/probe", headers=_header(plain)).status_code == 200
    ctx = seen["ctx"]
    assert ctx is not None
    assert ctx.tenant_id == "acme"
    assert ctx.authenticated is True


def test_middleware_viewer_cannot_post(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    plain = _create_key(store, tenant="acme", roles=("viewer",))
    client = TestClient(_make_app(store))
    resp = client.post("/systems", headers=_header(plain))
    assert resp.status_code == 403
    assert resp.json() == {"detail": "forbidden"}


def test_middleware_operator_can_deploy(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    plain = _create_key(store, tenant="acme", roles=("operator",))
    client = TestClient(_make_app(store))
    assert client.post("/engagement/schedule", headers=_header(plain)).status_code == 200


def test_middleware_auditor_cannot_admin(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    plain = _create_key(store, tenant="acme", roles=("auditor",))
    client = TestClient(_make_app(store))
    assert client.post("/incidents", headers=_header(plain)).status_code == 403


def test_middleware_tenant_mismatch_returns_403(tmp_path, monkeypatch) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    plain = _create_key(store, tenant="acme", roles=("admin",))
    client = TestClient(_make_app(store))
    resp = client.get("/systems", headers={**_header(plain), "X-Tenant-Id": "other"})
    assert resp.status_code == 403
    assert resp.json() == {"detail": "forbidden"}


# ---------------------------------------------------------------------------
# Auth middleware is mounted on the real server app (all 36+ routes)
# ---------------------------------------------------------------------------


def test_server_app_mounts_auth_middleware() -> None:
    mounted = any(
        getattr(entry, "cls", None) is AuthMiddleware for entry in server_app.user_middleware
    )
    assert mounted is True


def test_server_app_still_serves_without_keys(tmp_path, monkeypatch) -> None:
    keys_dir = tmp_path / "empty"
    monkeypatch.setenv("CUAS_AUTH_KEYS_DIR", str(keys_dir))
    client = TestClient(server_app)
    assert client.get("/").status_code == 200
    assert client.get("/status").status_code == 200


# ---------------------------------------------------------------------------
# CLI: deterministic output
# ---------------------------------------------------------------------------


def _namespace(**overrides) -> argparse.Namespace:
    defaults = {
        "create_key": False,
        "list_keys": False,
        "revoke_key": None,
        "rotate_key": None,
        "check_perm": False,
        "label": "default",
        "tenant": "default",
        "role": None,
        "key": None,
        "route": None,
        "method": "GET",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_cli_create_key_is_deterministic(tmp_path, monkeypatch, capsys) -> None:
    from c_uas.auth.cli import auth_main

    dir_a = tmp_path / "a" / "keys"
    dir_b = tmp_path / "b" / "keys"
    monkeypatch.setenv("CUAS_AUTH_KEYS_DIR", str(dir_a))

    assert auth_main(_namespace(create_key=True, tenant="acme", role="operator")) == 0
    out_a = capsys.readouterr().out

    monkeypatch.setenv("CUAS_AUTH_KEYS_DIR", str(dir_b))
    assert auth_main(_namespace(create_key=True, tenant="acme", role="operator")) == 0
    out_b = capsys.readouterr().out

    # The "stored at" line differs (different dirs) and "created_at" is a
    # real wall-clock timestamp (not deterministic); compare the rest.
    lines_a = [
        line
        for line in out_a.splitlines()
        if not line.startswith(("  stored at  :", "  created_at :"))
    ]
    lines_b = [
        line
        for line in out_b.splitlines()
        if not line.startswith(("  stored at  :", "  created_at :"))
    ]
    assert lines_a == lines_b
    assert "key        : cuas_live_" in out_a
    assert "roles      : operator" in out_a
    assert "tenant     : acme" in out_a
    assert "permissions: read, write, deploy" in out_a


def test_cli_list_keys(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("CUAS_AUTH_KEYS_DIR", str(tmp_path / "keys"))
    from c_uas.auth.cli import auth_main

    _use_tmp_store(tmp_path, monkeypatch).create_api_key(
        label="b", tenant_id="acme", roles=("viewer",)
    )
    assert auth_main(_namespace(list_keys=True)) == 0
    out = capsys.readouterr().out
    assert "key(s)" in out
    assert "acme" in out
    assert "viewer" in out
    assert "active" in out


def test_cli_revoke_key(tmp_path, monkeypatch, capsys) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    record, _ = store.create_api_key(label="revoke-me", tenant_id="acme", roles=("admin",))
    from c_uas.auth.cli import auth_main

    assert auth_main(_namespace(revoke_key=record.key_id)) == 0
    out = capsys.readouterr().out
    assert f"key revoked: {record.key_id}" in out
    # A second revoke of the same id reports not found
    assert auth_main(_namespace(revoke_key=record.key_id)) == 1


def test_cli_check_perm(tmp_path, monkeypatch, capsys) -> None:
    store = _use_tmp_store(tmp_path, monkeypatch)
    _, admin_key = store.create_api_key(label="k", tenant_id="acme", roles=("admin",))
    _, viewer_key = store.create_api_key(label="k2", tenant_id="acme", roles=("viewer",))
    from c_uas.auth.cli import auth_main

    assert (
        auth_main(
            _namespace(
                check_perm=True,
                key=admin_key,
                route="/engagement/schedule",
                method="POST",
                tenant="acme",
            )
        )
        == 0
    )
    allowed = capsys.readouterr().out
    assert "-> ALLOWED" in allowed

    assert (
        auth_main(
            _namespace(
                check_perm=True,
                key=viewer_key,
                route="/systems",
                method="POST",
                tenant="acme",
            )
        )
        == 0
    )
    denied = capsys.readouterr().out
    assert "-> DENIED" in denied

    assert auth_main(_namespace(check_perm=True, key="bogus", route="/systems", tenant="acme")) == 0
    assert "DENIED (invalid key)" in capsys.readouterr().out


def test_auth_response_type_is_dataclass() -> None:
    from c_uas.auth.models import AuthResponse

    resp = AuthResponse(authorized=True, status_code=200, detail="authorized")
    assert resp.authorized is True
    assert resp.status_code == 200
    assert resp.detail == "authorized"
    assert resp.tenant_context is None
