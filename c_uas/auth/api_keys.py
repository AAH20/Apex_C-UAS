"""Deterministic API key management for the C-UAS platform API.

Keys are generated from a fixed seed with SHA-256 — never the ``secrets``
module — so the same (seed, label, index) always yields the same key.
Only SHA-256 key hashes are persisted; plaintext keys are never written to
disk.

State persists under ~/.c-uas-platform/auth/keys/ (outside the repo), one
JSON file per key. The directory can be overridden with the
CUAS_AUTH_KEYS_DIR environment variable (used by tests).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from .models import APIKey
from .rbac import role_permissions

FIXED_SEED = "c-uas-platform-auth-v1"
DEFAULT_KEYS_DIR = Path.home() / ".c-uas-platform" / "auth" / "keys"
ENV_KEYS_DIR = "CUAS_AUTH_KEYS_DIR"

_KEY_PREFIX = "cuas_live_"
_KEY_ID_PREFIX = "cuas_"
_KEY_ID_HASH_LEN = 32


def hash_key(key: str) -> str:
    """SHA-256 hash of an API key (salted with the fixed seed)."""
    return hashlib.sha256(f"{FIXED_SEED}|{key}".encode("utf-8")).hexdigest()


def generate_api_key(seed: str = FIXED_SEED, label: str = "default", index: int = 0) -> str:
    """Deterministically derive an API key from (seed, label, index).

    Same inputs always yield the same key. No ``secrets`` module randomness
    is involved.
    """
    digest = hashlib.sha256(f"{seed}|{label}|{index}".encode("utf-8")).hexdigest()
    return f"{_KEY_PREFIX}{digest}"


def derive_key_id(key: str) -> str:
    """Deterministic key id derived from the key itself."""
    return f"{_KEY_ID_PREFIX}{hash_key(key)[:_KEY_ID_HASH_LEN]}"


def default_key_store() -> "KeyStore":
    """Open the key store from CUAS_AUTH_KEYS_DIR or the default location."""
    return KeyStore(os.environ.get(ENV_KEYS_DIR))


class KeyStore:
    """File-backed key store: one JSON record per key under ``keys_dir``."""

    def __init__(self, keys_dir: Optional[str] = None) -> None:
        if keys_dir is None:
            keys_dir = os.environ.get(ENV_KEYS_DIR) or str(DEFAULT_KEYS_DIR)
        self._dir = Path(keys_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key_id: str) -> Path:
        return self._dir / f"{key_id}.json"

    def _list_files(self) -> List[Path]:
        return sorted(p for p in self._dir.glob("*.json") if p.is_file())

    def _next_index(self) -> int:
        return len(self._list_files()) + 1

    def load(self, key_id: str) -> Optional[APIKey]:
        path = self._path(key_id)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        return APIKey(
            key_id=str(data["key_id"]),
            key_hash=str(data["key_hash"]),
            label=str(data["label"]),
            tenant_id=str(data["tenant_id"]),
            roles=tuple(str(r) for r in data.get("roles", ())),
            permissions=tuple(str(p) for p in data.get("permissions", ())),
            created_at=str(data.get("created_at", "")),
            expires_at=data.get("expires_at"),
            revoked=bool(data.get("revoked", False)),
        )

    def save(self, record: APIKey) -> None:
        path = self._path(record.key_id)
        path.write_text(
            json.dumps(asdict(record), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def has_any_keys(self) -> bool:
        return any(self._list_files())

    def list_keys(self) -> List[APIKey]:
        records: List[APIKey] = []
        for path in self._list_files():
            record = self.load(path.stem)
            if record is not None:
                records.append(record)
        return sorted(records, key=lambda r: r.key_id)

    def create_api_key(
        self,
        label: str = "default",
        tenant_id: str = "default",
        roles: Tuple[str, ...] = ("admin",),
        seed: str = FIXED_SEED,
    ) -> Tuple[APIKey, str]:
        """Create a persisted key; returns (record, plaintext key).

        Permissions are derived from roles via RBAC. The plaintext key is
        returned once and never stored.
        """
        for role_name in roles:
            if role_name not in ("admin", "operator", "viewer", "auditor"):
                raise ValueError(f"Unknown role: {role_name}")
        permissions: Tuple[str, ...] = ()
        for role_name in roles:
            permissions = tuple(dict.fromkeys(permissions + role_permissions(role_name)))
        index = self._next_index()
        plain = generate_api_key(seed=seed, label=label, index=index)
        key_id = derive_key_id(plain)
        now = datetime.now(timezone.utc).isoformat()
        record = APIKey(
            key_id=key_id,
            key_hash=hash_key(plain),
            label=label,
            tenant_id=tenant_id,
            roles=roles,
            permissions=permissions,
            created_at=now,
            expires_at=None,
            revoked=False,
        )
        self.save(record)
        return record, plain

    def validate_key(self, key: str) -> Optional[APIKey]:
        record = self.load(derive_key_id(key))
        if record is None or record.revoked:
            return None
        if record.key_hash != hash_key(key):
            return None
        if record.expires_at is not None:
            try:
                expires = datetime.fromisoformat(record.expires_at)
            except ValueError:
                return None
            if datetime.now(timezone.utc) > expires:
                return None
        return record

    def revoke_key(self, key_id: str) -> bool:
        record = self.load(key_id)
        if record is None or record.revoked:
            return False
        from dataclasses import replace

        self.save(replace(record, revoked=True))
        return True

    def rotate_key(
        self,
        key_id: str,
        seed: str = FIXED_SEED,
    ) -> Optional[Tuple[APIKey, str]]:
        """Revoke ``key_id`` and issue a replacement with the same identity.

        Returns (new_record, plaintext) or None when the key does not exist.
        """
        record = self.load(key_id)
        if record is None:
            return None
        self.revoke_key(key_id)
        new_record, plain = self.create_api_key(
            label=f"{record.label}-rotated",
            tenant_id=record.tenant_id,
            roles=record.roles,
            seed=seed,
        )
        return new_record, plain


# ---------------------------------------------------------------------------
# Module-level helpers over the default store
# ---------------------------------------------------------------------------


def create_key(
    label: str = "default",
    tenant_id: str = "default",
    roles: Tuple[str, ...] = ("admin",),
    seed: str = FIXED_SEED,
) -> Tuple[APIKey, str]:
    return default_key_store().create_api_key(
        label=label, tenant_id=tenant_id, roles=roles, seed=seed
    )


def validate_key(key: str) -> Optional[APIKey]:
    return default_key_store().validate_key(key)


def revoke_key(key_id: str) -> bool:
    return default_key_store().revoke_key(key_id)


def rotate_key(key_id: str, seed: str = FIXED_SEED) -> Optional[Tuple[APIKey, str]]:
    return default_key_store().rotate_key(key_id, seed=seed)


def list_keys() -> List[APIKey]:
    return default_key_store().list_keys()


def has_any_keys() -> bool:
    return default_key_store().has_any_keys()
