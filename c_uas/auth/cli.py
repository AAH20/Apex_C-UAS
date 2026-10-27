"""``c-uas auth`` subcommand: API key and RBAC administration.

Usage:
    c-uas auth --create-key [--label LABEL] [--tenant TENANT] [--role ROLE]...
    c-uas auth --list-keys
    c-uas auth --revoke-key KEY_ID
    c-uas auth --rotate-key KEY_ID
    c-uas auth --check-perm --key KEY --route PATH --method METHOD

All output is deterministic. Keys are derived from a fixed seed with SHA-256
and persisted under ~/.c-uas-platform/auth/keys/ (outside the repo).

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional, Tuple

from .api_keys import (
    APIKey,
    create_key,
    default_key_store,
    list_keys,
    revoke_key,
    rotate_key,
    validate_key,
)
from .models import TenantContext
from .rbac import ROLE_BY_NAME, authorize

_VALID_ROLES = tuple(sorted(ROLE_BY_NAME))

_USAGE = (
    "[C-UAS] auth: specify one of --create-key, --list-keys, "
    "--revoke-key, --rotate-key, --check-perm\n"
    "  c-uas auth --create-key --tenant acme --role operator\n"
    "  c-uas auth --list-keys\n"
    "  c-uas auth --revoke-key <key-id>\n"
    "  c-uas auth --check-perm --key <key> --route /engagement/schedule --method POST"
)


def build_subparser(subparsers: Any) -> Any:
    """Register the ``auth`` subcommand on a parent parser."""
    parser = subparsers.add_parser(
        "auth",
        help="API key and RBAC administration (keys, listing, revocation, permission checks)",
    )
    parser.add_argument(
        "--create-key",
        action="store_true",
        help="Create a deterministic API key (plaintext shown once)",
    )
    parser.add_argument(
        "--label",
        type=str,
        default="default",
        help="Key label (default: default)",
    )
    parser.add_argument(
        "--tenant",
        type=str,
        default="default",
        help="Tenant id for the key (default: default)",
    )
    parser.add_argument(
        "--role",
        type=str,
        default=None,
        help=(f"Role for the key (one of {', '.join(_VALID_ROLES)}, repeatable; default: admin)"),
    )
    parser.add_argument(
        "--list-keys",
        action="store_true",
        help="List persisted keys (metadata only, no hashes)",
    )
    parser.add_argument(
        "--revoke-key",
        type=str,
        default=None,
        help="Revoke the key with this key id",
    )
    parser.add_argument(
        "--rotate-key",
        type=str,
        default=None,
        help="Revoke the key with this key id and issue a replacement",
    )
    parser.add_argument(
        "--check-perm",
        action="store_true",
        help="Check whether a key is authorized for a route/method",
    )
    parser.add_argument(
        "--key",
        type=str,
        default=None,
        help="API key plaintext (for --check-perm)",
    )
    parser.add_argument(
        "--route",
        type=str,
        default=None,
        help="Route path (for --check-perm)",
    )
    parser.add_argument(
        "--method",
        type=str,
        default="GET",
        help="HTTP method (for --check-perm; default: GET)",
    )
    return parser


def _roles_from_args(role_arg: Optional[str]) -> Tuple[str, ...]:
    if role_arg is None:
        return ("admin",)
    roles: Tuple[str, ...] = ()
    for role in role_arg.split(","):
        role = role.strip()
        if role and role not in ROLE_BY_NAME:
            raise ValueError(
                "Unknown role: {!r} (expected one of {})".format(role, ", ".join(_VALID_ROLES))
            )
        roles = roles + (role,)
    return roles


def _format_key(record: APIKey, plain: str) -> str:
    perms = ", ".join(record.permissions) if record.permissions else "none"
    store = default_key_store()
    return "\n".join(
        [
            "[C-UAS] auth: API key created",
            f"  key_id     : {record.key_id}",
            f"  key        : {plain}   (plaintext shown once; SHA-256 hash only is stored)",
            f"  tenant     : {record.tenant_id}",
            f"  label      : {record.label}",
            f"  roles      : {', '.join(record.roles)}",
            f"  permissions: {perms}",
            f"  created_at : {record.created_at}",
            f"  stored at  : {store._dir / (record.key_id + '.json')}",
        ]
    )


def _handle_create_key(args: argparse.Namespace) -> int:
    try:
        roles = _roles_from_args(args.role)
    except ValueError as exc:
        print("[C-UAS] auth: {}".format(exc))
        return 1
    record, plain = create_key(
        label=args.label,
        tenant_id=args.tenant,
        roles=roles,
    )
    print(_format_key(record, plain))
    return 0


def _handle_list_keys() -> int:
    keys = list_keys()
    lines = [f"[C-UAS] auth: {len(keys)} key(s)"]
    for record in keys:
        state = "revoked" if record.revoked else "active"
        perms = ", ".join(record.permissions) if record.permissions else "none"
        lines.append(
            "  {key_id}  tenant={tenant}  roles={roles}  "
            "perms={perms}  {state}  created={created}".format(
                key_id=record.key_id,
                tenant=record.tenant_id,
                roles=",".join(record.roles),
                perms=perms,
                state=state,
                created=record.created_at,
            )
        )
    print("\n".join(lines))
    return 0


def _handle_revoke_key(key_id: str) -> int:
    if revoke_key(key_id):
        print("[C-UAS] auth: key revoked: {}".format(key_id))
        return 0
    print("[C-UAS] auth: key not found: {}".format(key_id))
    return 1


def _handle_rotate_key(key_id: str) -> int:
    result = rotate_key(key_id)
    if result is None:
        print("[C-UAS] auth: key not found: {}".format(key_id))
        return 1
    new_record, plain = result
    print("[C-UAS] auth: key rotated: {} -> {}".format(key_id, new_record.key_id))
    print("  key        : {}   (plaintext shown once)".format(plain))
    return 0


def _handle_check_perm(args: argparse.Namespace) -> int:
    if not args.key or not args.route:
        print("[C-UAS] auth: --key and --route are required for --check-perm")
        return 1
    record = validate_key(args.key)
    if record is None:
        print(
            "[C-UAS] auth: key={} route={} {} -> DENIED (invalid key)".format(
                args.key[:8], args.method, args.route
            )
        )
        return 0
    context = TenantContext(
        tenant_id=record.tenant_id,
        authenticated=True,
        roles=record.roles,
        permissions=record.permissions,
    )
    decision = authorize(context, args.method, args.route, tenant_id=args.tenant)
    verdict = "ALLOWED" if decision.authorized else "DENIED"
    reason = "" if decision.authorized else " ({})".format(decision.detail)
    print(
        "[C-UAS] auth: key={} tenant={} route={} -> {}{}".format(
            record.key_id,
            record.tenant_id,
            args.method + " " + args.route,
            verdict,
            reason,
        )
    )
    return 0


def auth_main(args: argparse.Namespace) -> int:
    if args.create_key:
        return _handle_create_key(args)
    if args.list_keys:
        return _handle_list_keys()
    if args.revoke_key is not None:
        return _handle_revoke_key(args.revoke_key)
    if args.rotate_key is not None:
        return _handle_rotate_key(args.rotate_key)
    if args.check_perm:
        return _handle_check_perm(args)
    print(_USAGE)
    return 1


def main(argv: Optional[list] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="c-uas auth",
        description="API key and RBAC administration for the C-UAS platform",
    )
    build_subparser(parser.add_subparsers(dest="command"))
    args = parser.parse_args(argv)
    return auth_main(args)


if __name__ == "__main__":
    sys.exit(main())
