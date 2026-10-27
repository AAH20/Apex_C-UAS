"""``c-uas k8s`` subcommand: declarative C-UAS platform deployment on Kubernetes.

Subcommands
-----------
``c-uas k8s --manifests``
    Render deterministic Kubernetes manifests (Deployment, Service, ConfigMap,
    NetworkPolicy, PodDisruptionBudget, ResourceQuota) from a spec.
``c-uas k8s --dry-run``
    Run reconciliation without persisting state; print drift and manifests.
``c-uas k8s --reconcile``
    Run reconciliation and persist last state under
    ``~/.c-uas-platform/k8s_operator/``.

All output is deterministic: identical inputs produce identical output.

License: AGPL-3.0.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional, Sequence

from .custom_resource import (
    DEFAULT_STATE_DIR,
    CUASPlatformSpec,
)
from .manifests import generate_all_manifests, manifests_to_yaml
from .reconciler import ReconciliationResult, reconcile


def build_subparser(subparsers: Any) -> Any:
    """Register the ``k8s`` subcommand on a parent parser (e.g. c_uas.cli)."""
    parser = subparsers.add_parser(
        "k8s",
        help=(
            "Kubernetes operator: declarative deployment and lifecycle "
            "management of the C-UAS platform (manifest generation only, "
            "no cluster access)"
        ),
    )
    parser.add_argument(
        "--name",
        type=str,
        default="cuas-platform",
        help="Resource / deployment name (default: cuas-platform)",
    )
    parser.add_argument(
        "--namespace",
        type=str,
        default="cuas-system",
        help="Target Kubernetes namespace (default: cuas-system)",
    )
    parser.add_argument(
        "--replicas",
        type=int,
        default=3,
        help="Desired replica count (default: 3)",
    )
    parser.add_argument(
        "--image",
        type=str,
        default="ghcr.io/aah20/c-uas-platform:latest",
        help="Container image (default: ghcr.io/aah20/c-uas-platform:latest)",
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable authentication (default: enabled)",
    )
    parser.add_argument(
        "--module",
        action="append",
        default=None,
        help="Module to enable (repeatable; default: detection,tracking,engagement,forensics)",
    )
    parser.add_argument(
        "--manifests",
        action="store_true",
        help="Render deterministic Kubernetes manifests and print them",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run reconciliation without persisting state (print drift + manifests)",
    )
    parser.add_argument(
        "--reconcile",
        action="store_true",
        help="Run reconciliation and persist last reconciled state",
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default=None,
        help="Operator state dir (default: ~/.c-uas-platform/k8s_operator/)",
    )
    parser.add_argument(
        "--no-mtls",
        action="store_true",
        help="Disable mTLS annotations on the NetworkPolicy",
    )
    return parser


def _build_spec(args: argparse.Namespace) -> CUASPlatformSpec:
    modules = tuple(args.module) if args.module else None
    return CUASPlatformSpec(
        replicas=args.replicas,
        image=args.image,
        auth_enabled=not args.no_auth,
        modules_enabled=modules if modules else CUASPlatformSpec.modules_enabled,
    )


def _render_manifests(spec: CUASPlatformSpec, args: argparse.Namespace) -> str:
    manifests = generate_all_manifests(
        spec,
        namespace=args.namespace,
        name=args.name,
        with_mTLS=not args.no_mtls,
    )
    return manifests_to_yaml(manifests)


def handle_manifests(args: argparse.Namespace) -> int:
    spec = _build_spec(args)
    print(_render_manifests(spec, args))
    return 0


def handle_dry_run(args: argparse.Namespace) -> int:
    spec = _build_spec(args)
    result: ReconciliationResult = reconcile(
        spec,
        namespace=args.namespace,
        name=args.name,
        dry_run=True,
        state_dir=args.state_dir or DEFAULT_STATE_DIR,
    )
    print("[C-UAS] k8s dry-run (no state persisted)")
    print(f"  name        : {result.resource.name}")
    print(f"  namespace   : {result.resource.namespace}")
    print(f"  replicas    : {result.resource.spec.replicas}")
    print(f"  image       : {result.resource.spec.image}")
    print(f"  auth_enabled: {result.resource.spec.auth_enabled}")
    print(f"  modules     : {', '.join(result.resource.spec.modules_enabled)}")
    print(f"  drift entries: {len(result.drift)}")
    for entry in result.drift:
        print(f"    - {entry.field}: desired={entry.desired!r} observed={entry.observed!r}")
    print(f"  changed     : {result.changed}")
    print(f"  applied     : {result.applied}")
    print("--- manifests ---")
    print(result.manifests_yaml)
    return 0


def handle_reconcile(args: argparse.Namespace) -> int:
    spec = _build_spec(args)
    result: ReconciliationResult = reconcile(
        spec,
        namespace=args.namespace,
        name=args.name,
        dry_run=False,
        state_dir=args.state_dir or DEFAULT_STATE_DIR,
    )
    print("[C-UAS] k8s reconcile (state persisted)")
    print(f"  name        : {result.resource.name}")
    print(f"  namespace   : {result.resource.namespace}")
    print(f"  phase       : {result.resource.status.phase}")
    print(f"  replicas_ready: {result.resource.status.replicas_ready}")
    print(f"  drift entries: {len(result.drift)}")
    for entry in result.drift:
        print(f"    - {entry.field}: desired={entry.desired!r} observed={entry.observed!r}")
    print(f"  changed     : {result.changed}")
    print(f"  applied     : {result.applied}")
    print(f"  state_dir   : {args.state_dir or DEFAULT_STATE_DIR}")
    print("--- manifests ---")
    print(result.manifests_yaml)
    return 0


def k8s_main(args: argparse.Namespace) -> int:
    """Dispatch the ``k8s`` subcommand from an already-parsed namespace."""
    if args.manifests:
        return handle_manifests(args)
    if args.dry_run:
        return handle_dry_run(args)
    if args.reconcile:
        return handle_reconcile(args)
    print("[C-UAS] k8s: specify --manifests, --dry-run, or --reconcile")
    print("  c-uas k8s --manifests")
    print("  c-uas k8s --dry-run --replicas 5")
    print("  c-uas k8s --reconcile")
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Standalone entry point: ``python -m c_uas.k8s_operator.cli``."""
    parser = argparse.ArgumentParser(
        prog="c-uas k8s",
        description="Kubernetes operator for the C-UAS platform",
    )
    subparsers = parser.add_subparsers(dest="command")
    build_subparser(subparsers)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 1
    return k8s_main(args)


if __name__ == "__main__":
    sys.exit(main())
