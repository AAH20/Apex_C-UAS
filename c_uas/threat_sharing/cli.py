"""
``c-uas threat-share`` subcommand: threat intelligence sharing & feeds.

Usage:
    c-uas threat-share --serve
    c-uas threat-share --ingest --feed <url>
    c-uas threat-share --query [--collection <id>] [--type <type>]
    c-uas threat-share --export --partner <name> [--level trusted] [--format stix]

All output is deterministic: same inputs -> same output, sorted object
ordering, fixed seed. State persists under
``~/.c-uas-platform/threat_sharing/`` (outside the repo).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List, Optional, Sequence

from .feed_client import (
    DEFAULT_MIN_CONFIDENCE,
    DEFAULT_MIN_RELEVANCE,
    ingest_feed,
)
from .sharing import (
    CommunityShare,
    SharePolicy,
    ShareTrustLevel,
    export_bundle,
)
from .taxii_server import app_factory


def build_subparser(subparsers: Any) -> Any:
    """Register the ``threat-share`` subcommand on a parent parser."""
    parser = subparsers.add_parser(
        "threat-share",
        help="Threat intelligence sharing & community feeds (TAXII 2.1 / STIX 2.1)",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Run the TAXII 2.1 sharing server",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Bind host for --serve",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8002,
        help="Bind port for --serve",
    )
    parser.add_argument(
        "--ingest",
        action="store_true",
        help="Ingest a STIX bundle from a remote TAXII feed",
    )
    parser.add_argument(
        "--feed",
        type=str,
        default=None,
        help="Remote TAXII 2.1 collection objects URL for --ingest",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MIN_CONFIDENCE,
        help="Minimum confidence (0.0-1.0) for ingested indicators",
    )
    parser.add_argument(
        "--min-relevance",
        type=float,
        default=DEFAULT_MIN_RELEVANCE,
        help="Minimum relevance (0.0-1.0) for ingested indicators",
    )
    parser.add_argument(
        "--query",
        action="store_true",
        help="Query the local TAXII collection manifest/objects",
    )
    parser.add_argument(
        "--collection",
        type=str,
        default=None,
        help="Collection id to query/export (default: cuas-indicators)",
    )
    parser.add_argument(
        "--type",
        type=str,
        default=None,
        help="Filter objects by STIX type (e.g. indicator)",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export a STIX 2.1 bundle to a partner",
    )
    parser.add_argument(
        "--partner",
        type=str,
        default=None,
        help="Partner organisation name for --export",
    )
    parser.add_argument(
        "--level",
        type=str,
        default="trusted",
        help="Partner trust level (untrusted/trusted/allied)",
    )
    parser.add_argument(
        "--format",
        type=str,
        default="stix",
        help="Export format: stix (default) or json",
    )
    return parser


def _default_partners() -> List[ShareTrustLevel]:
    return [
        ShareTrustLevel("untrusted", "tlp-white"),
        ShareTrustLevel("trusted", "tlp-amber"),
        ShareTrustLevel("allied", "tlp-red"),
    ]


def _render_shares(shares: List[CommunityShare]) -> str:
    lines = ["[C-UAS] Community Shares", "=" * 44]
    for share in sorted(shares, key=lambda s: s.share_id):
        lines.append("Share ID   : %s" % share.share_id)
        lines.append("Partner    : %s" % share.partner)
        lines.append("Trust      : %s" % share.partner_trust_level)
        lines.append("Bundle ID  : %s" % share.bundle_id)
        lines.append("Objects    : %d" % len(share.object_ids))
        lines.append("Markings   : %s" % ", ".join(share.marking_refs) or "(none)")
        lines.append("-")
    return "\n".join(lines)


def threat_share_main(args: argparse.Namespace) -> int:
    """Handle the ``threat-share`` subcommand from a parsed namespace."""
    if args.serve:
        import uvicorn  # type: ignore

        app = app_factory()
        print("[C-UAS] TAXII 2.1 sharing server on %s:%s" % (args.host, args.port))
        print("  Discovery: http://%s:%s/taxii2/" % (args.host, args.port))
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    if args.ingest:
        if not args.feed:
            print("[C-UAS] --feed required for --ingest")
            return 1

        def _get(url: str) -> Any:
            import httpx  # type: ignore

            resp = httpx.get(url, timeout=10.0)
            resp.raise_for_status()
            return resp

        from .taxii_server import _load_objects

        existing = [o.get("id", "") for o in _load_objects()]
        result = ingest_feed(
            args.feed,
            existing,
            _get,
            min_confidence=args.min_confidence,
            min_relevance=args.min_relevance,
        )
        print("[C-UAS] Feed Ingest: %s" % args.feed)
        print("  Received   : %d" % result.objects_received)
        print("  Ingested   : %d" % result.objects_ingested)
        print("  Duplicates : %d" % result.duplicates_skipped)
        print("  Filtered   : %d" % result.filtered_out)
        print("  SHA-256    : %s" % result.sha256)
        if result.ingested_ids:
            print("  Ids        : %s" % ", ".join(result.ingested_ids))
        return 0

    if args.query:
        collection_id = args.collection or "cuas-indicators"
        app = app_factory()
        with _test_client(app) as client:
            resp = client.get("/taxii2/collections/%s/manifest/" % collection_id)
            if resp.status_code == 404:
                print("[C-UAS] Collection not found: %s" % collection_id)
                return 1
            manifest = resp.json()
            objects = manifest.get("objects", [])
            if args.type:
                objects = [o for o in objects if o.get("type") == args.type]
            print("[C-UAS] Collection: %s (%d objects)" % (collection_id, len(objects)))
            for entry in objects:
                print("  %s  %s  v%s" % (entry.get("id"), entry.get("type"), entry.get("version")))
        return 0

    if args.export:
        if not args.partner:
            print("[C-UAS] --partner required for --export")
            return 1
        from .taxii_server import _load_objects

        objects = _load_objects()
        if args.type:
            objects = [o for o in objects if o.get("type") == args.type]
        policy = SharePolicy(trust_levels=tuple(_default_partners()))
        bundle, denied = export_bundle(
            objects,
            args.partner,
            args.level,
            policy=policy,
        )
        print("[C-UAS] Export to %s (level=%s)" % (args.partner, args.level))
        print("  Bundle ID : %s" % bundle.get("id"))
        print("  Objects   : %d" % len(bundle.get("objects", [])))
        print("  Denied    : %d" % len(denied))
        if denied:
            print("  Denied ids: %s" % ", ".join(denied))
        if args.format == "json":
            print(json.dumps(bundle, indent=2, sort_keys=True))
        else:
            # STIX compact rendering (deterministic).
            print(json.dumps(bundle, sort_keys=True, separators=(",", ":")))
        return 0

    print("[C-UAS] threat-share: specify --serve, --ingest, --query, or --export")
    print("  c-uas threat-share --serve")
    print("  c-uas threat-share --ingest --feed <url>")
    print("  c-uas threat-share --query")
    print("  c-uas threat-share --export --partner <name> --level trusted")
    return 1


def _test_client(app: Any) -> Any:
    from fastapi.testclient import TestClient

    return TestClient(app)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Standalone entry point: ``python -m c_uas.threat_sharing.cli``."""
    parser = argparse.ArgumentParser(prog="c-uas threat-share")
    build_subparser(parser.add_subparsers(dest="command"))
    args = parser.parse_args(argv)
    return threat_share_main(args)


if __name__ == "__main__":
    sys.exit(main())
