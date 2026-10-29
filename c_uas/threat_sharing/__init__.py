"""
C-UAS Threat Intelligence Sharing & Community Feeds.

TAXII 2.1-compliant server and STIX 2.1 client for sharing C-UAS threat
indicators across the operator community. Reuses the existing
``c_uas.threat_intel`` STIX bundle export (``STIXBundleBuilder``) and
persists all state under ``~/.c-uas-platform/threat_sharing/`` (outside
the repo).

Public API:
    from c_uas.threat_sharing import (
        TAXIICollection,
        TAXIIManifestEntry,
        CommunityShare,
        SharePolicy,
        build_subparser,
        threat_share_main,
    )

CLI:
    c-uas threat-share --serve
    c-uas threat-share --ingest --feed https://partner.example/taxii2/
    c-uas threat-share --query --collection cuas-indicators
    c-uas threat-share --export --format stix

License: AGPL-3.0. Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

from .cli import build_subparser, threat_share_main
from .sharing import CommunityShare, SharePolicy, ShareTrustLevel
from .taxii_server import TAXIICollection, TAXIIManifestEntry, app_factory

__all__ = [
    "TAXIICollection",
    "TAXIIManifestEntry",
    "CommunityShare",
    "SharePolicy",
    "ShareTrustLevel",
    "build_subparser",
    "threat_share_main",
    "app_factory",
]

__version__ = "0.1.0"
