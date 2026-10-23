"""
C-UAS Threat Intelligence — STIX 2.1 export, TAXII 2.1 sharing,
and real-time alerting.

Standards-based sharing of drone threat intelligence with broker
channels, partners, and SOC operators, plus real-time alerting for
critical events (spoof detection, high-confidence tracks, incidents,
compliance drops).

Public API:
    from c_uas.threat_intel import (
        STIXBundleBuilder, DetectionEvent, ForensicDossierRef,
        CompetitiveIntelEntry, AlertEngine, Alert, ChannelConfig,
        AlertRule, ThreatIntelStore, ConsoleChannel, WebhookChannel,
        EmailStubChannel,
    )

All persisted data lives under ~/.c-uas-platform/threat_intel/
(outside the repo).

CLI:
    c-uas threat-intel --export
    c-uas threat-intel --serve
    c-uas threat-intel --alert
    c-uas threat-intel --test
"""

from __future__ import annotations

from .alert_engine import (
    Alert,
    AlertEngine,
    AlertRule,
    Channel,
    ChannelConfig,
    ConsoleChannel,
    EmailStubChannel,
    WebhookChannel,
)
from .models import (
    CompetitiveIntelEntry,
    DetectionEvent,
    ForensicDossierRef,
    STIX_NAMESPACE,
)
from .store import ThreatIntelStore
from .stix_builder import (
    STIXBundleBuilder,
    bundle_hash,
    detection_event_from_dict,
    forensic_dossier_from_dict,
)
from .taxii_server import app_factory

__all__ = [
    "STIXBundleBuilder",
    "DetectionEvent",
    "ForensicDossierRef",
    "CompetitiveIntelEntry",
    "Alert",
    "AlertEngine",
    "AlertRule",
    "Channel",
    "ChannelConfig",
    "ConsoleChannel",
    "WebhookChannel",
    "EmailStubChannel",
    "ThreatIntelStore",
    "app_factory",
    "bundle_hash",
    "detection_event_from_dict",
    "forensic_dossier_from_dict",
    "STIX_NAMESPACE",
]

__version__ = "0.1.0"
