"""
STIX/TAXII threat intelligence data models for the C-UAS platform.

Defines dataclasses for detection events, forensic dossier references,
competitive intel entries, alerts, and alert channels. All types are
frozen dataclasses so they are hashable and safe to persist as JSON.

Pure Python + cryptography. Deterministic: same inputs produce identical
objects (content-addressed IDs via uuid5).
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Fixed STIX namespace so every object ID is content-addressed and
# deterministic across runs/sessions. Never changes.
STIX_NAMESPACE = uuid.UUID("6f3d8c2e-1a4b-4c9d-8e7f-2a3b4c5d6e7f")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stix_id(obj_type: str, name: str) -> str:
    """Content-addressed STIX ID: <type>--<uuid5>."""
    return f"{obj_type}--{uuid.uuid5(STIX_NAMESPACE, name)}"


@dataclass(frozen=True)
class DetectionEvent:
    """A single detection event from the C-UAS detection pipeline."""

    event_id: str
    timestamp: str
    source: str  # e.g. "rf_classifier", "spoof_detector", "controller_locator"
    target_id: str
    threat_level: str  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    protocol: Optional[str] = None
    confidence: Optional[float] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    anomalies: Tuple[str, ...] = field(default_factory=tuple)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ForensicDossierRef:
    """Reference to an Ed25519-signed forensic dossier (c_uas.forensics)."""

    dossier_id: str
    target_id: str
    threat_classification: str
    signature: str  # Ed25519 hex signature
    public_key_pem: str
    tamper_evident_hash: str
    timestamp_utc: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CompetitiveIntelEntry:
    """A deployed C-UAS system from the competitive landscape database."""

    name: str
    origin: str
    developer: str
    system_type: str
    power_class: Optional[str]
    effective_range_km: Optional[float]
    role: str
    public_status: str
    is_fielded: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Alert:
    """A real-time alert emitted by the AlertEngine."""

    alert_id: str
    timestamp: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    event_type: str  # e.g. "spoof_detection", "high_confidence_track", "incident"
    message: str
    source: str
    target_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ChannelConfig:
    """Configuration for a single alert delivery channel."""

    kind: str  # console, webhook, email
    enabled: bool = True
    webhook_url: Optional[str] = None
    email_to: Optional[str] = None  # stub only; log-only, no SMTP

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AlertRule:
    """A rule that triggers an alert when matched."""

    rule_id: str
    event_type: str
    min_severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
