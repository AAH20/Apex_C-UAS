"""
STIX 2.1 bundle builder for C-UAS threat intelligence.

Converts C-UAS detection events, Ed25519-signed forensic dossiers, and
competitive-landscape intel into STIX 2.1 bundles suitable for TAXII
sharing with broker channels, partners, and SOC operators.

All object IDs are content-addressed (uuid5 over a fixed namespace) so
the same inputs always produce byte-identical bundles. STIX 2.1 objects
are emitted as plain dicts (stdlib json-serializable) -- no external
STIX library required.

Markings use TLP (Traffic Light Protocol) per OASIS STIX 2.1 so
recipients know how broadly they may redistribute each object.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from .models import (
    STIX_NAMESPACE,  # noqa: F401  # re-exported for test import
    CompetitiveIntelEntry,
    DetectionEvent,
    ForensicDossierRef,
    _stix_id,
    _utc_now,
)

# Fixed default timestamp so bundles are fully deterministic by default
# (same inputs -> same output). Callers may override via STIXBundleBuilder(created=...).
DEFAULT_CREATED = "2026-10-23T00:00:00Z"


# TLP marking definitions embedded in every bundle. Statement form per
# STIX 2.1 marking-definition spec.
TLP_MARKINGS: List[Dict[str, Any]] = [
    {
        "type": "marking-definition",
        "id": _stix_id("marking-definition", "tlp-white"),
        "created": "2026-01-01T00:00:00Z",
        "definition_type": "statement",
        "definition": {
            "statement": [
                "Copyright 2026 Apex Growth Systems LLC. "
                "Recipients may redistribute without restriction."
            ]
        },
    },
    {
        "type": "marking-definition",
        "id": _stix_id("marking-definition", "tlp-amber"),
        "created": "2026-01-01T00:00:00Z",
        "definition_type": "tlp",
        "definition": {"tlp": {"label": "AMBER+STRICT"}},
    },
    {
        "type": "marking-definition",
        "id": _stix_id("marking-definition", "tlp-red"),
        "created": "2026-01-01T00:00:00Z",
        "definition_type": "tlp",
        "definition": {"tlp": {"label": "RED"}},
    },
]

_THREAT_ACTOR_ID = _stix_id("intrusion-set", "apex-unknown-uas-operator")
_ATTACK_PATTERN_ID = _stix_id("attack-pattern", "uas-airspace-intrusion")


def _bundle_id(name: str) -> str:
    return _stix_id("bundle", name)


def _indicator_id(suffix: str) -> str:
    return _stix_id("indicator", suffix)


def _observed_id(suffix: str) -> str:
    return _stix_id("observed-data", suffix)


def _severity_marking(threat_level: str) -> str:
    """Map C-UAS threat level to a TLP marking ref."""
    level = (threat_level or "NONE").upper()
    if level in ("CRITICAL", "HIGH"):
        return _stix_id("marking-definition", "tlp-red")
    if level == "MEDIUM":
        return _stix_id("marking-definition", "tlp-amber")
    return _stix_id("marking-definition", "tlp-white")


class STIXBundleBuilder:
    """Build STIX 2.1 bundles from C-UAS threat data."""

    def __init__(self, created: Optional[str] = None) -> None:
        self.created = created or DEFAULT_CREATED
        self.objects: List[Dict[str, Any]] = list(TLP_MARKINGS)
        # Seed the threat actor and attack pattern once per builder.
        self.objects.append(self._threat_actor_object())
        self.objects.append(self._attack_pattern_object())

    # ---- core STIX object factories ---------------------------------
    def _threat_actor_object(self) -> Dict[str, Any]:
        return {
            "type": "intrusion-set",
            "id": _THREAT_ACTOR_ID,
            "created": self.created,
            "modified": self.created,
            "name": "Unknown UAS Operator",
            "labels": ["unknown-actor"],
            "goals": ["unauthorized-airspace-intrusion"],
            "resource_level": "individual",
            "primary_motivation": "ideological",
            "marking_refs": [_stix_id("marking-definition", "tlp-amber")],
        }

    def _attack_pattern_object(self) -> Dict[str, Any]:
        return {
            "type": "attack-pattern",
            "id": _ATTACK_PATTERN_ID,
            "created": self.created,
            "modified": self.created,
            "name": "UAS Airspace Intrusion",
            "description": "Detection and tracking of unauthorized uncrewed "
            "aircraft system activity in controlled airspace.",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"},
                {"kill_chain_name": "mitre-attack", "phase_name": "delivery"},
            ],
            "marking_refs": [_stix_id("marking-definition", "tlp-amber")],
        }

    # ---- detection events -> observed data + indicator --------------
    def add_detection_event(self, event: DetectionEvent) -> str:
        """Add a detection event as STIX observed-data + indicator.

        Returns the observed-data object id.
        """
        oid = _observed_id(f"detect-{event.event_id}")
        level = (event.threat_level or "NONE").upper()

        # STIX observable object (custom x_cuas_detection type).
        observable: Dict[str, Any] = {
            "type": "x_cuas_detection",
            "detection_id": event.event_id,
            "timestamp": event.timestamp,
            "source": event.source,
            "target_id": event.target_id,
            "threat_level": level,
        }
        if event.protocol:
            observable["rf_protocol"] = event.protocol
        if event.confidence is not None:
            observable["confidence"] = event.confidence
        if event.latitude is not None and event.longitude is not None:
            observable["latitude"] = event.latitude
            observable["longitude"] = event.longitude
        if event.anomalies:
            observable["anomalies"] = list(event.anomalies)
        if event.metadata:
            observable["metadata"] = dict(event.metadata)

        observed: Dict[str, Any] = {
            "type": "observed-data",
            "id": oid,
            "created": self.created,
            "modified": self.created,
            "first_observed": event.timestamp,
            "last_observed": event.timestamp,
            "number_observed": 1,
            "objects": {"0": observable},
            "marking_refs": [_severity_marking(event.threat_level)],
        }
        self.objects.append(observed)

        # Indicator for the RF protocol / detection signature.
        pattern_parts: List[str] = [f"[x-cuas-detection:detection_id = '{event.event_id}']"]
        if event.protocol:
            pattern_parts.append(f"AND [x-cuas-detection:rf_protocol = '{event.protocol}']")
        pattern = " ".join(pattern_parts)

        indicator: Dict[str, Any] = {
            "type": "indicator",
            "id": _indicator_id(f"detect-{event.event_id}"),
            "created": self.created,
            "modified": self.created,
            "name": f"Detection: {event.target_id}",
            "description": f"{event.source} detected {event.target_id} at {level} threat level.",
            "pattern_type": "stix",
            "pattern": pattern,
            "valid_from": self.created,
            "labels": ["malicious-activity"],
            "threat_level": level,
            "marking_refs": [_severity_marking(event.threat_level)],
        }
        self.objects.append(indicator)
        return oid

    # ---- forensic dossier -> observed data with Ed25519 marking -----
    def add_forensic_dossier(self, dossier: ForensicDossierRef) -> str:
        """Add an Ed25519-signed forensic dossier as STIX observed-data.

        The Ed25519 signature, public key, and tamper-evident hash are
        carried as custom x_cuas_* properties so the evidence remains
        cryptographically verifiable inside the STIX bundle.

        Returns the observed-data object id.
        """
        oid = _observed_id(f"dossier-{dossier.dossier_id}")

        observable: Dict[str, Any] = {
            "type": "x_cuas_forensic_dossier",
            "dossier_id": dossier.dossier_id,
            "target_id": dossier.target_id,
            "threat_classification": dossier.threat_classification,
            "timestamp_utc": dossier.timestamp_utc,
            "tamper_evident_hash": dossier.tamper_evident_hash,
            "signature": dossier.signature,
            "public_key_pem": dossier.public_key_pem,
            "x_cuas_evidence_type": "ed25519_signed_airspace_dossier",
            "x_cuas_compliance": [
                "FAA_REMOTE_ID_PART_89",
                "DOD_COUNTER_UAS_STD",
                "FAA_PART_107",
            ],
        }

        observed: Dict[str, Any] = {
            "type": "observed-data",
            "id": oid,
            "created": self.created,
            "modified": self.created,
            "first_observed": self.created,
            "last_observed": self.created,
            "number_observed": 1,
            "objects": {"0": observable},
            # Forensic evidence is highly sensitive -> TLP RED.
            "marking_refs": [_stix_id("marking-definition", "tlp-red")],
        }
        self.objects.append(observed)
        return oid

    # ---- competitive intel -> observed data -------------------------
    def add_competitive_intel(self, entry: CompetitiveIntelEntry) -> str:
        """Add a deployed C-UAS system as STIX observed-data (TLP WHITE)."""
        oid = _observed_id(f"comp-{entry.name}")

        observable: Dict[str, Any] = {
            "type": "x_cuas_competitive_system",
            "name": entry.name,
            "origin": entry.origin,
            "developer": entry.developer,
            "system_type": entry.system_type,
            "role": entry.role,
            "public_status": entry.public_status,
            "is_fielded": entry.is_fielded,
        }
        if entry.power_class:
            observable["power_class"] = entry.power_class
        if entry.effective_range_km is not None:
            observable["effective_range_km"] = entry.effective_range_km

        observed: Dict[str, Any] = {
            "type": "observed-data",
            "id": oid,
            "created": self.created,
            "modified": self.created,
            "first_observed": self.created,
            "last_observed": self.created,
            "number_observed": 1,
            "objects": {"0": observable},
            "marking_refs": [_stix_id("marking-definition", "tlp-white")],
        }
        self.objects.append(observed)
        return oid

    # ---- build -------------------------------------------------------
    def build(self) -> Dict[str, Any]:
        """Return the STIX 2.1 bundle dict."""
        bundle: Dict[str, Any] = {
            "type": "bundle",
            "id": _bundle_id("cuas-threat-intel"),
            "spec_version": "2.1",
            "objects": self.objects,
        }
        return bundle

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.build(), indent=2, sort_keys=True)


def detection_event_from_dict(raw: Dict[str, Any]) -> DetectionEvent:
    return DetectionEvent(
        event_id=raw["event_id"],
        timestamp=raw.get("timestamp", _utc_now()),
        source=raw.get("source", "unknown"),
        target_id=raw.get("target_id", "UNKNOWN"),
        threat_level=raw.get("threat_level", "NONE"),
        protocol=raw.get("protocol"),
        confidence=raw.get("confidence"),
        latitude=raw.get("latitude"),
        longitude=raw.get("longitude"),
        anomalies=tuple(raw.get("anomalies", []) or []),
        metadata=dict(raw.get("metadata") or {}),
    )


def forensic_dossier_from_dict(raw: Dict[str, Any]) -> ForensicDossierRef:
    return ForensicDossierRef(
        dossier_id=raw["dossier_id"],
        target_id=raw["target_id"],
        threat_classification=raw.get("threat_classification", "UNKNOWN"),
        signature=raw.get("signature", ""),
        public_key_pem=raw.get("public_key_pem", ""),
        tamper_evident_hash=raw.get("tamper_evident_hash", ""),
        timestamp_utc=float(raw.get("timestamp_utc", time.time())),
    )


def bundle_hash(bundle: Dict[str, Any]) -> str:
    """SHA-256 of the canonical bundle JSON (for integrity checks)."""
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
