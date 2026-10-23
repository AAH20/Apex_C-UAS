"""
Automated Compliance Evidence Collection — ISO 42001.

Continuously collects, signs, and packages evidence from all platform
components for ISO 42001 audits and regulatory compliance.

Components
----------
- EvidenceCollector : pull evidence from detection, tracking, engagement,
  forensics, governance records, threat intel exports, broker campaigns,
  and edge node health.
- EvidencePackageManager : bundle collected evidence into signed, timestamped
  packages (Ed25519 signing, SHA-256 content addressing).
- AuditTrailGenerator : audit trails showing who did what, when, and with
  what evidence.
- ComplianceReporter : map collected evidence to ISO 42001 Annex A controls
  (A.5.1 through A.11.1).
- EvidenceExport : export packages as JSON or ZIP with manifest.

All state is persisted to ~/.c-uas-platform/compliance/ (outside the repo).
Deterministic: content-addressed IDs, fixed timestamps, same input produces
the same signed package.

Defensive-only: compliance for defensive C-UAS AI. No weapons-employment
effector, no live SDR, no exploitation code.

Usage
-----
    from c_uas.compliance import (
        EvidenceCollector,
        EvidencePackageManager,
        AuditTrailGenerator,
        ComplianceReporter,
        EvidenceExport,
    )

    collector = EvidenceCollector()
    records = collector.collect()                       # List[EvidenceRecord]

    manager = EvidencePackageManager()
    package = manager.package(records)                  # signed EvidencePackage

    trail = AuditTrailGenerator().build(records)        # who did what, when

    reporter = ComplianceReporter()
    report = reporter.generate(records)                 # Annex A mapping

    EvidenceExport().to_json(package, path)             # or to_zip(...)

CLI
---
    c-uas compliance --collect
    c-uas compliance --package
    c-uas compliance --export --format json --out /tmp/pkg.json
    c-uas compliance --report
"""

from __future__ import annotations

import hashlib
import json
import time
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Persistent storage outside the repo — compliance state survives repo rebuilds.
_COMPLIANCE_DIR = Path.home() / ".c-uas-platform" / "compliance"
_EVIDENCE_FILE = _COMPLIANCE_DIR / "collected_evidence.json"
_PACKAGES_FILE = _COMPLIANCE_DIR / "evidence_packages.json"
_TRAILS_FILE = _COMPLIANCE_DIR / "audit_trails.json"
_KEY_FILE = _COMPLIANCE_DIR / "signing_key.pem"

# Source component state directories (outside the repo). Module-level so tests
# can monkeypatch them to isolated temp dirs (c_uas.grc_clab convention).
_GOV_DIR = Path.home() / ".c-uas-platform" / "governance"
_GRC_DIR = Path.home() / ".c-uas-platform" / "grc_clab"
_TI_DIR = Path.home() / ".c-uas-platform" / "threat_intel"
_BRK_DIR = Path.home() / ".c-uas-platform" / "broker"
_EDGE_ROOT = Path.home() / ".c-uas-platform" / "edge"

# ISO 42001 Annex A controls relevant to agentic C-UAS AI systems.
ISO_42001_ANNEX_A_CONTROLS: List[str] = [
    "A.5.1",  # AI policy
    "A.5.2",  # AI system inventory
    "A.6.1",  # Roles and responsibilities
    "A.7.1",  # AI risk assessment process
    "A.8.1",  # Data governance
    "A.8.2",  # Input validation
    "A.8.3",  # Output verification
    "A.9.1",  # Monitoring and measurement
    "A.10.1", # Incident management
    "A.11.1", # Third-party AI
]

# Evidence sources the collector ingests, keyed by component domain.
EVIDENCE_SOURCES: Dict[str, str] = {
    "detection": "RF signal classification / GNSS spoofing detection events",
    "tracking": "EKF trajectory prediction and intercept estimation",
    "engagement": "NP-hard engagement scheduling and fire control",
    "forensics": "Ed25519-signed airspace intrusion dossiers",
    "governance": "ISO 42001 AI system registry, risks, controls, incidents",
    "threat_intel": "STIX/TAXII threat intelligence exports and alerts",
    "broker": "Broker Channel OS tenant, slot, and campaign records",
    "edge": "Edge node health, detection queues, sync state",
}

GENESIS_HASH = "0" * 64


def _ensure_dir() -> None:
    _COMPLIANCE_DIR.mkdir(parents=True, exist_ok=True)


def _load_json(path: Path) -> list:
    _ensure_dir()
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save_json(path: Path, data: list) -> None:
    _ensure_dir()
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


def _canonical(obj: Any) -> str:
    """Canonical JSON encoding for content addressing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _content_id(prefix: str, payload: Dict[str, Any]) -> str:
    """Content-addressed ID: sha256(prefix + canonical payload)."""
    return f"{prefix}-{_sha256_hex(_canonical(payload))[:16]}"


# --------------------------------------------------------------------------- #
# Signing key (Ed25519) — generated once, persisted outside the repo.
# --------------------------------------------------------------------------- #


def _load_signing_key() -> tuple:
    """Load or generate the Ed25519 package signing key.

    Returns the private key and the public key PEM bytes.
    """
    _ensure_dir()
    if _KEY_FILE.exists():
        try:
            private_key = serialization.load_pem_private_key(
                _KEY_FILE.read_bytes(), password=None
            )
            public_pem = private_key.public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
            return private_key, public_pem
        except (ValueError, OSError):
            pass  # fall through to regenerate
    private_key = ed25519.Ed25519PrivateKey.generate()
    _KEY_FILE.write_bytes(
        private_key.private_bytes(
            Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_pem


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EvidenceRecord:
    """One collected evidence record, content-addressed by its payload."""

    evidence_id: str          # content-addressed: ev-<sha256>
    source: str               # detection | tracking | engagement | forensics | governance | threat_intel | broker | edge
    component: str            # owning platform component, e.g. c_uas.api
    event_type: str           # e.g. rf_classification, control_implementation
    timestamp: float          # deterministic collection timestamp
    collected_at: float       # wall-clock when the record was collected
    payload: Dict[str, Any]   # the actual evidence

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidencePackage:
    """Signed, timestamped package bundling collected evidence."""

    package_id: str           # content-addressed: pkg-<sha256>
    timestamp: float          # fixed package timestamp (deterministic)
    evidence_ids: List[str]   # ids of records bundled in this package
    evidence_count: int
    signature: str            # Ed25519 signature over package canonical bytes
    public_key_pem: str       # signer public key (PEM)
    prev_package_id: Optional[str]  # hash-link to previous package
    manifest: Dict[str, Any]  # per-source evidence breakdown

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuditTrailEntry:
    """One audit trail step: actor, action, when, evidence referenced."""

    step_id: str
    timestamp: float
    actor: str                # component or CLI user that produced the evidence
    action: str               # e.g. collected, packaged, exported, reported
    target: str               # component or record id acted upon
    evidence_ids: List[str]   # evidence referenced by this step
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ComplianceMapping:
    """Mapping of one Annex A control to the evidence that supports it."""

    control_id: str           # A.5.1 ... A.11.1
    title: str
    applicable: bool
    evidence_ids: List[str]
    evidence_count: int
    satisfied: bool           # at least one supporting evidence record exists
    gap_note: Optional[str]   # why a control is not yet satisfied

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ComplianceReport:
    """ISO 42001 compliance report mapping evidence to Annex A controls."""

    generated_at: float
    package_id: Optional[str]
    total_evidence: int
    controls: List[ComplianceMapping]
    satisfied_controls: int
    total_controls: int
    coverage_percentage: float
    overall_status: str       # compliant | partial | non_compliant

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def _iso_control_title(control_id: str) -> str:
    titles = {
        "A.5.1": "AI policy",
        "A.5.2": "AI system inventory",
        "A.6.1": "Roles and responsibilities",
        "A.7.1": "AI risk assessment process",
        "A.8.1": "Data governance",
        "A.8.2": "Input validation",
        "A.8.3": "Output verification",
        "A.9.1": "Monitoring and measurement",
        "A.10.1": "Incident management",
        "A.11.1": "Third-party AI",
    }
    return titles.get(control_id, "Annex A control")


_DEFAULT_TIMESTAMP = 1_777_000_000.0  # 2026-04-22T12:26:40Z, deterministic reference


# --------------------------------------------------------------------------- #
# EvidenceCollector
# --------------------------------------------------------------------------- #


class EvidenceCollector:
    """Collect evidence from every platform component.

    Pulls persisted state from:
      - governance        (~/.c-uas-platform/governance/)
      - grc_clab          (~/.c-uas-platform/grc_clab/)
      - threat_intel      (~/.c-uas-platform/threat_intel/)
      - broker            (~/.c-uas-platform/broker/)
      - edge              (~/.c-uas-platform/edge/)

    State locations are computed at call time so tests can monkeypatch
    Path.home or set C_UAS_* env vars, following the c_uas.grc_clab convention.
    """

    def __init__(self, timestamp: Optional[float] = None) -> None:
        self._timestamp = timestamp if timestamp is not None else time.time()
        self._records: List[EvidenceRecord] = []

    # -- collection per source ----------------------------------------------

    def _collect_dir_json(
        self, source: str, component: str, event_type: str, path: Path
    ) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        if not path.exists():
            return records
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return records
        if not isinstance(data, list):
            if isinstance(data, dict):
                data = [data]  # a single record object is treated as one-item list
            else:
                return records
        for row in data:
            if not isinstance(row, dict):
                continue
            payload = {"record": row, "source_file": path.name}
            rec = EvidenceRecord(
                evidence_id=_content_id("ev", payload),
                source=source,
                component=component,
                event_type=event_type,
                timestamp=self._timestamp,
                collected_at=self._timestamp,
                payload=payload,
            )
            records.append(rec)
        return records

    def _collect_governance(self) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        for name in ("ai_systems", "risks", "controls", "evidence", "incidents"):
            records.extend(
                self._collect_dir_json(
                    "governance", "c_uas.governance", name, _GOV_DIR / f"{name}.json"
                )
            )
        return records

    def _collect_grc_clab(self) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        for name in (
            "scan_logs",
            "auto_evidence",
            "compliance_snapshots",
            "drift_alerts",
            "remediation_plans",
        ):
            records.extend(
                self._collect_dir_json(
                    "governance", "c_uas.grc_clab", name, _GRC_DIR / f"{name}.json"
                )
            )
        return records

    def _collect_threat_intel(self) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        for name in ("bundles", "alerts", "channels"):
            records.extend(
                self._collect_dir_json(
                    "threat_intel", "c_uas.threat_intel", name, _TI_DIR / f"{name}.json"
                )
            )
        return records

    def _collect_broker(self) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        for name in ("tenants", "slots", "campaigns"):
            records.extend(
                self._collect_dir_json(
                    "broker", "c_uas.broker", name, _BRK_DIR / f"{name}.json"
                )
            )
        return records

    def _collect_edge(self) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []
        edge_root = _EDGE_ROOT
        if not edge_root.exists():
            return records
        for node_dir in sorted(edge_root.iterdir()):
            if not node_dir.is_dir():
                continue
            for name in ("health", "detections", "sync"):
                path = node_dir / f"{name}.json"
                if not path.exists():
                    continue
                records.extend(
                    self._collect_dir_json(
                        "edge",
                        f"c_uas.edge.{node_dir.name}",
                        name,
                        node_dir / f"{name}.json",
                    )
                )
        return records

    # -- public API ----------------------------------------------------------

    def collect(self) -> List[EvidenceRecord]:
        """Collect evidence from all platform components.

        Returns the combined list of EvidenceRecord objects and persists them
        to ~/.c-uas-platform/compliance/collected_evidence.json.
        """
        self._records = []
        self._records.extend(self._collect_governance())
        self._records.extend(self._collect_grc_clab())
        self._records.extend(self._collect_threat_intel())
        self._records.extend(self._collect_broker())
        self._records.extend(self._collect_edge())

        # De-duplicate by evidence_id while preserving first-seen order.
        seen: Set[str] = set()
        unique: List[EvidenceRecord] = []
        for rec in self._records:
            if rec.evidence_id in seen:
                continue
            seen.add(rec.evidence_id)
            unique.append(rec)
        self._records = unique

        existing = _load_json(_EVIDENCE_FILE)
        existing_ids: Set[str] = {
            row.get("evidence_id")
            for row in existing
            if isinstance(row, dict) and row.get("evidence_id") is not None
        }
        to_append = [
            rec.to_dict()
            for rec in self._records
            if rec.evidence_id not in existing_ids
        ]
        _save_json(_EVIDENCE_FILE, existing + to_append)
        return list(self._records)

    def list_collected(self) -> List[EvidenceRecord]:
        """Return all previously collected evidence records from storage."""
        records: List[EvidenceRecord] = []
        for row in _load_json(_EVIDENCE_FILE):
            if isinstance(row, dict):
                records.append(EvidenceRecord(**row))
        return records


# --------------------------------------------------------------------------- #
# EvidencePackageManager
# --------------------------------------------------------------------------- #


class EvidencePackageManager:
    """Bundle evidence records into signed, timestamped packages."""

    def __init__(self) -> None:
        self._private_key, self._public_pem = _load_signing_key()
        self._packages: List[EvidencePackage] = []
        for row in _load_json(_PACKAGES_FILE):
            if isinstance(row, dict):
                self._packages.append(EvidencePackage(**row))

    def _package_canonical(
        self,
        timestamp: float,
        evidence_ids: List[str],
        prev_package_id: Optional[str],
        manifest: Dict[str, Any],
    ) -> str:
        body = {
            "timestamp": timestamp,
            "evidence_ids": sorted(evidence_ids),
            "prev_package_id": prev_package_id,
            "manifest": manifest,
        }
        return _canonical(body)

    def package(
        self,
        records: List[EvidenceRecord],
        timestamp: Optional[float] = None,
        prev_package_id: Optional[str] = None,
    ) -> EvidencePackage:
        """Create a signed EvidencePackage from the given records.

        Same input (records + timestamp) always yields the same package_id and
        signature. Deterministic and content-addressed.
        """
        if timestamp is None:
            timestamp = _DEFAULT_TIMESTAMP

        evidence_ids = sorted({rec.evidence_id for rec in records})
        # Manifest: per-source breakdown of bundled evidence.
        by_source: Dict[str, List[str]] = {}
        for rec in records:
            by_source.setdefault(rec.source, []).append(rec.evidence_id)
        manifest = {
            source: sorted(ids) for source, ids in sorted(by_source.items())
        }

        canonical = self._package_canonical(
            timestamp, evidence_ids, prev_package_id, manifest
        )
        package_id = _content_id("pkg", {"canonical": canonical, "timestamp": timestamp})
        signature = self._private_key.sign(canonical.encode("utf-8"))

        package = EvidencePackage(
            package_id=package_id,
            timestamp=timestamp,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence_ids),
            signature=signature.hex(),
            public_key_pem=self._public_pem.decode("utf-8"),
            prev_package_id=prev_package_id,
            manifest=manifest,
        )
        self._packages.append(package)
        _save_json(_PACKAGES_FILE, [p.to_dict() for p in self._packages])
        return package

    def list_packages(self) -> List[EvidencePackage]:
        return list(self._packages)

    def verify_package(self, package: EvidencePackage) -> bool:
        """Verify the Ed25519 signature of a package."""
        try:
            public_key = serialization.load_pem_public_key(
                package.public_key_pem.encode("utf-8")
            )
        except (ValueError, OSError):
            return False
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        if not isinstance(public_key, Ed25519PublicKey):
            return False
        canonical = self._package_canonical(
            package.timestamp,
            package.evidence_ids,
            package.prev_package_id,
            package.manifest,
        )
        try:
            public_key.verify(
                bytes.fromhex(package.signature), canonical.encode("utf-8")
            )
            return True
        except Exception:  # noqa: BLE001 — signature invalid
            return False


# --------------------------------------------------------------------------- #
# AuditTrailGenerator
# --------------------------------------------------------------------------- #


class AuditTrailGenerator:
    """Generate audit trails: who did what, when, with what evidence."""

    def __init__(self) -> None:
        self._trails: List[AuditTrailEntry] = []
        for row in _load_json(_TRAILS_FILE):
            if isinstance(row, dict):
                self._trails.append(AuditTrailEntry(**row))

    def build(
        self,
        records: List[EvidenceRecord],
        actor: str = "c-uas compliance --collect",
    ) -> List[AuditTrailEntry]:
        """Build an audit trail for a collection run.

        One step per evidence source, chained through the evidence records.
        """
        trail: List[AuditTrailEntry] = []
        by_source: Dict[str, List[EvidenceRecord]] = {}
        for rec in records:
            by_source.setdefault(rec.source, []).append(rec)

        step_id = 0
        for source in sorted(by_source):
            src_records = by_source[source]
            step_id += 1
            entry = AuditTrailEntry(
                step_id=f"step-{step_id:04d}",
                timestamp=src_records[0].timestamp,
                actor=actor,
                action="collected",
                target=source,
                evidence_ids=[r.evidence_id for r in src_records],
                details={
                    "component": src_records[0].component,
                    "record_count": len(src_records),
                    "event_types": sorted({r.event_type for r in src_records}),
                },
            )
            trail.append(entry)

        # Packaging step closes the trail.
        step_id += 1
        trail.append(
            AuditTrailEntry(
                step_id=f"step-{step_id:04d}",
                timestamp=_DEFAULT_TIMESTAMP,
                actor=actor,
                action="packaged",
                target="evidence_package",
                evidence_ids=[r.evidence_id for r in records],
                details={"package_count": 1},
            )
        )

        existing = _load_json(_TRAILS_FILE)
        existing_ids: Set[str] = {
            row.get("step_id")
            for row in existing
            if isinstance(row, dict) and row.get("step_id") is not None
        }
        to_append = [e.to_dict() for e in trail if e.step_id not in existing_ids]
        _save_json(_TRAILS_FILE, existing + to_append)
        self._trails.extend(trail)
        return trail

    def list_trails(self) -> List[AuditTrailEntry]:
        return list(self._trails)


# --------------------------------------------------------------------------- #
# ComplianceReporter
# --------------------------------------------------------------------------- #


class ComplianceReporter:
    """Map collected evidence to ISO 42001 Annex A controls (A.5.1-A.11.1)."""

    # Source -> Annex A controls it can satisfy.
    SOURCE_CONTROL_MAP: Dict[str, List[str]] = {
        "governance": ["A.5.1", "A.5.2", "A.6.1", "A.7.1", "A.10.1", "A.11.1"],
        "threat_intel": ["A.8.1", "A.9.1", "A.11.1"],
        "detection": ["A.8.2", "A.9.1"],
        "tracking": ["A.8.3", "A.9.1"],
        "engagement": ["A.8.3", "A.9.1"],
        "forensics": ["A.10.1"],
        "broker": ["A.6.1", "A.11.1"],
        "edge": ["A.9.1"],
    }

    def generate(
        self, records: Optional[List[EvidenceRecord]] = None
    ) -> ComplianceReport:
        """Generate a compliance report mapping evidence to Annex A controls.

        If records is None, uses all previously collected evidence from storage.
        """
        if records is None:
            records = EvidenceCollector().list_collected()

        mappings: List[ComplianceMapping] = []
        for control_id in ISO_42001_ANNEX_A_CONTROLS:
            # Find evidence whose source can satisfy this control.
            supporting: List[str] = []
            for rec in records:
                controls = self.SOURCE_CONTROL_MAP.get(rec.source, [])
                if control_id in controls:
                    supporting.append(rec.evidence_id)
            # De-duplicate while preserving order.
            seen: Set[str] = set()
            supporting_unique: List[str] = []
            for eid in supporting:
                if eid not in seen:
                    seen.add(eid)
                    supporting_unique.append(eid)

            title = _iso_control_title(control_id)
            satisfied = len(supporting_unique) > 0
            gap_note = None if satisfied else f"No evidence collected for {control_id}"
            mappings.append(
                ComplianceMapping(
                    control_id=control_id,
                    title=title,
                    applicable=True,
                    evidence_ids=supporting_unique,
                    evidence_count=len(supporting_unique),
                    satisfied=satisfied,
                    gap_note=gap_note,
                )
            )

        satisfied = sum(1 for m in mappings if m.satisfied)
        total = len(mappings)
        coverage = round((satisfied / total) * 100.0, 2) if total else 0.0
        if coverage >= 90:
            status = "compliant"
        elif coverage >= 60:
            status = "partial"
        else:
            status = "non_compliant"

        return ComplianceReport(
            generated_at=_DEFAULT_TIMESTAMP,
            package_id=None,
            total_evidence=len(records),
            controls=mappings,
            satisfied_controls=satisfied,
            total_controls=total,
            coverage_percentage=coverage,
            overall_status=status,
        )


# --------------------------------------------------------------------------- #
# EvidenceExport
# --------------------------------------------------------------------------- #


class EvidenceExport:
    """Export signed evidence packages to JSON or ZIP with manifest."""

    @staticmethod
    def to_json(package: EvidencePackage, path: str) -> str:
        """Write the package as canonical JSON to `path`. Returns the path."""
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_canonical(package.to_dict()) + "\n")
        return str(out)

    @staticmethod
    def to_zip(
        package: EvidencePackage,
        records: List[EvidenceRecord],
        path: str,
    ) -> str:
        """Write a ZIP archive: package.json + evidence records + manifest.json."""
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        record_map = {r.evidence_id: r for r in records}
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("package.json", _canonical(package.to_dict()) + "\n")
            zf.writestr("manifest.json", _canonical(package.manifest) + "\n")
            for eid in package.evidence_ids:
                rec = record_map.get(eid)
                if rec is not None:
                    zf.writestr(f"evidence/{eid}.json", _canonical(rec.to_dict()) + "\n")
        return str(out)
