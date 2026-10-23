"""Deterministic tests for Automated Compliance Evidence Collection (ISO 42001).

Scenarios
---------
- content addressing is deterministic and payload-sensitive
- evidence collection pulls from all component sources
- collection de-duplicates by content-addressed evidence id
- collected evidence persists to storage and round-trips
- package creation is deterministic: same input -> same package_id + signature
- package signature verifies; tampered signature does not
- package can be hash-linked to a previous package
- audit trail emits one step per source and records who/what/when
- compliance report maps evidence to Annex A controls A.5.1-A.11.1
- report coverage is computed and deterministic
- export writes JSON and ZIP (package + manifest + evidence records)
- fixed default timestamp keeps packages stable across runs

All state is isolated to a per-test temp dir under ~/.c-uas-platform/compliance
(and the source component dirs) so tests never share or leak persisted data.
"""

import json
import os
import zipfile
from pathlib import Path

import pytest

import c_uas.compliance as comp
from c_uas.compliance import (
    AuditTrailEntry,
    AuditTrailGenerator,
    ComplianceReporter,
    EvidenceCollector,
    EvidenceExport,
    EvidencePackage,
    EvidencePackageManager,
    EvidenceRecord,
    _DEFAULT_TIMESTAMP,
    _content_id,
)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point every compliance and source persistence path at a fresh temp dir."""
    base = tmp_path / "c-uas-platform"
    dirs = {
        "_COMPLIANCE_DIR": base / "compliance",
        "_GOV_DIR": base / "governance",
        "_GRC_DIR": base / "grc_clab",
        "_TI_DIR": base / "threat_intel",
        "_BRK_DIR": base / "broker",
        "_EDGE_ROOT": base / "edge",
    }
    for attr, path in dirs.items():
        path.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(comp, attr, path)

    comp_files = {
        "_EVIDENCE_FILE": dirs["_COMPLIANCE_DIR"] / "collected_evidence.json",
        "_PACKAGES_FILE": dirs["_COMPLIANCE_DIR"] / "evidence_packages.json",
        "_TRAILS_FILE": dirs["_COMPLIANCE_DIR"] / "audit_trails.json",
        "_KEY_FILE": dirs["_COMPLIANCE_DIR"] / "signing_key.pem",
    }
    for attr, path in comp_files.items():
        monkeypatch.setattr(comp, attr, path)
        if attr != "_KEY_FILE":
            path.write_text("[]")
    return base


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


# --------------------------------------------------------------------------- #
# Content addressing
# --------------------------------------------------------------------------- #


def test_content_id_is_deterministic():
    h1 = _content_id("ev", {"a": 1, "b": 2})
    h2 = _content_id("ev", {"a": 1, "b": 2})
    assert h1 == h2
    assert h1.startswith("ev-")


def test_content_id_changes_with_payload():
    h1 = _content_id("ev", {"a": 1})
    h2 = _content_id("ev", {"a": 2})
    assert h1 != h2


def test_default_timestamp_is_fixed():
    assert _DEFAULT_TIMESTAMP == 1_777_000_000.0


# --------------------------------------------------------------------------- #
# EvidenceCollector
# --------------------------------------------------------------------------- #


def test_collect_governance_records(isolated):
    gov = comp._GOV_DIR
    _write_json(
        gov / "ai_systems.json",
        [
            {
                "name": "EKF Tracking",
                "module_path": "c_uas.tracking.ekf_interceptor",
                "lifecycle_stage": "operation",
                "risk_level": "medium",
                "registered_at": 1000.0,
            }
        ],
    )
    _write_json(gov / "risks.json", [])
    _write_json(gov / "controls.json", [])
    _write_json(gov / "evidence.json", [])
    _write_json(gov / "incidents.json", [])

    collector = EvidenceCollector(timestamp=1700000000.0)
    records = collector.collect()

    assert len(records) == 1
    rec = records[0]
    assert rec.source == "governance"
    assert rec.component == "c_uas.governance"
    assert rec.event_type == "ai_systems"
    assert rec.timestamp == 1700000000.0
    assert rec.evidence_id.startswith("ev-")
    assert rec.payload["record"]["name"] == "EKF Tracking"


def test_collect_all_sources(isolated):
    # Seed every source component directory.
    gov = comp._GOV_DIR
    for name in ("ai_systems", "risks", "controls", "evidence", "incidents"):
        _write_json(gov / f"{name}.json", [{"id": 1}])
    _write_json(comp._GRC_DIR / "scan_logs.json", [{"scan": 1}])
    _write_json(comp._TI_DIR / "bundles.json", [{"bundle": 1}])
    _write_json(comp._BRK_DIR / "tenants.json", [{"tenant": 1}])
    edge_node = comp._EDGE_ROOT / "node-01"
    _write_json(edge_node / "health.json", {"status": "ok"})

    collector = EvidenceCollector(timestamp=1700000000.0)
    records = collector.collect()

    sources = {r.source for r in records}
    assert "governance" in sources
    assert "threat_intel" in sources
    assert "broker" in sources
    assert "edge" in sources
    assert any(r.component == "c_uas.edge.node-01" for r in records)


def test_collect_deduplicates_by_evidence_id(isolated):
    gov = comp._GOV_DIR
    row = {
        "name": "Dup System",
        "module_path": "mod.a",
        "lifecycle_stage": "operation",
        "risk_level": "low",
        "registered_at": 1000.0,
    }
    _write_json(gov / "ai_systems.json", [row, row])  # identical rows
    for name in ("risks", "controls", "evidence", "incidents"):
        _write_json(gov / f"{name}.json", [])

    collector = EvidenceCollector(timestamp=1700000000.0)
    records = collector.collect()

    assert len(records) == 1  # de-duplicated by content id


def test_collect_persists_and_list_collected_round_trip(isolated):
    gov = comp._GOV_DIR
    _write_json(gov / "ai_systems.json", [{"name": "Persist Sys", "module_path": "m", "lifecycle_stage": "operation", "risk_level": "low", "registered_at": 1000.0}])
    for name in ("risks", "controls", "evidence", "incidents"):
        _write_json(gov / f"{name}.json", [])

    collector = EvidenceCollector(timestamp=1700000000.0)
    collector.collect()

    back = EvidenceCollector(timestamp=1700000000.0).list_collected()
    assert len(back) == 1
    assert back[0].payload["record"]["name"] == "Persist Sys"


# --------------------------------------------------------------------------- #
# EvidencePackageManager
# --------------------------------------------------------------------------- #


def _sample_records():
    r1 = EvidenceRecord(
        evidence_id="ev-aaa",
        source="governance",
        component="c_uas.governance",
        event_type="ai_systems",
        timestamp=1700000000.0,
        collected_at=1700000000.0,
        payload={"record": {"name": "A"}},
    )
    r2 = EvidenceRecord(
        evidence_id="ev-bbb",
        source="detection",
        component="c_uas.api",
        event_type="rf_classification",
        timestamp=1700000000.0,
        collected_at=1700000000.0,
        payload={"record": {"freq": 2450}},
    )
    return [r1, r2]


def test_package_is_deterministic(isolated):
    records = _sample_records()
    m1 = EvidencePackageManager()
    p1 = m1.package(records, timestamp=1700000000.0)
    m2 = EvidencePackageManager()
    p2 = m2.package(records, timestamp=1700000000.0)

    assert p1.package_id == p2.package_id
    assert p1.evidence_ids == ["ev-aaa", "ev-bbb"]
    assert p1.evidence_count == 2
    assert p1.signature == p2.signature
    assert p1.public_key_pem == p2.public_key_pem


def test_package_changes_with_different_evidence(isolated):
    m = EvidencePackageManager()
    p1 = m.package(_sample_records(), timestamp=1700000000.0)
    different = _sample_records() + [
        EvidenceRecord(
            evidence_id="ev-ccc",
            source="tracking",
            component="c_uas.tracking",
            event_type="ekf_update",
            timestamp=1700000000.0,
            collected_at=1700000000.0,
            payload={"record": {}},
        )
    ]
    p2 = m.package(different, timestamp=1700000000.0)
    assert p1.package_id != p2.package_id
    assert p2.evidence_count == 3


def test_package_is_hash_linked_to_previous(isolated):
    records = _sample_records()
    m = EvidencePackageManager()
    p1 = m.package(records, timestamp=1700000000.0)
    p2 = m.package(records, timestamp=1700000000.0, prev_package_id=p1.package_id)
    assert p2.prev_package_id == p1.package_id


def test_verify_package_is_valid(isolated):
    records = _sample_records()
    m = EvidencePackageManager()
    package = m.package(records, timestamp=1700000000.0)
    assert m.verify_package(package) is True


def test_verify_package_rejects_tampered_signature(isolated):
    records = _sample_records()
    m = EvidencePackageManager()
    package = m.package(records, timestamp=1700000000.0)
    tampered = EvidencePackage(
        package_id=package.package_id,
        timestamp=package.timestamp,
        evidence_ids=package.evidence_ids,
        evidence_count=package.evidence_count,
        signature="0" * 64,  # invalid signature
        public_key_pem=package.public_key_pem,
        prev_package_id=package.prev_package_id,
        manifest=package.manifest,
    )
    assert m.verify_package(tampered) is False


# --------------------------------------------------------------------------- #
# AuditTrailGenerator
# --------------------------------------------------------------------------- #


def test_audit_trail_has_one_step_per_source(isolated):
    records = _sample_records()
    trail = AuditTrailGenerator().build(records, actor="c-uas compliance --collect")

    sources = {e.target for e in trail if e.action == "collected"}
    assert "governance" in sources
    assert "detection" in sources
    assert any(e.action == "packaged" for e in trail)


def test_audit_trail_records_who_what_when(isolated):
    records = _sample_records()
    trail = AuditTrailGenerator().build(records, actor="soc-operator")
    step = trail[0]
    assert isinstance(step, AuditTrailEntry)
    assert step.actor == "soc-operator"
    assert step.action == "collected"
    assert step.timestamp == 1700000000.0
    assert set(step.evidence_ids) == {"ev-aaa", "ev-bbb"} or len(step.evidence_ids) >= 1
    assert "record_count" in step.details


# --------------------------------------------------------------------------- #
# ComplianceReporter
# --------------------------------------------------------------------------- #


def test_compliance_report_maps_all_annex_a_controls(isolated):
    records = _sample_records()
    report = ComplianceReporter().generate(records)

    assert report.total_controls == 10
    assert {c.control_id for c in report.controls} == {
        "A.5.1", "A.5.2", "A.6.1", "A.7.1", "A.8.1",
        "A.8.2", "A.8.3", "A.9.1", "A.10.1", "A.11.1",
    }
    # governance evidence satisfies A.5.1, A.5.2, A.6.1, A.7.1, A.10.1, A.11.1
    satisfied = {c.control_id for c in report.controls if c.satisfied}
    assert {"A.5.1", "A.5.2", "A.6.1", "A.7.1", "A.10.1", "A.11.1"}.issubset(satisfied)
    # detection evidence satisfies A.8.2, A.9.1
    assert {"A.8.2", "A.9.1"}.issubset(satisfied)


def test_compliance_report_coverage_is_deterministic(isolated):
    records = _sample_records()
    r1 = ComplianceReporter().generate(records)
    r2 = ComplianceReporter().generate(records)
    assert r1.coverage_percentage == r2.coverage_percentage
    assert r1.overall_status == r2.overall_status
    assert r1.generated_at == r2.generated_at == _DEFAULT_TIMESTAMP


def test_compliance_report_records_gaps(isolated):
    # No evidence at all -> every control reports a gap.
    report = ComplianceReporter().generate([])
    assert report.satisfied_controls == 0
    assert report.coverage_percentage == 0.0
    assert report.overall_status == "non_compliant"
    for c in report.controls:
        assert c.satisfied is False
        assert c.gap_note is not None


# --------------------------------------------------------------------------- #
# EvidenceExport
# --------------------------------------------------------------------------- #


def test_export_json_round_trip(isolated):
    records = _sample_records()
    m = EvidencePackageManager()
    package = m.package(records, timestamp=1700000000.0)

    out = str(comp._COMPLIANCE_DIR / "pkg.json")
    written = EvidenceExport.to_json(package, out)
    assert written == out

    data = json.loads(Path(out).read_text())
    assert data["package_id"] == package.package_id
    assert data["signature"] == package.signature
    assert len(data["evidence_ids"]) == 2


def test_export_zip_contains_package_manifest_evidence(isolated):
    records = _sample_records()
    m = EvidencePackageManager()
    package = m.package(records, timestamp=1700000000.0)

    out = str(comp._COMPLIANCE_DIR / "pkg.zip")
    EvidenceExport.to_zip(package, records, out)

    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert "package.json" in names
        assert "manifest.json" in names
        assert "evidence/ev-aaa.json" in names
        assert "evidence/ev-bbb.json" in names
        pkg = json.loads(zf.read("package.json"))
        assert pkg["package_id"] == package.package_id


def test_export_json_to_stdout_path_is_dash(isolated):
    records = _sample_records()
    m = EvidencePackageManager()
    package = m.package(records, timestamp=1700000000.0)
    # Writing to "-" should not raise; it creates a file literally named "-".
    out = str(comp._COMPLIANCE_DIR / "-")
    EvidenceExport.to_json(package, out)
    assert Path(out).exists()
