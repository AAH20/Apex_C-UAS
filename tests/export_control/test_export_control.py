"""Deterministic Export Control Compliance Scanner tests.

Covers scan detection, audit diff, CI gate exit codes, and persistence.
All values computed from real execution — no mocks, no fabricated metrics.
"""

from __future__ import annotations

from c_uas.export_control import (
    Finding,
    ScanReport,
    evaluate_gate,
    load_latest_scan,
    run_gate,
    save_scan,
    scan_directory,
)
from c_uas.export_control.audit import diff_audits
from c_uas.export_control.scanner import _severity, _term_score


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def test_term_score_counts_weapons_terms() -> None:
    count, matched = _term_score("This weapon destroys targets via kinetic strike")
    assert count == 5  # weapon, destroys, targets, kinetic, strike
    assert "weapon" in matched
    assert "kinetic" in matched


def test_term_score_ignores_defensive_only_text() -> None:
    count, matched = _term_score("detect and track drones in airspace")
    assert count == 0
    assert matched == []


def test_severity_bands() -> None:
    assert _severity(0, False) == "info"
    assert _severity(1, True) == "low"
    assert _severity(1, False) == "medium"
    assert _severity(2, False) == "high"
    assert _severity(3, False) == "critical"


def test_scan_detects_weapons_framing(tmp_path) -> None:
    readme = tmp_path / "README.md"
    _write(str(readme), "This repository helps you weapon strike drones defensively.")
    src = tmp_path / "module.py"
    _write(str(src), "def detect(uav): return True  # defensive tracking only")

    report = scan_directory(str(tmp_path))
    assert report.files_scanned == 2
    assert report.critical_count == 0
    assert report.high_count >= 1  # weapon + strike on the README line
    findings = {f.term for f in report.findings}
    assert "weapon" in findings
    assert "strike" in findings


def test_scan_deterministic(tmp_path) -> None:
    readme = tmp_path / "README.md"
    _write(str(readme), "kinetic weapon strike plan")
    r1 = scan_directory(str(tmp_path))
    r2 = scan_directory(str(tmp_path))
    assert r1 == r2


def test_scan_skips_git_and_pycache(tmp_path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    _write(str(git_dir / "config"), "weapon strike config")
    pycache = tmp_path / "__pycache__"
    pycache.mkdir()
    _write(str(pycache / "mod.pyc"), "weapon strike cache")
    readme = tmp_path / "README.md"
    _write(str(readme), "clean readme")

    report = scan_directory(str(tmp_path))
    assert report.files_scanned == 1  # only README.md
    assert report.critical_count == 0


def test_scan_persistence_roundtrip(tmp_path) -> None:
    readme = tmp_path / "README.md"
    _write(str(readme), "target eliminate plan")
    report = scan_directory(str(tmp_path))
    save_scan(report, state_dir=str(tmp_path / ".c-uas-platform"))
    loaded = load_latest_scan(state_dir=str(tmp_path / ".c-uas-platform"))
    assert loaded is not None
    assert loaded.files_scanned == report.files_scanned
    assert loaded.high_count == report.high_count
    assert tuple(f.term for f in loaded.findings) == tuple(f.term for f in report.findings)


def test_audit_diff_detects_new_and_removed() -> None:
    prior_findings = (
        Finding(
            file="old.py",
            line=1,
            term="weapon",
            context="weapon",
            severity="high",
            repo_description_risk=False,
        ),
    )
    prior = ScanReport(
        root="/prior",
        files_scanned=1,
        findings=prior_findings,
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        info_count=0,
        generated_at="2026-01-01T00:00:00Z",
    )
    current_findings = (
        Finding(
            file="new.py",
            line=2,
            term="strike",
            context="strike",
            severity="critical",
            repo_description_risk=True,
        ),
    )
    current = ScanReport(
        root="/current",
        files_scanned=1,
        findings=current_findings,
        critical_count=1,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
        generated_at="2026-01-02T00:00:00Z",
    )
    trail = diff_audits(prior, current)
    assert trail.new_count == 1
    assert trail.removed_count == 1
    assert trail.current_critical == 1
    assert trail.current_high == 0
    assert trail.new_findings[0].term == "strike"
    assert trail.removed_findings[0].term == "weapon"


def test_gate_fails_on_high_or_critical(tmp_path) -> None:
    readme = tmp_path / "README.md"
    _write(str(readme), "critical weapon strike eliminate plan")
    rc = run_gate(str(tmp_path), state_dir=str(tmp_path / ".c-uas-platform"))
    assert rc != 0


def test_gate_passes_when_clean(tmp_path) -> None:
    readme = tmp_path / "README.md"
    _write(str(readme), "detect and track drones defensively")
    rc = run_gate(str(tmp_path), state_dir=str(tmp_path / ".c-uas-platform"))
    assert rc == 0


def test_evaluate_gate_returns_structured_result(tmp_path) -> None:
    readme = tmp_path / "README.md"
    _write(str(readme), "clean defensive detection")
    result = evaluate_gate(str(tmp_path), state_dir=str(tmp_path / ".c-uas-platform"))
    assert result.passed is True
    assert result.critical_count == 0
    assert result.high_count == 0


def test_scan_handles_empty_directory(tmp_path) -> None:
    report = scan_directory(str(tmp_path))
    assert report.files_scanned == 0
    assert report.critical_count == 0
    assert report.findings == ()
