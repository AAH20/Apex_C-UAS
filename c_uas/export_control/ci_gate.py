"""Export-control CI gate.

Exits non-zero if any HIGH or CRITICAL findings are present; exits 0 if only
LOW/INFO findings or the tree is clean. Deterministic JSON output.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from .audit import diff_audits, save_audit
from .scanner import Finding, ScanReport, save_scan, scan_directory

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "export_control")
SCAN_SUBDIR = "scans"
LATEST_FILENAME = "latest_scan.json"
PREVIOUS_FILENAME = "previous_scan.json"


@dataclass(frozen=True)
class GateResult:
    """CI gate evaluation result."""

    passed: bool
    reason: str
    critical_count: int
    high_count: int
    new_findings: int
    removed_findings: int
    state_path: str


def _load_prior_scan(state_dir: str | os.PathLike[str]) -> Optional[ScanReport]:
    """Load the previous scan (from the prior run) if present."""
    prior_path = Path(state_dir) / SCAN_SUBDIR / PREVIOUS_FILENAME
    if not prior_path.exists():
        return None
    data = json.loads(prior_path.read_text(encoding="utf-8"))
    findings = tuple(
        Finding(
            file=item["file"],
            line=item["line"],
            term=item["term"],
            context=item["context"],
            severity=item["severity"],
            repo_description_risk=item["repo_description_risk"],
        )
        for item in data.get("findings", [])
    )
    return ScanReport(
        root=data["root"],
        files_scanned=data["files_scanned"],
        findings=findings,
        critical_count=data["critical_count"],
        high_count=data["high_count"],
        medium_count=data["medium_count"],
        low_count=data["low_count"],
        info_count=data["info_count"],
        generated_at=data["generated_at"],
    )


def evaluate_gate(
    root: str | os.PathLike[str],
    state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR,
) -> GateResult:
    """Evaluate the CI gate for ``root``.

    Scans the tree, persists the scan, diffs against the prior scan, and
    returns a ``GateResult``. The gate fails (passed=False) when any
    CRITICAL or HIGH finding exists.
    """
    report = scan_directory(root)
    save_scan(report, state_dir)

    prior = _load_prior_scan(state_dir)
    trail = diff_audits(prior, report)
    save_audit(trail, state_dir)

    # Keep a copy of this run's scan as previous_scan.json for the next run.
    scan_dir = Path(state_dir) / SCAN_SUBDIR
    scan_dir.mkdir(parents=True, exist_ok=True)
    latest = scan_dir / LATEST_FILENAME
    previous = scan_dir / PREVIOUS_FILENAME
    if latest.exists():
        previous.write_text(latest.read_text(encoding="utf-8"), encoding="utf-8")

    failed = report.critical_count > 0 or report.high_count > 0
    if failed:
        reason = (
            f"{report.critical_count} critical and {report.high_count} high "
            "§120.41 findings; gate failed"
        )
    else:
        reason = (
            f"clean: {report.critical_count} critical, {report.high_count} high; "
            f"{report.low_count} low, {report.info_count} info"
        )

    return GateResult(
        passed=not failed,
        reason=reason,
        critical_count=report.critical_count,
        high_count=report.high_count,
        new_findings=trail.new_count,
        removed_findings=trail.resolved_count,
        state_path=str(scan_dir / LATEST_FILENAME),
    )


def run_gate(
    root: str | os.PathLike[str],
    state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR,
) -> int:
    """Run the CI gate and return a process exit code (0 = pass, 1 = fail)."""
    result = evaluate_gate(root, state_dir)
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0 if result.passed else 1
