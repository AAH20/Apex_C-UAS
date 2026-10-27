"""Readiness report rendering and persistence.

Readiness reports are persisted as JSON under
~/.c-uas-platform/production_readiness/reports/ (outside the repo), one file
per report plus a ``latest.json`` pointer, written atomically.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .aggregator import ReadinessReport
from .checks import DEFAULT_STATE_DIR, DomainResult

REPORTS_SUBDIR = "reports"
LATEST_FILENAME = "latest.json"


def _reports_dir(state_dir: str) -> str:
    directory = os.path.join(state_dir, REPORTS_SUBDIR)
    os.makedirs(directory, exist_ok=True)
    return directory


def report_id(report: ReadinessReport) -> str:
    """Deterministic content id for a report."""
    payload = {
        "generated_at": report.generated_at,
        "overall_score": report.overall_score,
        "go_no_go": report.go_no_go,
        "checks": [
            {
                "domain": check.domain,
                "check": check.check,
                "passed": check.passed,
                "score": check.score,
            }
            for check in report.checks
        ],
    }
    material = json.dumps(payload, sort_keys=True)
    return "RR-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def save_report(report: ReadinessReport, state_dir: str = DEFAULT_STATE_DIR) -> str:
    """Atomically persist a report; return the report file path.

    Writes <report_id>.json and refreshes <state_dir>/reports/latest.json.
    """
    directory = _reports_dir(state_dir)
    rid = report_id(report)
    path = os.path.join(directory, rid + ".json")
    tmp_path = path + ".tmp"
    data = asdict(report)
    data["checks"] = [dict(check) for check in data["checks"]]
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(tmp_path, path)

    latest_path = os.path.join(directory, LATEST_FILENAME)
    tmp_latest = latest_path + ".tmp"
    with open(tmp_latest, "w", encoding="utf-8") as handle:
        json.dump({"report_id": rid}, handle, indent=2)
    os.replace(tmp_latest, latest_path)
    return path


def load_report(report_id: str, state_dir: str = DEFAULT_STATE_DIR) -> Optional[ReadinessReport]:
    """Load a previously persisted report by id, or None if absent."""
    path = os.path.join(state_dir, REPORTS_SUBDIR, report_id + ".json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return _report_from_dict(data)


def load_latest_report(state_dir: str = DEFAULT_STATE_DIR) -> Optional[ReadinessReport]:
    """Load the latest persisted report, or None if none exists."""
    latest_path = os.path.join(state_dir, REPORTS_SUBDIR, LATEST_FILENAME)
    if not os.path.exists(latest_path):
        return None
    with open(latest_path, "r", encoding="utf-8") as handle:
        pointer = json.load(handle)
    rid = pointer.get("report_id")
    if not rid:
        return None
    return load_report(rid, state_dir=state_dir)


def _report_from_dict(data: Dict[str, Any]) -> ReadinessReport:
    checks = tuple(
        DomainResult(
            domain=item["domain"],
            check=item["check"],
            passed=bool(item["passed"]),
            score=float(item["score"]),
            threshold=float(item["threshold"]),
            gate=item["gate"],
            critical=bool(item["critical"]),
            remediation=tuple(item.get("remediation", [])),
            details=item.get("details", {}),
        )
        for item in data["checks"]
    )
    return ReadinessReport(
        schema_version=data["schema_version"],
        generated_at=data["generated_at"],
        overall_score=float(data["overall_score"]),
        go_no_go=data["go_no_go"],
        decision_reason=data["decision_reason"],
        checks=checks,
        remediation=tuple(data.get("remediation", [])),
    )


def render_text(report: ReadinessReport) -> str:
    """Deterministic plain-text rendering of a readiness report."""
    lines: List[str] = []
    lines.append("[C-UAS] Production Readiness Review")
    lines.append("=" * 42)
    lines.append(f"Overall score : {report.overall_score:.1f}/100")
    lines.append(f"Decision      : {report.go_no_go}")
    lines.append(f"Reason        : {report.decision_reason}")
    lines.append(f"Generated at  : {report.generated_at}")
    lines.append("-" * 42)
    lines.append("Per-domain checks (in domain order):")
    for check in report.checks:
        mark = "PASS" if check.passed else "FAIL"
        critical = " [CRITICAL]" if check.critical else ""
        lines.append(
            f"  {check.domain:16s} {mark:4s} score={check.score:5.1f} gate={check.gate}{critical}"
        )
        error = check.details.get("error")
        if error:
            lines.append(f"    error: {error}")
        for item in check.remediation:
            lines.append(f"    remediation: {item}")
    lines.append("-" * 42)
    if report.remediation:
        lines.append("Remediation:")
        for item in report.remediation:
            lines.append(f"  - {item}")
    else:
        lines.append("Remediation: none")
    lines.append(f"Report id     : {report_id(report)}")
    return "\n".join(lines)


def render_json(report: ReadinessReport) -> str:
    """Deterministic JSON rendering of a readiness report."""
    data = asdict(report)
    data["checks"] = [dict(check) for check in data["checks"]]
    data["report_id"] = report_id(report)
    return json.dumps(data, indent=2, sort_keys=True)
