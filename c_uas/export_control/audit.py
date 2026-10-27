"""Export-control audit trail.

Loads prior scan results and diffs them against the current scan, reporting
new, removed, and resolved findings. State persists under
``~/.c-uas-platform/export_control/audit/``.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from .scanner import Finding, ScanReport, utc_now_iso

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "export_control")
AUDIT_SUBDIR = "audit"
LATEST_FILENAME = "latest_audit.json"


def _finding_key(f: Finding) -> Tuple[str, int, str]:
    return (f.file, f.line, f.term)


@dataclass(frozen=True)
class AuditTrail:
    """Diff between a prior scan and the current scan."""

    generated_at: str
    new_findings: Tuple[Finding, ...]
    removed_findings: Tuple[Finding, ...]
    resolved_count: int
    new_count: int
    removed_count: int
    current_critical: int
    current_high: int


def load_prior(state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR) -> Optional[ScanReport]:
    """Load the previously persisted scan report, or None."""
    from .scanner import load_latest_scan

    return load_latest_scan(state_dir)


def diff_audits(prior: Optional[ScanReport], current: ScanReport) -> AuditTrail:
    """Diff ``prior`` against ``current``.

    A finding is 'new' if its (file, line, term) key was not in the prior
    scan; 'removed' if it was in the prior scan but not the current one.
    """
    prior_keys: Dict[Tuple[str, int, str], Finding] = {}
    if prior is not None:
        for f in prior.findings:
            prior_keys[_finding_key(f)] = f

    current_keys: Dict[Tuple[str, int, str], Finding] = {}
    for f in current.findings:
        current_keys[_finding_key(f)] = f

    new_findings = tuple(current_keys[k] for k in sorted(current_keys) if k not in prior_keys)
    removed_findings = tuple(prior_keys[k] for k in sorted(prior_keys) if k not in current_keys)

    return AuditTrail(
        generated_at=utc_now_iso(),
        new_findings=new_findings,
        removed_findings=removed_findings,
        resolved_count=len(removed_findings),
        new_count=len(new_findings),
        removed_count=len(removed_findings),
        current_critical=current.critical_count,
        current_high=current.high_count,
    )


def save_audit(trail: AuditTrail, state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR) -> Path:
    """Persist the audit trail as JSON under ``state_dir/audit/``."""
    base = Path(state_dir)
    audit_dir = base / AUDIT_SUBDIR
    audit_dir.mkdir(parents=True, exist_ok=True)
    latest = audit_dir / LATEST_FILENAME
    payload = asdict(trail)
    latest.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return latest
