"""Export-control scanner for §120.41 'specially designed' exposure.

Walks a directory tree, scans Python sources, README.md, and repo-description
metadata for weapons-employment framing that may trigger ITAR §120.41
''specially designed'' exposure via the repository *description* (not the
source). Produces a deterministic scan report with file/line/context per
finding.

Nothing here modifies the scanned tree — this is read-only advisory output.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "export_control")
SCAN_SUBDIR = "scans"
LATEST_FILENAME = "latest_scan.json"

# Weapons-employment terms that, when describing a repository's *purpose*,
# may indicate §120.41 'specially designed' exposure via description.
WEAPONS_TERMS: Sequence[str] = (
    "weapon",
    "weapons",
    "strike",
    "strikes",
    "neutralize",
    "neutralizes",
    "eliminate",
    "eliminates",
    "destroy",
    "destroys",
    "defeat",
    "defeats",
    "intercept",
    "intercepts",
    "kinetic",
    "target",
    "targets",
    "employ",
    "employs",
    "engage",
    "engages",
)

# Terms that suggest a defensive / non-weapons context (lower risk).
DEFENSIVE_TERMS: Sequence[str] = (
    "detect",
    "detection",
    "track",
    "tracking",
    "defense",
    "defensive",
    "c-uas",
    "counter-uav",
    "counter-uas",
    "airspace",
    "forensics",
)

# File extensions considered scannable source.
SCANNABLE_EXTENSIONS: Tuple[str, ...] = (".py", ".md", ".txt", ".toml", ".yaml", ".yml", ".json")


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _term_score(text: str) -> Tuple[int, List[str]]:
    """Count weapons terms and defensive terms in text.

    Returns (weapons_count, matched_weapons_terms). Defensive terms do not
    cancel weapons terms; they only inform the severity label.
    """
    lowered = text.lower()
    matched: List[str] = []
    count = 0
    for term in WEAPONS_TERMS:
        # Word-boundary-ish match to avoid substring false positives
        # (e.g. 'target' inside 'targeting' still counts as targeting-related).
        pattern = r"\b" + re.escape(term) + r"\b"
        for _ in re.finditer(pattern, lowered):
            count += 1
            if term not in matched:
                matched.append(term)
    return count, matched


def _severity(weapons_count: int, has_defensive: bool) -> str:
    if weapons_count >= 3:
        return "critical"
    if weapons_count == 2:
        return "high"
    if weapons_count == 1:
        return "medium" if not has_defensive else "low"
    return "info"


@dataclass(frozen=True)
class Finding:
    """A single weapons-employment finding in a scanned file."""

    file: str
    line: int
    term: str
    context: str
    severity: str
    repo_description_risk: bool


@dataclass(frozen=True)
class ScanReport:
    """Deterministic scan report for a directory tree."""

    root: str
    files_scanned: int
    findings: Tuple[Finding, ...]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    generated_at: str


def utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_scannable(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in SCANNABLE_EXTENSIONS


def _scan_file(path: Path, root: Path) -> List[Finding]:
    findings: List[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return findings

    relative = str(path.relative_to(root))
    is_readme = path.name.lower() == "readme.md"
    lines = text.split("\n")
    for idx, line in enumerate(lines, start=1):
        weapons_count, matched = _term_score(line)
        if not matched:
            continue
        has_defensive = any(t in line.lower() for t in DEFENSIVE_TERMS)
        severity = _severity(weapons_count, has_defensive)
        # Repo-description risk: README.md or top-level metadata files are the
        # primary §120.41 exposure vector (description, not source).
        repo_risk = is_readme or path.parent == root
        for term in matched:
            findings.append(
                Finding(
                    file=relative,
                    line=idx,
                    term=term,
                    context=line.strip()[:120],
                    severity=severity,
                    repo_description_risk=repo_risk,
                )
            )
    return findings


def scan_directory(root: str | os.PathLike[str]) -> ScanReport:
    """Scan ``root`` for weapons-employment framing.

    Returns a deterministic ``ScanReport``. Results are sorted by
    (file, line, term) for reproducibility.
    """
    root_path = Path(root).resolve()
    all_findings: List[Finding] = []
    files_scanned = 0

    for dirpath, _dirnames, filenames in os.walk(root_path):
        # Skip version-control and dependency directories.
        _dirnames[:] = [
            d
            for d in _dirnames
            if d not in (".git", "__pycache__", ".venv", "node_modules", ".mypy_cache")
        ]
        for fname in sorted(filenames):
            path = Path(dirpath) / fname
            if not _is_scannable(path):
                continue
            files_scanned += 1
            all_findings.extend(_scan_file(path, root_path))

    all_findings.sort(key=lambda f: (f.file, f.line, f.term))

    severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        severity_counts[f.severity] += 1

    return ScanReport(
        root=str(root_path),
        files_scanned=files_scanned,
        findings=tuple(all_findings),
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        info_count=severity_counts["info"],
        generated_at=utc_now_iso(),
    )


def save_scan(report: ScanReport, state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR) -> Path:
    """Persist the scan report as JSON under ``state_dir/scans/``."""
    base = Path(state_dir)
    scan_dir = base / SCAN_SUBDIR
    scan_dir.mkdir(parents=True, exist_ok=True)
    latest = scan_dir / LATEST_FILENAME
    payload = asdict(report)
    latest.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return latest


def load_latest_scan(state_dir: str | os.PathLike[str] = DEFAULT_STATE_DIR) -> Optional[ScanReport]:
    """Load the most recent persisted scan report, or None if absent."""
    latest = Path(state_dir) / SCAN_SUBDIR / LATEST_FILENAME
    if not latest.exists():
        return None
    data = json.loads(latest.read_text(encoding="utf-8"))
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
