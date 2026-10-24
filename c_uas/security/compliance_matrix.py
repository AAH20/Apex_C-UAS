"""ISO 42001 / SOC 2 compliance matrix for the C-UAS platform.

Maps platform security controls to ISO/IEC 42001:2023 (AI management
system) and SOC 2 trust-services criteria, links each control to
evidence (hardening check IDs and penetration test scenario IDs), and
performs gap analysis. All judgments are computed deterministically
from audit and penetration results. No network, no live evidence
collection -- evidence references point at persisted state under
~/.c-uas-platform/security/.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from .hardening import HardeningAudit, HardeningCheck
from .penetration import PenTestReport, PenTestResult

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "security")
MATRIX_SUBDIR = "compliance"
LATEST_FILENAME = "latest_matrix.json"


@dataclass(frozen=True)
class Control:
    """One compliance control with evidence linkage and gap status."""

    control_id: str
    framework: str  # "ISO 42001" or "SOC 2"
    domain: str
    title: str
    description: str
    evidence_refs: Tuple[str, ...]
    implemented: bool
    gap: str


@dataclass(frozen=True)
class ComplianceMatrix:
    """Deterministic compliance matrix with per-framework coverage."""

    matrix_id: str
    controls: Tuple[Control, ...]
    iso_coverage: float
    soc2_coverage: float
    overall_coverage: float
    gaps: Tuple[str, ...]


FRAMEWORKS: Tuple[str, ...] = ("ISO 42001", "SOC 2")

# Control definitions: (control_id, framework, domain, title, description,
#   evidence_refs). Evidence refs are hardening check IDs or penetration
#   scenario IDs. A control is implemented when every referenced evidence
#   item passes.
CONTROL_SPECS: Tuple[Tuple[str, str, str, str, str, Tuple[str, ...]], ...] = (
    (
        "A.5.2",
        "ISO 42001",
        "Organizational controls",
        "Roles and responsibilities for AI security",
        "Security roles and responsibilities are assigned for AI systems.",
        ("TENANT-001", "PRIVESC-001"),
    ),
    (
        "A.6.2",
        "ISO 42001",
        "Organizational controls",
        "AI system risk and impact assessment",
        "Risks of AI systems, including misuse and data exposure, are assessed.",
        ("INJ-001", "SSRF-001"),
    ),
    (
        "A.7.2",
        "ISO 42001",
        "Resource controls",
        "AI data governance and sanitization",
        "Training and operational data are governed and sanitized; secrets never in code.",
        ("SECRET-002", "INJ-001"),
    ),
    (
        "A.8.2",
        "ISO 42001",
        "Technical controls",
        "Security of AI systems",
        "Technical security controls protect AI systems and their data.",
        ("NET-001", "NET-002", "SECRET-001"),
    ),
    (
        "A.9.3",
        "ISO 42001",
        "Monitoring controls",
        "Monitoring of AI system behavior",
        "AI system behavior and security events are continuously monitored.",
        ("AUDIT-001", "AUDIT-003"),
    ),
    (
        "A.10.3",
        "ISO 42001",
        "Monitoring controls",
        "Incident reporting and response",
        "Security incidents are detected, retained, and reported.",
        ("AUDIT-002", "AUDIT-003"),
    ),
    (
        "CC6.1",
        "SOC 2",
        "Logical access",
        "Logical access controls",
        "Access to data and systems is restricted to authorized tenants.",
        ("TENANT-002", "RLS-001"),
    ),
    (
        "CC6.6",
        "SOC 2",
        "External threat mitigation",
        "External threat mitigation",
        "External attack surfaces are restricted and monitored.",
        ("SSRF-001", "NET-001"),
    ),
    (
        "CC7.1",
        "SOC 2",
        "Monitoring and detection",
        "Security monitoring and detection",
        "Security-relevant events are detected and logged.",
        ("AUDIT-001", "AUDIT-003"),
    ),
    (
        "CC7.2",
        "SOC 2",
        "Incident response",
        "Incident response",
        "Incidents are identified and responded to per defined retention.",
        ("AUDIT-002",),
    ),
    (
        "CC8.1",
        "SOC 2",
        "Change management",
        "Cryptographic key management",
        "Keys and credentials are rotated and protected.",
        ("SECRET-001", "SECRET-002"),
    ),
    (
        "CC4.1",
        "SOC 2",
        "Confidentiality / privacy",
        "Tenant data confidentiality",
        "Tenant data cannot be read across tenant boundaries.",
        ("RLS-002", "TENANT-001"),
    ),
)


def _check_result_by_id(audit: HardeningAudit) -> Dict[str, HardeningCheck]:
    return {check.check_id: check for check in audit.checks}


def _pen_result_by_id(report: PenTestReport) -> Dict[str, PenTestResult]:
    return {result.scenario_id: result for result in report.results}


def _evidence_passed(
    refs: Tuple[str, ...],
    checks: Dict[str, Any],
    pens: Dict[str, Any],
) -> bool:
    for ref in refs:
        if ref in checks:
            if not checks[ref].passed:
                return False
        elif ref in pens:
            if not pens[ref].passed:
                return False
        else:
            return False
    return True


def build_matrix(audit: HardeningAudit, report: PenTestReport) -> ComplianceMatrix:
    """Build the compliance matrix (pure computation).

    Each control is implemented when every linked evidence item (hardening
    check or penetration scenario) passes. Gaps list unimplemented
    controls. Coverage is computed per framework.
    """
    checks = _check_result_by_id(audit)
    pens = _pen_result_by_id(report)

    controls: List[Control] = []
    gaps: List[str] = []
    for (
        control_id,
        framework,
        domain,
        title,
        description,
        refs,
    ) in CONTROL_SPECS:
        implemented = _evidence_passed(refs, checks, pens)
        gap = (
            ""
            if implemented
            else ("Not implemented: evidence references %s do not all pass." % ", ".join(refs))
        )
        if not implemented:
            gaps.append("%s: %s" % (control_id, title))
        controls.append(
            Control(
                control_id=control_id,
                framework=framework,
                domain=domain,
                title=title,
                description=description,
                evidence_refs=refs,
                implemented=implemented,
                gap=gap,
            )
        )

    iso_controls = [c for c in controls if c.framework == "ISO 42001"]
    soc2_controls = [c for c in controls if c.framework == "SOC 2"]
    iso_coverage = round(
        sum(1 for c in iso_controls if c.implemented) / len(iso_controls) * 100.0,
        2,
    )
    soc2_coverage = round(
        sum(1 for c in soc2_controls if c.implemented) / len(soc2_controls) * 100.0,
        2,
    )
    overall_coverage = round(
        sum(1 for c in controls if c.implemented) / len(controls) * 100.0,
        2,
    )

    payload = {
        "controls": [asdict(c) for c in sorted(controls, key=lambda c: c.control_id)],
        "overall_coverage": overall_coverage,
    }
    matrix_id = (
        "COMPLIANCE-"
        + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
    )

    return ComplianceMatrix(
        matrix_id=matrix_id,
        controls=tuple(controls),
        iso_coverage=iso_coverage,
        soc2_coverage=soc2_coverage,
        overall_coverage=overall_coverage,
        gaps=tuple(gaps),
    )


# --------------------------------------------------------------------------- #
# Persistence (outside the repo)
# --------------------------------------------------------------------------- #


class ComplianceMatrixStore:
    """Save/load compliance matrices under <state_dir>/compliance/."""

    def __init__(self, state_dir: str = DEFAULT_STATE_DIR) -> None:
        self.dir = os.path.join(state_dir, MATRIX_SUBDIR)

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, matrix_id: str) -> str:
        return os.path.join(self.dir, matrix_id + ".json")

    def save_matrix(self, matrix: ComplianceMatrix) -> str:
        """Atomically persist a matrix and return its matrix_id."""
        self.ensure_dir()
        data = asdict(matrix)
        data["controls"] = [dict(c) for c in data["controls"]]
        data["controls"] = [
            {k: (list(v) if k == "evidence_refs" else v) for k, v in c.items()}
            for c in data["controls"]
        ]
        tmp_path = self._path(matrix.matrix_id) + ".tmp"
        final_path = self._path(matrix.matrix_id)
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp_path, final_path)
        latest_path = os.path.join(os.path.dirname(self.dir), LATEST_FILENAME)
        tmp_latest = latest_path + ".tmp"
        with open(tmp_latest, "w", encoding="utf-8") as handle:
            json.dump({"matrix_id": matrix.matrix_id}, handle, indent=2)
        os.replace(tmp_latest, latest_path)
        return matrix.matrix_id

    def load_matrix(self, matrix_id: str) -> ComplianceMatrix:
        """Load a previously saved compliance matrix by id."""
        with open(self._path(matrix_id), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return _matrix_from_dict(data)

    def latest_matrix_id(self) -> Optional[str]:
        latest_path = os.path.join(os.path.dirname(self.dir), LATEST_FILENAME)
        if not os.path.exists(latest_path):
            return None
        with open(latest_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data.get("matrix_id")

    def latest_matrix(self) -> Optional[ComplianceMatrix]:
        matrix_id = self.latest_matrix_id()
        if matrix_id is None:
            return None
        return self.load_matrix(matrix_id)


def _matrix_from_dict(data: Dict[str, Any]) -> ComplianceMatrix:
    controls = tuple(
        Control(**{**c, "evidence_refs": tuple(c["evidence_refs"])}) for c in data["controls"]
    )
    return ComplianceMatrix(
        matrix_id=data["matrix_id"],
        controls=controls,
        iso_coverage=data["iso_coverage"],
        soc2_coverage=data["soc2_coverage"],
        overall_coverage=data["overall_coverage"],
        gaps=tuple(data["gaps"]),
    )
