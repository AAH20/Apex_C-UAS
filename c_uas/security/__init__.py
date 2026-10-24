"""Production hardening and security for the C-UAS platform.

Hardening audit, penetration test framework, and ISO 42001 / SOC 2
compliance matrix. All evaluations are deterministic, defensive only
(no exploitation, no live targets, no network), and computed from
configuration flags rather than secrets.

State persists under ~/.c-uas-platform/security/ (outside the repo).
"""

from .compliance_matrix import (
    ComplianceMatrix,
    ComplianceMatrixStore,
    build_matrix,
)
from .hardening import (
    DEFAULT_STATE_DIR,
    HardeningAudit,
    HardeningAuditStore,
    HardeningCheck,
    PlatformConfig,
    run_audit,
)
from .penetration import (
    ALL_SCENARIOS,
    PenTestReport,
    PenTestReportStore,
    PenTestResult,
    PenTestScenario,
    run_penetration_test,
)

__all__ = [
    "DEFAULT_STATE_DIR",
    "ALL_SCENARIOS",
    "HardeningAudit",
    "HardeningAuditStore",
    "HardeningCheck",
    "PenTestReport",
    "PenTestReportStore",
    "PenTestResult",
    "PenTestScenario",
    "PlatformConfig",
    "ComplianceMatrix",
    "ComplianceMatrixStore",
    "build_matrix",
    "run_audit",
    "run_penetration_test",
]
