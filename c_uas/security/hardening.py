"""Production hardening audit for the C-UAS platform.

Evaluates tenant isolation, row-level security (RLS), secret management,
zero-trust network policies, and audit-trail completeness against a
platform configuration and produces a deterministic 0-100 security score
with a letter grade.

All values are computed from the supplied configuration -- no network, no
live credentials, no exploitation. Audit state persists under
~/.c-uas-platform/security/ (outside the repo).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "security")
AUDITS_SUBDIR = "audits"
LATEST_FILENAME = "latest_audit.json"

# Category weights (sum to 1.0). Order is fixed for deterministic output.
CATEGORY_WEIGHTS: Dict[str, float] = {
    "tenant_isolation": 0.25,
    "rls": 0.20,
    "secret_management": 0.20,
    "zero_trust_network": 0.20,
    "audit_trail": 0.15,
}

# Within-category check weights (each category's weights sum to 1.0).
CHECK_WEIGHTS: Dict[str, float] = {
    "TENANT-001": 0.5,
    "TENANT-002": 0.5,
    "RLS-001": 0.5,
    "RLS-002": 0.5,
    "SECRET-001": 0.4,
    "SECRET-002": 0.6,
    "NET-001": 0.5,
    "NET-002": 0.5,
    "AUDIT-001": 0.3,
    "AUDIT-002": 0.3,
    "AUDIT-003": 0.4,
}

GRADE_BANDS: List[Tuple[int, str]] = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]

MAX_SCORE = 100.0


@dataclass(frozen=True)
class PlatformConfig:
    """Observable platform security configuration. Inputs are configuration
    flags only -- never secrets or credentials."""

    tenant_isolation_enforced: bool = False
    tenant_scoped_queries: bool = False
    cross_tenant_access_blocked: bool = False
    rls_enabled: bool = False
    rls_applied_to_all_tables: bool = False
    secret_rotation_days: int = 0
    secrets_in_environment: bool = False
    no_plaintext_secrets_in_code: bool = False
    key_management_service: bool = False
    zero_trust_network_policies: bool = False
    mtls_enforced: bool = False
    default_deny_ingress: bool = False
    network_segmentation: bool = False
    audit_logging_enabled: bool = False
    audit_trail_retention_days: int = 0
    audit_logs_immutable: bool = False
    audit_events_cover_authz: bool = False


@dataclass(frozen=True)
class HardeningCheck:
    """Single hardening control evaluation. Deterministic given a config."""

    check_id: str
    category: str
    title: str
    description: str
    passed: bool
    evidence: str
    weight: float
    score: float
    remediation: str


@dataclass(frozen=True)
class HardeningAudit:
    """Deterministic hardening audit result."""

    audit_id: str
    config_hash: str
    checks: Tuple[HardeningCheck, ...]
    overall_score: float
    grade: str


def grade_for(score: float) -> str:
    """Letter grade for a numeric score (deterministic bands)."""
    for threshold, grade in GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"


def config_hash(config: PlatformConfig) -> str:
    """Content hash of a platform configuration (deterministic)."""
    payload: Dict[str, Any] = asdict(config)
    return "CFG-" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Individual check evaluations (pure functions)
# --------------------------------------------------------------------------- #


def _check_tenant_isolation(config: PlatformConfig) -> List[HardeningCheck]:
    checks: List[HardeningCheck] = []
    passed = bool(config.tenant_isolation_enforced and config.cross_tenant_access_blocked)
    checks.append(
        HardeningCheck(
            check_id="TENANT-001",
            category="tenant_isolation",
            title="Tenant isolation enforced across services",
            description=(
                "Every service enforces tenant boundaries and rejects "
                "cross-tenant requests by default."
            ),
            passed=passed,
            evidence=(
                "tenant_isolation_enforced=%s, "
                "cross_tenant_access_blocked=%s"
                % (config.tenant_isolation_enforced, config.cross_tenant_access_blocked)
            ),
            weight=CHECK_WEIGHTS["TENANT-001"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Enable tenant context propagation in every service and "
                "reject requests lacking a valid tenant ID; add integration "
                "tests that assert cross-tenant requests are denied."
            ),
        )
    )
    passed = bool(config.tenant_scoped_queries)
    checks.append(
        HardeningCheck(
            check_id="TENANT-002",
            category="tenant_isolation",
            title="Every cross-service request carries tenant context",
            description="All inter-service requests include a tenant ID for scoping.",
            passed=passed,
            evidence="tenant_scoped_queries=%s" % config.tenant_scoped_queries,
            weight=CHECK_WEIGHTS["TENANT-002"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Inject the authenticated tenant ID into all downstream "
                "service calls and reject calls where it is missing."
            ),
        )
    )
    return checks


def _check_rls(config: PlatformConfig) -> List[HardeningCheck]:
    checks: List[HardeningCheck] = []
    passed = bool(config.rls_enabled)
    checks.append(
        HardeningCheck(
            check_id="RLS-001",
            category="rls",
            title="Row-level security enabled on the data layer",
            description="RLS policies restrict rows to the requesting tenant.",
            passed=passed,
            evidence="rls_enabled=%s" % config.rls_enabled,
            weight=CHECK_WEIGHTS["RLS-001"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Enable RLS on every table holding tenant data and bind "
                "policies to the authenticated tenant context."
            ),
        )
    )
    passed = bool(config.rls_applied_to_all_tables)
    checks.append(
        HardeningCheck(
            check_id="RLS-002",
            category="rls",
            title="RLS applied to all data tables",
            description="No tenant table is exempt from row-level security.",
            passed=passed,
            evidence="rls_applied_to_all_tables=%s" % config.rls_applied_to_all_tables,
            weight=CHECK_WEIGHTS["RLS-002"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Audit the table inventory against the RLS policy catalog "
                "and add missing policies before any table goes live."
            ),
        )
    )
    return checks


def _check_secret_management(config: PlatformConfig) -> List[HardeningCheck]:
    checks: List[HardeningCheck] = []
    passed = bool(0 < config.secret_rotation_days <= 90)
    checks.append(
        HardeningCheck(
            check_id="SECRET-001",
            category="secret_management",
            title="Secret rotation configured within 90 days",
            description="Rotated credentials limit blast radius of leaks.",
            passed=passed,
            evidence="secret_rotation_days=%d" % config.secret_rotation_days,
            weight=CHECK_WEIGHTS["SECRET-001"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Configure automatic rotation for every credential with a "
                "maximum interval of 90 days."
            ),
        )
    )
    passed = bool(
        config.secrets_in_environment
        and config.no_plaintext_secrets_in_code
        and config.key_management_service
    )
    checks.append(
        HardeningCheck(
            check_id="SECRET-002",
            category="secret_management",
            title="Secrets sourced from environment or KMS, never from code",
            description="No plaintext secrets committed; keys are KMS-managed.",
            passed=passed,
            evidence=(
                "secrets_in_environment=%s, no_plaintext_secrets_in_code=%s, "
                "key_management_service=%s"
                % (
                    config.secrets_in_environment,
                    config.no_plaintext_secrets_in_code,
                    config.key_management_service,
                )
            ),
            weight=CHECK_WEIGHTS["SECRET-002"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Move all secrets out of source code into environment "
                "variables or a KMS, rotate any previously committed "
                "credentials, and add a pre-commit secret scan."
            ),
        )
    )
    return checks


def _check_zero_trust_network(config: PlatformConfig) -> List[HardeningCheck]:
    checks: List[HardeningCheck] = []
    passed = bool(config.zero_trust_network_policies and config.default_deny_ingress)
    checks.append(
        HardeningCheck(
            check_id="NET-001",
            category="zero_trust_network",
            title="Zero-trust network policies with default-deny ingress",
            description="All ingress is denied unless explicitly allowed by policy.",
            passed=passed,
            evidence=(
                "zero_trust_network_policies=%s, default_deny_ingress=%s"
                % (
                    config.zero_trust_network_policies,
                    config.default_deny_ingress,
                )
            ),
            weight=CHECK_WEIGHTS["NET-001"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Adopt default-deny ingress network policies per namespace "
                "and allow-list only required service-to-service paths."
            ),
        )
    )
    passed = bool(config.mtls_enforced and config.network_segmentation)
    checks.append(
        HardeningCheck(
            check_id="NET-002",
            category="zero_trust_network",
            title="mTLS enforced plus network segmentation",
            description="Service-to-service traffic is encrypted and segmented.",
            passed=passed,
            evidence=(
                "mtls_enforced=%s, network_segmentation=%s"
                % (config.mtls_enforced, config.network_segmentation)
            ),
            weight=CHECK_WEIGHTS["NET-002"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Enforce mTLS between all services and segment the network "
                "so a compromised component cannot reach unrelated tenants."
            ),
        )
    )
    return checks


def _check_audit_trail(config: PlatformConfig) -> List[HardeningCheck]:
    checks: List[HardeningCheck] = []
    passed = bool(config.audit_logging_enabled)
    checks.append(
        HardeningCheck(
            check_id="AUDIT-001",
            category="audit_trail",
            title="Audit logging enabled",
            description="Security-relevant events are recorded durably.",
            passed=passed,
            evidence="audit_logging_enabled=%s" % config.audit_logging_enabled,
            weight=CHECK_WEIGHTS["AUDIT-001"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Enable audit logging on all entry points and forward logs "
                "to tamper-resistant storage."
            ),
        )
    )
    passed = bool(config.audit_trail_retention_days >= 90)
    checks.append(
        HardeningCheck(
            check_id="AUDIT-002",
            category="audit_trail",
            title="Audit trail retention of at least 90 days",
            description="Logs are retained long enough for incident investigation.",
            passed=passed,
            evidence="audit_trail_retention_days=%d" % config.audit_trail_retention_days,
            weight=CHECK_WEIGHTS["AUDIT-002"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Set log retention to at least 90 days and archive older "
                "logs to cold storage instead of deleting them."
            ),
        )
    )
    passed = bool(config.audit_logs_immutable and config.audit_events_cover_authz)
    checks.append(
        HardeningCheck(
            check_id="AUDIT-003",
            category="audit_trail",
            title="Immutable audit logs covering authentication and authorization",
            description="AuthN/AuthZ events are immutable and complete.",
            passed=passed,
            evidence=(
                "audit_logs_immutable=%s, audit_events_cover_authz=%s"
                % (config.audit_logs_immutable, config.audit_events_cover_authz)
            ),
            weight=CHECK_WEIGHTS["AUDIT-003"],
            score=MAX_SCORE if passed else 0.0,
            remediation=(
                "Make audit writes append-only (WORM storage or signed "
                "log entries) and ensure every authentication and "
                "authorization decision is emitted as an audit event."
            ),
        )
    )
    return checks


_CHECK_FUNCTIONS = {
    "tenant_isolation": _check_tenant_isolation,
    "rls": _check_rls,
    "secret_management": _check_secret_management,
    "zero_trust_network": _check_zero_trust_network,
    "audit_trail": _check_audit_trail,
}


def run_audit(config: PlatformConfig) -> HardeningAudit:
    """Run the full hardening audit (pure computation, no I/O).

    Returns a HardeningAudit with a content-hash audit_id so identical
    configurations produce identical audits.
    """
    category_scores: Dict[str, float] = {}
    all_checks: List[HardeningCheck] = []
    for category in CATEGORY_WEIGHTS:
        checks = _CHECK_FUNCTIONS[category](config)
        all_checks.extend(checks)
        category_scores[category] = sum(check.weight * check.score for check in checks)
    overall_score = round(
        sum(
            CATEGORY_WEIGHTS[category] * category_scores[category] for category in CATEGORY_WEIGHTS
        ),
        2,
    )
    audit_id = (
        "HARDEN-"
        + hashlib.sha256(
            json.dumps(
                [
                    {
                        "check_id": check.check_id,
                        "passed": check.passed,
                        "score": check.score,
                    }
                    for check in sorted(all_checks, key=lambda c: c.check_id)
                ],
                sort_keys=True,
            ).encode()
        ).hexdigest()[:16]
    )
    return HardeningAudit(
        audit_id=audit_id,
        config_hash=config_hash(config),
        checks=tuple(all_checks),
        overall_score=overall_score,
        grade=grade_for(overall_score),
    )


# --------------------------------------------------------------------------- #
# Persistence (outside the repo)
# --------------------------------------------------------------------------- #


class HardeningAuditStore:
    """Save/load hardening audits under <state_dir>/audits/."""

    def __init__(self, state_dir: str = DEFAULT_STATE_DIR) -> None:
        self.dir = os.path.join(state_dir, AUDITS_SUBDIR)

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, audit_id: str) -> str:
        return os.path.join(self.dir, audit_id + ".json")

    def save_audit(self, audit: HardeningAudit) -> str:
        """Atomically persist an audit and return its audit_id."""
        self.ensure_dir()
        data = asdict(audit)
        data["checks"] = [dict(c) for c in data["checks"]]
        tmp_path = self._path(audit.audit_id) + ".tmp"
        final_path = self._path(audit.audit_id)
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp_path, final_path)
        latest_path = os.path.join(os.path.dirname(self.dir), LATEST_FILENAME)
        tmp_latest = latest_path + ".tmp"
        with open(tmp_latest, "w", encoding="utf-8") as handle:
            json.dump({"audit_id": audit.audit_id}, handle, indent=2)
        os.replace(tmp_latest, latest_path)
        return audit.audit_id

    def load_audit(self, audit_id: str) -> HardeningAudit:
        """Load a previously saved audit by id."""
        with open(self._path(audit_id), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return _audit_from_dict(data)

    def latest_audit_id(self) -> Optional[str]:
        latest_path = os.path.join(os.path.dirname(self.dir), LATEST_FILENAME)
        if not os.path.exists(latest_path):
            return None
        with open(latest_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data.get("audit_id")

    def latest_audit(self) -> Optional[HardeningAudit]:
        audit_id = self.latest_audit_id()
        if audit_id is None:
            return None
        return self.load_audit(audit_id)


def _audit_from_dict(data: Dict[str, Any]) -> HardeningAudit:
    checks = tuple(HardeningCheck(**check) for check in data["checks"])
    return HardeningAudit(
        audit_id=data["audit_id"],
        config_hash=data["config_hash"],
        checks=checks,
        overall_score=data["overall_score"],
        grade=data["grade"],
    )
