"""Penetration test framework for the C-UAS platform.

Simulates five attack scenarios against a platform configuration and
reports pass/fail per scenario:

  AUTH-001  Authentication bypass (forged / stolen token)
  INJ-001   Injection (SQL / NoSQL against tenant data)
  PRIVESC-001  Privilege escalation (cross-tenant access)
  IDOR-001  Insecure direct object reference (object-ID guessing)
  SSRF-001  Server-side request forgery to internal endpoints

A scenario PASSES when the platform controls modeled in the configuration
mitigate the attack. This is defensive only: no exploitation, no live
targets, no network traffic. Results are deterministic for a given
configuration. State persists under ~/.c-uas-platform/security/.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from .hardening import PlatformConfig

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "security")
REPORTS_SUBDIR = "penetration"
LATEST_FILENAME = "latest_penetration_report.json"

MAX_SCORE = 100.0


@dataclass(frozen=True)
class PenTestScenario:
    """One attack scenario with deterministic expected mitigation."""

    scenario_id: str
    name: str
    category: str
    description: str
    attack_vector: str
    severity: str
    remediation: str


@dataclass(frozen=True)
class PenTestResult:
    """Pass/fail outcome for one scenario."""

    scenario_id: str
    passed: bool
    evidence: str
    risk_level: str


@dataclass(frozen=True)
class PenTestReport:
    """Deterministic penetration test report."""

    report_id: str
    config_hash: str
    results: Tuple[PenTestResult, ...]
    overall_passed: bool
    pass_rate: float


ALL_SCENARIOS: Tuple[PenTestScenario, ...] = (
    PenTestScenario(
        scenario_id="AUTH-001",
        name="Authentication bypass via forged token",
        category="auth_bypass",
        description=(
            "Attacker attempts to authenticate with a forged or stolen "
            "session token to impersonate a tenant administrator."
        ),
        attack_vector="forged JWT / session token",
        severity="CRITICAL",
        remediation=(
            "Move signing keys out of source code into a KMS, require "
            "short-lived tokens, and log every authentication event."
        ),
    ),
    PenTestScenario(
        scenario_id="INJ-001",
        name="SQL injection against tenant data",
        category="injection",
        description=(
            "Attacker injects SQL through an input field to read or "
            "modify records belonging to other tenants."
        ),
        attack_vector="unsanitized SQL / NoSQL query parameter",
        severity="HIGH",
        remediation=(
            "Use parameterized queries everywhere, enable row-level "
            "security, and enforce tenant scoping on all queries."
        ),
    ),
    PenTestScenario(
        scenario_id="PRIVESC-001",
        name="Privilege escalation via cross-tenant access",
        category="privilege_escalation",
        description=(
            "Attacker with a valid tenant token attempts to access "
            "resources of another tenant by guessing internal IDs."
        ),
        attack_vector="missing cross-tenant authorization checks",
        severity="HIGH",
        remediation=(
            "Enforce cross-tenant access blocking, audit every "
            "authorization decision, and require mTLS between services."
        ),
    ),
    PenTestScenario(
        scenario_id="IDOR-001",
        name="Insecure direct object reference (object-ID guessing)",
        category="idor",
        description=(
            "Attacker substitutes object IDs in requests to read or modify objects they do not own."
        ),
        attack_vector="predictable object identifiers in URLs",
        severity="MEDIUM",
        remediation=(
            "Scope every object lookup to the authenticated tenant ID, "
            "back it with RLS, and log access attempts."
        ),
    ),
    PenTestScenario(
        scenario_id="SSRF-001",
        name="Server-side request forgery to internal endpoints",
        category="ssrf",
        description=(
            "Attacker forces the platform to make requests to internal "
            "metadata or management endpoints it should not reach."
        ),
        attack_vector="unvalidated fetch target supplied by user input",
        severity="HIGH",
        remediation=(
            "Enforce zero-trust network policies with default-deny "
            "ingress, segment the network, and validate outbound targets."
        ),
    ),
)


def _scenario_by_id(scenario_id: str) -> PenTestScenario:
    for scenario in ALL_SCENARIOS:
        if scenario.scenario_id == scenario_id:
            return scenario
    raise KeyError("Unknown scenario: %s" % scenario_id)


def _evaluate_auth_bypass(config: PlatformConfig) -> PenTestResult:
    passed = bool(
        config.no_plaintext_secrets_in_code
        and config.key_management_service
        and config.audit_logging_enabled
    )
    evidence = (
        "no_plaintext_secrets_in_code=%s, key_management_service=%s, "
        "audit_logging_enabled=%s"
        % (
            config.no_plaintext_secrets_in_code,
            config.key_management_service,
            config.audit_logging_enabled,
        )
    )
    return PenTestResult(
        scenario_id="AUTH-001",
        passed=passed,
        evidence=evidence,
        risk_level="LOW" if passed else "HIGH",
    )


def _evaluate_injection(config: PlatformConfig) -> PenTestResult:
    passed = bool(
        config.rls_enabled and config.rls_applied_to_all_tables and config.tenant_isolation_enforced
    )
    evidence = "rls_enabled=%s, rls_applied_to_all_tables=%s, tenant_isolation_enforced=%s" % (
        config.rls_enabled,
        config.rls_applied_to_all_tables,
        config.tenant_isolation_enforced,
    )
    return PenTestResult(
        scenario_id="INJ-001",
        passed=passed,
        evidence=evidence,
        risk_level="LOW" if passed else "HIGH",
    )


def _evaluate_privilege_escalation(config: PlatformConfig) -> PenTestResult:
    passed = bool(
        config.cross_tenant_access_blocked
        and config.audit_events_cover_authz
        and config.mtls_enforced
    )
    evidence = "cross_tenant_access_blocked=%s, audit_events_cover_authz=%s, mtls_enforced=%s" % (
        config.cross_tenant_access_blocked,
        config.audit_events_cover_authz,
        config.mtls_enforced,
    )
    return PenTestResult(
        scenario_id="PRIVESC-001",
        passed=passed,
        evidence=evidence,
        risk_level="LOW" if passed else "HIGH",
    )


def _evaluate_idor(config: PlatformConfig) -> PenTestResult:
    passed = bool(
        config.tenant_scoped_queries and config.rls_enabled and config.audit_logging_enabled
    )
    evidence = "tenant_scoped_queries=%s, rls_enabled=%s, audit_logging_enabled=%s" % (
        config.tenant_scoped_queries,
        config.rls_enabled,
        config.audit_logging_enabled,
    )
    return PenTestResult(
        scenario_id="IDOR-001",
        passed=passed,
        evidence=evidence,
        risk_level="LOW" if passed else "HIGH",
    )


def _evaluate_ssrf(config: PlatformConfig) -> PenTestResult:
    passed = bool(
        config.zero_trust_network_policies
        and config.default_deny_ingress
        and config.network_segmentation
    )
    evidence = (
        "zero_trust_network_policies=%s, default_deny_ingress=%s, "
        "network_segmentation=%s"
        % (
            config.zero_trust_network_policies,
            config.default_deny_ingress,
            config.network_segmentation,
        )
    )
    return PenTestResult(
        scenario_id="SSRF-001",
        passed=passed,
        evidence=evidence,
        risk_level="LOW" if passed else "HIGH",
    )


_EVALUATORS = {
    "AUTH-001": _evaluate_auth_bypass,
    "INJ-001": _evaluate_injection,
    "PRIVESC-001": _evaluate_privilege_escalation,
    "IDOR-001": _evaluate_idor,
    "SSRF-001": _evaluate_ssrf,
}


def config_hash(config: PlatformConfig) -> str:
    """Content hash of a platform configuration (deterministic)."""
    payload: Dict[str, Any] = asdict(config)
    return "CFG-" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def run_penetration_test(config: PlatformConfig) -> PenTestReport:
    """Run all penetration scenarios (pure computation, no I/O).

    Results are deterministic: identical configurations produce identical
    reports.
    """
    results: List[PenTestResult] = []
    for scenario in ALL_SCENARIOS:
        result = _EVALUATORS[scenario.scenario_id](config)
        results.append(result)
    passed_count = sum(1 for result in results if result.passed)
    pass_rate = round(passed_count / len(results) * MAX_SCORE, 2)
    report_id = (
        "PENTEST-"
        + hashlib.sha256(
            json.dumps(
                [
                    {
                        "scenario_id": result.scenario_id,
                        "passed": result.passed,
                        "risk_level": result.risk_level,
                    }
                    for result in sorted(results, key=lambda r: r.scenario_id)
                ],
                sort_keys=True,
            ).encode()
        ).hexdigest()[:16]
    )
    return PenTestReport(
        report_id=report_id,
        config_hash=config_hash(config),
        results=tuple(results),
        overall_passed=bool(results) and all(result.passed for result in results),
        pass_rate=pass_rate,
    )


# --------------------------------------------------------------------------- #
# Persistence (outside the repo)
# --------------------------------------------------------------------------- #


class PenTestReportStore:
    """Save/load penetration reports under <state_dir>/penetration/."""

    def __init__(self, state_dir: str = DEFAULT_STATE_DIR) -> None:
        self.dir = os.path.join(state_dir, REPORTS_SUBDIR)

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, report_id: str) -> str:
        return os.path.join(self.dir, report_id + ".json")

    def save_report(self, report: PenTestReport) -> str:
        """Atomically persist a report and return its report_id."""
        self.ensure_dir()
        data = asdict(report)
        data["results"] = [dict(r) for r in data["results"]]
        tmp_path = self._path(report.report_id) + ".tmp"
        final_path = self._path(report.report_id)
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp_path, final_path)
        latest_path = os.path.join(os.path.dirname(self.dir), LATEST_FILENAME)
        tmp_latest = latest_path + ".tmp"
        with open(tmp_latest, "w", encoding="utf-8") as handle:
            json.dump({"report_id": report.report_id}, handle, indent=2)
        os.replace(tmp_latest, latest_path)
        return report.report_id

    def load_report(self, report_id: str) -> PenTestReport:
        """Load a previously saved penetration report by id."""
        with open(self._path(report_id), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return _report_from_dict(data)

    def latest_report_id(self) -> Optional[str]:
        latest_path = os.path.join(os.path.dirname(self.dir), LATEST_FILENAME)
        if not os.path.exists(latest_path):
            return None
        with open(latest_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data.get("report_id")

    def latest_report(self) -> Optional[PenTestReport]:
        report_id = self.latest_report_id()
        if report_id is None:
            return None
        return self.load_report(report_id)


def _report_from_dict(data: Dict[str, Any]) -> PenTestReport:
    results = tuple(PenTestResult(**result) for result in data["results"])
    return PenTestReport(
        report_id=data["report_id"],
        config_hash=data["config_hash"],
        results=results,
        overall_passed=data["overall_passed"],
        pass_rate=data["pass_rate"],
    )
