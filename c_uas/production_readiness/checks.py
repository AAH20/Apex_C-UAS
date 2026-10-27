"""Per-domain production readiness checks.

Each check imports and calls a real platform module and returns a frozen
``DomainResult``. Nothing is faked: scores come from the real hardening
audit, the real composite health probe, the real contract gate, the real
cost model, the real evidence chain, the real edge fleet, and the real
capacity planner. All checks are deterministic given their inputs; no
network, no live credentials, no exploitation.

State for the persistence helpers lives under
~/.c-uas-platform/production_readiness/ (outside the repo).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Tuple

if TYPE_CHECKING:
    from c_uas.contract_readiness.contract import ContractReport
    from c_uas.datacenter.capacity import HeadroomAnalysis, RackSpec
    from c_uas.edge.fleet import FleetManager
    from c_uas.finops.cost_model import FacilityCost
    from c_uas.grc_clab.evidence_chain import EvidenceChain
    from c_uas.observability.health import CompositeHealth
    from c_uas.security.hardening import HardeningAudit, PlatformConfig

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "production_readiness")

# Pass thresholds per domain.
SECURITY_PASS_THRESHOLD = 80.0  # hardening audit score >= 80
OBSERVABILITY_PASS_THRESHOLD = 80.0  # composite health >= 80
EDGE_PASS_THRESHOLD = 80.0  # fleet health >= 80
DATACENTER_HEADROOM_GT = 0.0  # capacity headroom must be strictly > 0
OVERALL_GO_THRESHOLD = 85.0  # weighted-average readiness >= 85 for GO

# Domain weights for the weighted-average readiness score (sum to 1.0).
# Order is fixed for deterministic output.
DOMAIN_WEIGHTS: Dict[str, float] = {
    "security": 0.20,
    "observability": 0.15,
    "contract": 0.15,
    "finops": 0.10,
    "grc": 0.10,
    "edge": 0.15,
    "datacenter": 0.15,
}

# Every domain check is a hard gate for production readiness: a failed
# critical check forces NO-GO regardless of the overall weighted score.
CRITICAL_DOMAINS: Tuple[str, ...] = tuple(DOMAIN_WEIGHTS)


@dataclass(frozen=True)
class DomainResult:
    """One domain readiness check result."""

    domain: str  # "security" | "observability" | ...
    check: str  # check name, e.g. "hardening_audit"
    passed: bool  # gate met
    score: float  # 0-100 computed score
    threshold: float  # gate threshold (numeric where applicable)
    gate: str  # human-readable gate, e.g. "hardening_score >= 80.0"
    critical: bool  # failure blocks GO regardless of overall score
    remediation: Tuple[str, ...]  # remediation items when the check fails
    details: Dict[str, Any]  # raw domain detail (audit id, missing routes, ...)


# --------------------------------------------------------------------------- #
# Domain check results (pure computations around real module calls)
# --------------------------------------------------------------------------- #


def _domain_result(
    domain: str,
    check: str,
    passed: bool,
    score: float,
    threshold: float,
    gate: str,
    critical: bool,
    remediation: Tuple[str, ...],
    details: Optional[Dict[str, Any]] = None,
) -> DomainResult:
    return DomainResult(
        domain=domain,
        check=check,
        passed=bool(passed),
        score=round(float(score), 2),
        threshold=round(float(threshold), 2),
        gate=gate,
        critical=bool(critical),
        remediation=tuple(remediation),
        details=dict(details or {}),
    )


def _check_error(
    domain: str,
    check: str,
    gate: str,
    critical: bool,
    exc: Exception,
) -> DomainResult:
    return _domain_result(
        domain=domain,
        check=check,
        passed=False,
        score=0.0,
        threshold=0.0,
        gate=gate,
        critical=critical,
        remediation=(),
        details={"error": type(exc).__name__, "message": str(exc)},
    )


def security_check(
    config: Optional["PlatformConfig"] = None,
    audit: Optional["HardeningAudit"] = None,
) -> DomainResult:
    """Hardening audit score via ``c_uas.security.hardening.run_audit``.

    ``config`` defaults to ``PlatformConfig()``; pass an explicit config to
    score a different posture. ``audit`` may be injected (e.g. in tests) to
    avoid re-running the audit.
    """
    try:
        from c_uas.security.hardening import PlatformConfig as _PlatformConfig
        from c_uas.security.hardening import run_audit  # type: ignore

        if config is None:
            config = _PlatformConfig()
        if audit is None:
            audit = run_audit(config)
        score = float(audit.overall_score)
        passed = score >= SECURITY_PASS_THRESHOLD
        remediation = tuple(check.remediation for check in audit.checks if not check.passed)
        details = {
            "audit_id": audit.audit_id,
            "config_hash": audit.config_hash,
            "grade": audit.grade,
            "overall_score": audit.overall_score,
            "checks_passed": sum(1 for c in audit.checks if c.passed),
            "checks_total": len(audit.checks),
        }
    except Exception as exc:  # noqa: BLE001
        return _check_error("security", "hardening_audit", "hardening_score >= 80.0", True, exc)
    return _domain_result(
        domain="security",
        check="hardening_audit",
        passed=passed,
        score=score,
        threshold=SECURITY_PASS_THRESHOLD,
        gate="hardening_score >= 80.0",
        critical=True,
        remediation=remediation,
        details=details,
    )


def observability_check(
    composite: Optional["CompositeHealth"] = None,
    state_dir: Optional[str] = None,
) -> DomainResult:
    """Composite health via the ``c_uas.observability.health`` probes.

    Runs every component probe (performance, security, gateway, websockets,
    chaos, edge) against the real platform modules and aggregates the
    composite score. Pass an injected ``CompositeHealth`` to skip the probes.
    """
    try:
        from c_uas.observability.health import (  # type: ignore
            HealthAggregator,
            run_all_probes,
        )

        if composite is None:
            aggregator = HealthAggregator(state_dir=state_dir)
            run_all_probes(aggregator)
            composite = aggregator.composite()
        score = float(composite.composite_score)
        passed = score >= OBSERVABILITY_PASS_THRESHOLD
        remediation: List[str] = []
        if not passed:
            for health in composite.components:
                if health.score < OBSERVABILITY_PASS_THRESHOLD:
                    remediation.append(
                        f"Improve {health.component} health (score {health.score:.1f})"
                    )
            if not remediation:
                remediation = ["Investigate degraded/unhealthy platform components"]
        details = {
            "overall_status": composite.overall_status,
            "composite_score": composite.composite_score,
            "components": {
                c.component: {"status": c.status, "score": c.score} for c in composite.components
            },
            "unhealthy": list(composite.unhealthy),
        }
    except Exception as exc:  # noqa: BLE001
        return _check_error(
            "observability", "composite_health", "composite_health >= 80.0", True, exc
        )
    return _domain_result(
        domain="observability",
        check="composite_health",
        passed=passed,
        score=score,
        threshold=OBSERVABILITY_PASS_THRESHOLD,
        gate="composite_health >= 80.0",
        critical=True,
        remediation=tuple(remediation),
        details=details,
    )


def contract_check(
    spec_path: Optional[str] = None,
    app_routes: Optional[Sequence] = None,
    report: Optional["ContractReport"] = None,
) -> DomainResult:
    """Contract gate via ``c_uas.contract_readiness.contract.verify_contract``.

    Passes when the app route table has no missing routes against the spec.
    Fail-closed: no spec path means the check cannot pass.
    """
    try:
        from c_uas.contract_readiness.contract import (  # type: ignore
            load_app_routes,
            verify_contract,
        )

        if report is None:
            if spec_path is None:
                return _domain_result(
                    domain="contract",
                    check="missing_routes",
                    passed=False,
                    score=0.0,
                    threshold=0.0,
                    gate="missing_routes == 0",
                    critical=True,
                    remediation=(
                        "Add an OpenAPI spec and run `c-uas contract --gate "
                        "--spec <spec>` so the contract gate can verify routes.",
                    ),
                    details={"error": "no_spec_path", "missing": []},
                )
            if app_routes is None:
                app_routes = load_app_routes()
            report = verify_contract(spec_path, list(app_routes))
        missing = list(report.missing)
        spec_routes = list(report.spec_routes)
        if spec_routes:
            score = round(100.0 * (len(spec_routes) - len(missing)) / len(spec_routes), 2)
        else:
            score = 100.0
        passed = len(missing) == 0
        remediation = tuple(f"Implement route {entry.method} {entry.path}" for entry in missing)
        details = {
            "spec_path": getattr(report, "spec_path", spec_path),
            "spec_route_count": len(spec_routes),
            "app_route_count": len(list(report.app_routes)),
            "missing": [{"method": entry.method, "path": entry.path} for entry in missing],
            "ok": bool(report.ok),
        }
    except Exception as exc:  # noqa: BLE001
        return _check_error("contract", "missing_routes", "missing_routes == 0", True, exc)
    return _domain_result(
        domain="contract",
        check="missing_routes",
        passed=passed,
        score=score,
        threshold=0.0,
        gate="missing_routes == 0",
        critical=True,
        remediation=remediation,
        details=details,
    )


def finops_check(cost: Optional["FacilityCost"] = None) -> DomainResult:
    """Cost model validity via ``c_uas.finops.cost_model.compute_facility_cost``.

    Passes when the model computes a coherent result (positive facility draw,
    non-negative power cost, PUE cost multiplier >= 1).
    """
    try:
        from c_uas.finops.cost_model import compute_facility_cost  # type: ignore

        if cost is None:
            cost = compute_facility_cost(it_load_kw=100.0)
        valid = bool(
            cost.total_facility_kw > 0
            and cost.monthly_power_cost_usd >= 0
            and cost.pue_cost_multiplier >= 1.0
        )
        score = 100.0 if valid else 0.0
        details = {
            "it_load_kw": cost.it_load_kw,
            "total_facility_kw": cost.total_facility_kw,
            "monthly_power_cost_usd": cost.monthly_power_cost_usd,
            "pue_cost_multiplier": cost.pue_cost_multiplier,
        }
    except Exception as exc:  # noqa: BLE001
        return _check_error("finops", "cost_model_valid", "cost_model_valid == true", True, exc)
    return _domain_result(
        domain="finops",
        check="cost_model_valid",
        passed=valid,
        score=score,
        threshold=1.0,
        gate="cost_model_valid == true",
        critical=True,
        remediation=(),
        details=details,
    )


def grc_check(chain: Optional["EvidenceChain"] = None) -> DomainResult:
    """Evidence chain verification via ``c_uas.grc_clab.evidence_chain``.

    Passes when the hash-linked evidence chain verifies (tamper-intact).
    """
    try:
        from c_uas.grc_clab.evidence_chain import EvidenceChain as _EvidenceChain  # type: ignore

        if chain is None:
            chain = _EvidenceChain()
        verified = bool(chain.verify_chain())
        score = 100.0 if verified else 0.0
        details = {
            "entry_count": chain.entry_count(),
            "head_hash": chain.head_hash(),
        }
    except Exception as exc:  # noqa: BLE001
        return _check_error(
            "grc", "evidence_chain_verifies", "evidence_chain_verifies == true", True, exc
        )
    return _domain_result(
        domain="grc",
        check="evidence_chain_verifies",
        passed=verified,
        score=score,
        threshold=1.0,
        gate="evidence_chain_verifies == true",
        critical=True,
        remediation=(),
        details=details,
    )


def edge_check(fleet_manager: Optional["FleetManager"] = None) -> DomainResult:
    """Fleet health via ``c_uas.edge.fleet.FleetManager.fleet_health``.

    Passes when the average edge-node health score is >= 80 and at least one
    node is registered.
    """
    try:
        from c_uas.edge.fleet import FleetManager as _FleetManager  # type: ignore

        fm = fleet_manager if fleet_manager is not None else _FleetManager()
        report = fm.fleet_health()
        score = float(report.average_health_score)
        passed = score >= EDGE_PASS_THRESHOLD and report.total_nodes > 0
        remediation: List[str] = []
        if not passed:
            if report.total_nodes == 0:
                remediation.append("Register at least one edge node in the fleet")
            else:
                remediation.append(
                    f"Restore edge fleet health (average "
                    f"{report.average_health_score:.1f} < {EDGE_PASS_THRESHOLD:.0f})"
                )
        details = {
            "total_nodes": report.total_nodes,
            "active_nodes": report.active_nodes,
            "offline_nodes": report.offline_nodes,
            "average_health_score": report.average_health_score,
            "by_tenant": dict(report.by_tenant),
        }
    except Exception as exc:  # noqa: BLE001
        return _check_error("edge", "fleet_health", "fleet_health >= 80.0", True, exc)
    return _domain_result(
        domain="edge",
        check="fleet_health",
        passed=passed,
        score=score,
        threshold=EDGE_PASS_THRESHOLD,
        gate="fleet_health >= 80.0",
        critical=True,
        remediation=tuple(remediation),
        details=details,
    )


def datacenter_check(
    headroom: Optional["HeadroomAnalysis"] = None,
    spec: Optional["RackSpec"] = None,
    it_load_kw: float = 70.0,
    cooling_load_kw: float = 25.0,
    compute_units: int = 30,
) -> DomainResult:
    """Capacity headroom via ``c_uas.datacenter.capacity.compute_headroom``.

    Passes when every resource (power, cooling, space) retains strictly
    positive headroom percentage.
    """
    try:
        from c_uas.datacenter.capacity import (  # type: ignore
            RackSpec as _RackSpec,
        )
        from c_uas.datacenter.capacity import (
            compute_headroom,
        )

        if headroom is None:
            if spec is None:
                spec = _RackSpec(
                    rack_id="rack-1",
                    max_power_kw=100.0,
                    max_cooling_kw=40.0,
                    max_rack_units=42,
                )
            headroom = compute_headroom("rack-1", it_load_kw, cooling_load_kw, compute_units, spec)
        headrooms = (
            headroom.headroom_power_pct,
            headroom.headroom_cooling_pct,
            headroom.headroom_units_pct,
        )
        limiting = min(headrooms)
        score = round(max(0.0, min(100.0, limiting)), 2)
        passed = limiting > DATACENTER_HEADROOM_GT
        remediation: List[str] = []
        if not passed:
            remediation.append(
                f"Add capacity: limiting factor {headroom.limiting_factor} "
                f"has {limiting:.1f}% headroom (must be > 0)"
            )
        details = {
            "rack_id": headroom.rack_id,
            "available_power_kw": headroom.available_power_kw,
            "available_cooling_kw": headroom.available_cooling_kw,
            "available_rack_units": headroom.available_rack_units,
            "headroom_power_pct": headroom.headroom_power_pct,
            "headroom_cooling_pct": headroom.headroom_cooling_pct,
            "headroom_units_pct": headroom.headroom_units_pct,
            "limiting_factor": headroom.limiting_factor,
        }
    except Exception as exc:  # noqa: BLE001
        return _check_error("datacenter", "capacity_headroom", "capacity_headroom > 0.0", True, exc)
    return _domain_result(
        domain="datacenter",
        check="capacity_headroom",
        passed=passed,
        score=score,
        threshold=DATACENTER_HEADROOM_GT,
        gate="capacity_headroom > 0.0",
        critical=True,
        remediation=tuple(remediation),
        details=details,
    )


# --------------------------------------------------------------------------- #
# Check registry
# --------------------------------------------------------------------------- #

_CHECK_FUNCTIONS: Dict[str, Callable[..., DomainResult]] = {
    "security": security_check,
    "observability": observability_check,
    "contract": contract_check,
    "finops": finops_check,
    "grc": grc_check,
    "edge": edge_check,
    "datacenter": datacenter_check,
}


def domain_check(domain: str) -> DomainResult:
    """Run one registered domain check with default inputs."""
    if domain not in _CHECK_FUNCTIONS:
        raise ValueError(f"Unknown readiness domain: {domain}")
    return _CHECK_FUNCTIONS[domain]()


def all_checks() -> Tuple[DomainResult, ...]:
    """Run every domain check with default inputs, in fixed domain order."""
    return tuple(_CHECK_FUNCTIONS[domain]() for domain in DOMAIN_WEIGHTS)
