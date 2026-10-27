"""Production Readiness Review for the C-UAS platform.

Aggregates per-domain readiness checks across the whole platform
(security, observability, contract, finops, grc, edge, datacenter) into a
single release go/no-go decision:

- security   : hardening audit score >= 80  (c_uas.security.hardening.run_audit)
- observability : composite health >= 80  (c_uas.observability.health probes)
- contract   : no missing OpenAPI routes  (c_uas.contract_readiness.contract.verify_contract)
- finops     : cost model valid  (c_uas.finops.cost_model.compute_facility_cost)
- grc        : evidence chain verifies  (c_uas.grc_clab.evidence_chain.EvidenceChain.verify_chain)
- edge       : fleet health >= 80  (c_uas.edge.fleet.FleetManager.fleet_health)
- datacenter : capacity headroom > 0  (c_uas.datacenter.capacity.compute_headroom)

Every check imports and calls a real platform module -- no demo data, no
fabricated metrics, no network. All checks are deterministic given their
inputs. Readiness reports persist under
~/.c-uas-platform/production_readiness/ (outside the repo).

Conventions: frozen dataclasses, pure functions, deterministic, real computed
values, CLI subparsers. License: AGPL-3.0.
"""

from __future__ import annotations

from .aggregator import (
    GO,
    NO_GO,
    OVERALL_GO_THRESHOLD,
    ReadinessReport,
    aggregate,
    decision,
    overall_score,
    run_readiness_check,
)
from .checks import (
    CRITICAL_DOMAINS,
    DATACENTER_HEADROOM_GT,
    DOMAIN_WEIGHTS,
    EDGE_PASS_THRESHOLD,
    OBSERVABILITY_PASS_THRESHOLD,
    SECURITY_PASS_THRESHOLD,
    DomainResult,
    all_checks,
    contract_check,
    datacenter_check,
    edge_check,
    finops_check,
    grc_check,
    observability_check,
    security_check,
)
from .report import (
    DEFAULT_STATE_DIR,
    load_latest_report,
    load_report,
    render_json,
    render_text,
    save_report,
)

__all__ = [
    "CRITICAL_DOMAINS",
    "DATACENTER_HEADROOM_GT",
    "DEFAULT_STATE_DIR",
    "DOMAIN_WEIGHTS",
    "DomainResult",
    "EDGE_PASS_THRESHOLD",
    "GO",
    "NO_GO",
    "OBSERVABILITY_PASS_THRESHOLD",
    "OVERALL_GO_THRESHOLD",
    "ReadinessReport",
    "SECURITY_PASS_THRESHOLD",
    "all_checks",
    "aggregate",
    "contract_check",
    "datacenter_check",
    "decision",
    "edge_check",
    "finops_check",
    "grc_check",
    "load_latest_report",
    "load_report",
    "observability_check",
    "overall_score",
    "render_json",
    "render_text",
    "run_readiness_check",
    "save_report",
    "security_check",
]
