"""
Contract Readiness Engine: OpenAPI contract verification, breaking-change
detection, and CI gating for the C-UAS platform API.

State persists under ~/.c-uas-platform/contract_readiness/ (outside the repo).
All compute is deterministic: identical inputs produce identical output.

License: AGPL-3.0. Author: Ahmed Hassan <aah@a2zsoc.com>.
Publisher: Apex Growth Systems LLC.
"""

from __future__ import annotations

# Backward compatibility: the legacy burn-rate / CAC-LTV / MVP-scope model
# previously lived in c_uas/contract_readiness.py. That module file is left
# untouched on disk, but since the package now shadows it, its public API is
# re-exported here so existing consumers keep working (c_uas.cli
# "contract-readiness" command and its tests).
from ._legacy import (  # noqa: E402
    BurnRateInput,
    BurnRateResult,
    CACLTVInput,
    CACLTVResult,
    ContractReadinessModel,
    MVPFeature,
    MVPScope,
)
from .breaking import (
    BreakingChange,
    BreakingReport,
    detect_breaking_changes,
    detect_breaking_changes_from_files,
)
from .ci_gate import DEFAULT_STATE_DIR, GateResult, evaluate_gate, run_gate
from .cli import build_subparser, contract_main, main
from .contract import (
    ContractReport,
    RouteEntry,
    extract_app_routes,
    extract_spec_routes,
    load_app_routes,
    load_spec,
    verify_contract,
)

__all__ = [
    "DEFAULT_STATE_DIR",
    "BreakingChange",
    "BreakingReport",
    "ContractReport",
    "GateResult",
    "RouteEntry",
    "BurnRateInput",
    "BurnRateResult",
    "CACLTVInput",
    "CACLTVResult",
    "ContractReadinessModel",
    "MVPFeature",
    "MVPScope",
    "build_subparser",
    "contract_main",
    "detect_breaking_changes",
    "detect_breaking_changes_from_files",
    "evaluate_gate",
    "extract_app_routes",
    "extract_spec_routes",
    "load_app_routes",
    "load_spec",
    "main",
    "run_gate",
    "verify_contract",
]
