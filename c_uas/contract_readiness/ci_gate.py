"""
CI gate: exit non-zero on missing routes or breaking changes. Deterministic
output; last-run state is persisted under ~/.c-uas-platform/contract_readiness/
(outside the repo) so cross-session CI runs leave an auditable trail.

Usage:
    from c_uas.contract_readiness.ci_gate import run_gate
    result = run_gate(spec="openapi.yaml")   # exit_code 0 / 1
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .breaking import BreakingReport, detect_breaking_changes_from_files
from .contract import ContractReport, load_app_routes, verify_contract

DEFAULT_STATE_DIR = Path.home() / ".c-uas-platform" / "contract_readiness"
STATE_FILE = "gate_state.json"


@dataclass(frozen=True)
class GateResult:
    """Result of a contract gate run."""

    command: str
    exit_code: int
    ok: bool
    reason: str
    contract_report: Optional[ContractReport]
    breaking_report: Optional[BreakingReport]
    state_path: str


def evaluate_gate(
    contract_report: Optional[ContractReport],
    breaking_report: Optional[BreakingReport],
) -> Tuple[int, str]:
    """Pure gate decision: (exit_code, reason). No side effects."""
    problems: List[str] = []
    if contract_report is not None and not contract_report.ok:
        parts: List[str] = []
        if contract_report.missing:
            parts.append(f"{len(contract_report.missing)} missing route(s)")
        if contract_report.extra:
            parts.append(f"{len(contract_report.extra)} extra route(s)")
        if contract_report.mismatched:
            parts.append(f"{len(contract_report.mismatched)} mismatched route(s)")
        problems.append("contract mismatch: " + "; ".join(parts))
    if breaking_report is not None and breaking_report.breaking:
        problems.append(f"{len(breaking_report.changes)} breaking change(s)")
    if problems:
        return 1, "contract gate FAILED: " + "; ".join(problems)
    return 0, "contract gate PASSED"


def _report_snapshot(
    contract_report: Optional[ContractReport],
    breaking_report: Optional[BreakingReport],
) -> Dict[str, Any]:
    return {
        "contract": None
        if contract_report is None
        else {
            "spec_path": contract_report.spec_path,
            "spec_route_count": len(contract_report.spec_routes),
            "app_route_count": len(contract_report.app_routes),
            "missing": [{"method": r.method, "path": r.path} for r in contract_report.missing],
            "extra": [{"method": r.method, "path": r.path} for r in contract_report.extra],
            "mismatched": [
                {
                    "path": path,
                    "spec_methods": list(spec_methods),
                    "app_methods": list(app_methods),
                }
                for path, spec_methods, app_methods in contract_report.mismatched
            ],
            "ok": contract_report.ok,
        },
        "breaking": None
        if breaking_report is None
        else {
            "old_spec_path": breaking_report.old_spec_path,
            "new_spec_path": breaking_report.new_spec_path,
            "changes": [asdict(change) for change in breaking_report.changes],
            "breaking": breaking_report.breaking,
        },
    }


def run_gate(
    spec_path: Optional[str] = None,
    old_spec_path: Optional[str] = None,
    state_dir: Path = DEFAULT_STATE_DIR,
    app_routes: Optional[Sequence] = None,
) -> GateResult:
    """Run the gate and persist deterministic state under state_dir."""
    contract_report: Optional[ContractReport] = None
    breaking_report: Optional[BreakingReport] = None

    if spec_path is not None:
        routes = load_app_routes() if app_routes is None else list(app_routes)
        contract_report = verify_contract(spec_path, routes)

    if spec_path is not None and old_spec_path is not None:
        breaking_report = detect_breaking_changes_from_files(old_spec_path, spec_path)

    exit_code, reason = evaluate_gate(contract_report, breaking_report)

    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / STATE_FILE
    state: Dict[str, Any] = {
        "command": "gate",
        "exit_code": exit_code,
        "ok": exit_code == 0,
        "reason": reason,
        "spec_path": spec_path,
        "old_spec_path": old_spec_path,
        "snapshot": _report_snapshot(contract_report, breaking_report),
    }
    state_path.write_text(json.dumps(state, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    return GateResult(
        command="gate",
        exit_code=exit_code,
        ok=exit_code == 0,
        reason=reason,
        contract_report=contract_report,
        breaking_report=breaking_report,
        state_path=str(state_path),
    )
