"""Data center lifecycle decisions: provision, decommission, refresh, retire,
decommission cost analysis, asset lifecycle stage tracking.

Adapted from Data Center Commander (DCC) lifecycle stages (demand strategy
through decommission & reuse). All decisions are advisory -- nothing here
actuates facility equipment or removes assets from service without an explicit
operator decision recorded alongside.

State persists under ~/.c-uas-platform/datacenter/lifecycle/ (outside the repo).

License: AGPL-3.0.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from typing import Dict, Optional, Tuple

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".c-uas-platform", "datacenter")
LIFECYCLE_SUBDIR = "lifecycle"
LATEST_FILENAME = "latest_lifecycle.json"

# Lifecycle stages mirroring DCC's operate/maintain/optimize -> refresh ->
# decommission progression.
STAGE_PROVISIONING = "provisioning"
STAGE_ACTIVE = "active"
STAGE_MAINTENANCE = "maintenance"
STAGE_REFRESH = "refresh"
STAGE_DECOMMISSIONING = "decommissioning"
STAGE_RETIRED = "retired"

VALID_STAGES: Tuple[str, ...] = (
    STAGE_PROVISIONING,
    STAGE_ACTIVE,
    STAGE_MAINTENANCE,
    STAGE_REFRESH,
    STAGE_DECOMMISSIONING,
    STAGE_RETIRED,
)

# Allowed stage transitions (from -> set of allowed to).
ALLOWED_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    STAGE_PROVISIONING: (STAGE_ACTIVE, STAGE_DECOMMISSIONING),
    STAGE_ACTIVE: (STAGE_MAINTENANCE, STAGE_REFRESH, STAGE_DECOMMISSIONING),
    STAGE_MAINTENANCE: (STAGE_ACTIVE, STAGE_REFRESH, STAGE_DECOMMISSIONING),
    STAGE_REFRESH: (STAGE_ACTIVE, STAGE_DECOMMISSIONING),
    STAGE_DECOMMISSIONING: (STAGE_RETIRED,),
    STAGE_RETIRED: (),  # terminal
}

# Default cost basis (illustrative USD; operators supply site-specific values).
DEFAULT_PROVISION_COST_USD = 2_500.0
DEFAULT_REFRESH_COST_USD = 12_000.0
DEFAULT_RETIRE_COST_USD = 1_500.0
DEFAULT_DECOMMISSION_COST_USD = 3_000.0


@dataclass(frozen=True)
class AssetRecord:
    """A tracked data-center asset with its current lifecycle stage."""

    asset_id: str
    stage: str
    purchase_date: str  # ISO-8601 date
    service_tag: str
    rack_id: str
    decommission_cost_usd: float
    refresh_cost_usd: float
    retire_cost_usd: float
    end_of_support_date: Optional[str] = None  # ISO-8601 date
    last_decision: Optional[str] = None  # description of last lifecycle action


@dataclass(frozen=True)
class LifecycleDecision:
    """A single recorded lifecycle decision (advisory)."""

    asset_id: str
    action: str  # "provision" | "decommission" | "refresh" | "retire"
    stage_before: str
    stage_after: str
    cost_usd: float
    reason: str
    timestamp: str  # ISO-8601 UTC


@dataclass(frozen=True)
class DecommissionCostBreakdown:
    """Itemized decommission cost analysis."""

    asset_id: str
    decommission_labor_usd: float
    media_sanitization_usd: float
    hazardous_material_handling_usd: float
    transport_usd: float
    contract_closeout_usd: float
    recovery_reuse_credit_usd: float
    total_decommission_cost_usd: float
    net_decommission_cost_usd: float


@dataclass(frozen=True)
class LifecycleReport:
    """Aggregate lifecycle state across all tracked assets."""

    report_id: str
    config_hash: str
    assets: Tuple[AssetRecord, ...]
    decisions: Tuple[LifecycleDecision, ...]
    stage_counts: Dict[str, int]
    total_decommission_cost_usd: float
    assets_needing_retirement: int  # past end-of-support and still active


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_stage(stage: str) -> None:
    if stage not in VALID_STAGES:
        raise ValueError(
            "Invalid lifecycle stage: %r (expected one of %s)" % (stage, ", ".join(VALID_STAGES))
        )


def _config_hash(assets: Tuple[AssetRecord, ...]) -> str:
    payload = [asdict(a) for a in assets]
    return "LC-" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def provision(
    asset_id: str,
    service_tag: str,
    rack_id: str,
    purchase_date: Optional[str] = None,
    decommission_cost_usd: float = DEFAULT_PROVISION_COST_USD,
    refresh_cost_usd: float = DEFAULT_REFRESH_COST_USD,
    retire_cost_usd: float = DEFAULT_RETIRE_COST_USD,
    end_of_support_date: Optional[str] = None,
    state_dir: str = DEFAULT_STATE_DIR,
) -> Tuple[AssetRecord, LifecycleDecision]:
    """Provision a new asset into the ACTIVE stage.

    Returns the created AssetRecord and the recorded LifecycleDecision.
    """
    purchase_date = purchase_date or _utc_now()[:10]
    now = _utc_now()
    asset = AssetRecord(
        asset_id=asset_id,
        stage=STAGE_ACTIVE,
        purchase_date=purchase_date,
        service_tag=service_tag,
        rack_id=rack_id,
        decommission_cost_usd=decommission_cost_usd,
        refresh_cost_usd=refresh_cost_usd,
        retire_cost_usd=retire_cost_usd,
        end_of_support_date=end_of_support_date,
        last_decision="provisioned -> active",
    )
    decision = LifecycleDecision(
        asset_id=asset_id,
        action="provision",
        stage_before=STAGE_PROVISIONING,
        stage_after=STAGE_ACTIVE,
        cost_usd=decommission_cost_usd,
        reason="New asset provisioned into service",
        timestamp=now,
    )
    _save_state(_load_assets(state_dir) + (asset,), state_dir)
    return asset, decision


def _transition(
    asset_id: str,
    action: str,
    stage_after: str,
    cost_usd: float,
    reason: str,
    state_dir: str,
    assets: Tuple[AssetRecord, ...],
) -> Tuple[AssetRecord, LifecycleDecision]:
    """Validate and apply a single stage transition for an asset."""
    by_id = {a.asset_id: a for a in assets}
    if asset_id not in by_id:
        raise KeyError("Asset not tracked: %s" % asset_id)
    current = by_id[asset_id]
    _validate_stage(current.stage)
    _validate_stage(stage_after)
    allowed = ALLOWED_TRANSITIONS.get(current.stage, ())
    if stage_after not in allowed:
        raise ValueError(
            "Invalid transition for asset %s: %s -> %s "
            "(allowed from %s: %s)" % (asset_id, current.stage, stage_after, current.stage, allowed)
        )
    now = _utc_now()
    updated = AssetRecord(
        asset_id=asset_id,
        stage=stage_after,
        purchase_date=current.purchase_date,
        service_tag=current.service_tag,
        rack_id=current.rack_id,
        decommission_cost_usd=current.decommission_cost_usd,
        refresh_cost_usd=current.refresh_cost_usd,
        retire_cost_usd=current.retire_cost_usd,
        end_of_support_date=current.end_of_support_date,
        last_decision="%s -> %s" % (action, stage_after),
    )
    decision = LifecycleDecision(
        asset_id=asset_id,
        action=action,
        stage_before=current.stage,
        stage_after=stage_after,
        cost_usd=cost_usd,
        reason=reason,
        timestamp=now,
    )
    next_assets = tuple(updated if a.asset_id == asset_id else a for a in assets)
    _save_state(next_assets, state_dir)
    return updated, decision


def decommission(
    asset_id: str,
    reason: str = "Decommissioned at end of useful life",
    state_dir: str = DEFAULT_STATE_DIR,
) -> Tuple[AssetRecord, LifecycleDecision]:
    """Move an ACTIVE asset to DECOMMISSIONING (advisory; not destructive)."""
    assets = _load_assets(state_dir)
    return _transition(
        asset_id,
        action="decommission",
        stage_after=STAGE_DECOMMISSIONING,
        cost_usd=next(a for a in assets if a.asset_id == asset_id).decommission_cost_usd,
        reason=reason,
        state_dir=state_dir,
        assets=assets,
    )


def refresh(
    asset_id: str,
    reason: str = "Refreshed hardware to current generation",
    state_dir: str = DEFAULT_STATE_DIR,
) -> Tuple[AssetRecord, LifecycleDecision]:
    """Move an asset from ACTIVE/MAINTENANCE to REFRESH then back to ACTIVE."""
    assets = _load_assets(state_dir)
    current = next(a for a in assets if a.asset_id == asset_id)
    # Refresh: active/maintenance -> refresh (intermediate), then back to active.
    intermediate, dec1 = _transition(
        asset_id,
        action="refresh",
        stage_after=STAGE_REFRESH,
        cost_usd=current.refresh_cost_usd,
        reason=reason,
        state_dir=state_dir,
        assets=assets,
    )
    assets2 = _load_assets(state_dir)
    final, dec2 = _transition(
        asset_id,
        action="refresh",
        stage_after=STAGE_ACTIVE,
        cost_usd=0.0,
        reason="Refresh complete; returned to active service",
        state_dir=state_dir,
        assets=assets2,
    )
    return final, dec2


def retire(
    asset_id: str,
    reason: str = "Retired from service",
    state_dir: str = DEFAULT_STATE_DIR,
) -> Tuple[AssetRecord, LifecycleDecision]:
    """Move a DECOMMISSIONING asset to the terminal RETIRED stage."""
    assets = _load_assets(state_dir)
    return _transition(
        asset_id,
        action="retire",
        stage_after=STAGE_RETIRED,
        cost_usd=next(a for a in assets if a.asset_id == asset_id).retire_cost_usd,
        reason=reason,
        state_dir=state_dir,
        assets=assets,
    )


def decommission_cost_analysis(
    asset_id: str,
    state_dir: str = DEFAULT_STATE_DIR,
    labor_usd: float = 800.0,
    media_sanitization_usd: float = 250.0,
    hazardous_material_usd: float = 150.0,
    transport_usd: float = 200.0,
    contract_closeout_usd: float = 100.0,
    recovery_credit_usd: float = 400.0,
) -> DecommissionCostBreakdown:
    """Itemized decommission cost analysis for an asset.

    net = total - recovery_credit. Real computed values, no fabrication.
    """
    assets = _load_assets(state_dir)
    by_id = {a.asset_id: a for a in assets}
    if asset_id not in by_id:
        raise KeyError("Asset not tracked: %s" % asset_id)
    total = (
        labor_usd
        + media_sanitization_usd
        + hazardous_material_usd
        + transport_usd
        + contract_closeout_usd
    )
    net = total - recovery_credit_usd
    return DecommissionCostBreakdown(
        asset_id=asset_id,
        decommission_labor_usd=round(labor_usd, 2),
        media_sanitization_usd=round(media_sanitization_usd, 2),
        hazardous_material_handling_usd=round(hazardous_material_usd, 2),
        transport_usd=round(transport_usd, 2),
        contract_closeout_usd=round(contract_closeout_usd, 2),
        recovery_reuse_credit_usd=round(recovery_credit_usd, 2),
        total_decommission_cost_usd=round(total, 2),
        net_decommission_cost_usd=round(net, 2),
    )


def track_stage(asset_id: str, state_dir: str = DEFAULT_STATE_DIR) -> AssetRecord:
    """Return the current lifecycle stage record for an asset."""
    assets = _load_assets(state_dir)
    for a in assets:
        if a.asset_id == asset_id:
            return a
    raise KeyError("Asset not tracked: %s" % asset_id)


def lifecycle_report(state_dir: str = DEFAULT_STATE_DIR) -> LifecycleReport:
    """Aggregate lifecycle state across all tracked assets."""
    assets = _load_assets(state_dir)
    decisions = _load_decisions(state_dir)
    stage_counts: Dict[str, int] = {s: 0 for s in VALID_STAGES}
    for a in assets:
        stage_counts[a.stage] = stage_counts.get(a.stage, 0) + 1
    total_decommission = sum(a.decommission_cost_usd for a in assets)
    today = date.today().isoformat()
    needing_retirement = sum(
        1
        for a in assets
        if a.end_of_support_date is not None
        and a.end_of_support_date < today
        and a.stage in (STAGE_ACTIVE, STAGE_MAINTENANCE, STAGE_REFRESH)
    )
    config_hash = _config_hash(assets)
    report_id = "lc-" + config_hash
    return LifecycleReport(
        report_id=report_id,
        config_hash=config_hash,
        assets=assets,
        decisions=decisions,
        stage_counts=stage_counts,
        total_decommission_cost_usd=round(total_decommission, 2),
        assets_needing_retirement=needing_retirement,
    )


# --------------------------------------------------------------------------- #
# Persistence (JSON, outside repo)
# --------------------------------------------------------------------------- #


def _assets_path(state_dir: str) -> str:
    return os.path.join(state_dir, LIFECYCLE_SUBDIR, LATEST_FILENAME)


def _load_assets(state_dir: str) -> Tuple[AssetRecord, ...]:
    path = _assets_path(state_dir)
    if not os.path.exists(path):
        return ()
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return tuple(AssetRecord(**item) for item in payload.get("assets", []))


def _save_state(assets: Tuple[AssetRecord, ...], state_dir: str) -> None:
    subdir = os.path.join(state_dir, LIFECYCLE_SUBDIR)
    os.makedirs(subdir, exist_ok=True)
    path = _assets_path(state_dir)
    payload = {
        "config_hash": _config_hash(assets),
        "assets": [asdict(a) for a in assets],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def _decisions_path(state_dir: str) -> str:
    return os.path.join(state_dir, LIFECYCLE_SUBDIR, "decisions.json")


def _load_decisions(state_dir: str) -> Tuple[LifecycleDecision, ...]:
    path = _decisions_path(state_dir)
    if not os.path.exists(path):
        return ()
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return tuple(LifecycleDecision(**item) for item in payload.get("decisions", []))


def _save_decision(decision: LifecycleDecision, state_dir: str) -> None:
    subdir = os.path.join(state_dir, LIFECYCLE_SUBDIR)
    os.makedirs(subdir, exist_ok=True)
    path = _decisions_path(state_dir)
    existing = list(_load_decisions(state_dir))
    existing.append(decision)
    payload = {"decisions": [asdict(d) for d in existing]}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
