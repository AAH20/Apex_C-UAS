"""
Broker Channel OS — multi-tenant broker management for C-UAS GTM distribution.

Multi-tenant broker registration, agent slot allocation (330 slots per broker
default), campaign dispatch via Facebook/WhatsApp/SMS/Email, and delivery
analytics for MENA and emerging markets.

All state persisted to ~/.c-uas-platform/broker/ (outside the repo).
Deterministic: fixed logical clock (no wall-clock), content-addressed SHA-256
IDs, same input -> same output on every run. No randomness, no external API
calls. Delivery figures are simulated and labeled illustrative per grounding
policy — no live Meta or WhatsApp integration is delivered.

Usage:
    from c_uas.broker import BrokerTenantManager, AgentSlotManager
    from c_uas.broker import CampaignManager, CampaignAnalytics, DistributionChannel

    mgr = BrokerTenantManager()
    tenant = mgr.register("Al Aman Security", "UAE",
                          "ops@alaman.example", "+971500000001", "fb.com/alaman")
    slots = AgentSlotManager()
    slots.allocate(tenant.broker_id, 50)
    campaigns = CampaignManager()
    camp = campaigns.create_campaign(tenant.broker_id, DistributionChannel.WHATSAPP,
                                     "UAE", "Protect your airspace — demo C-UAS.", 10_000)
    campaigns.dispatch_campaign(camp.campaign_id)
    report = CampaignAnalytics().analyze(camp.campaign_id)

License: AGPL-3.0. Publisher: Apex Growth Systems LLC (aah@a2zsoc.com).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Determinism constants: no wall-clock, no randomness. All timestamps derive
# from a fixed logical clock persisted under the state dir. Replaying the same
# sequence of operations from an empty state dir produces identical state.
# ---------------------------------------------------------------------------

BASE_TS = "2026-10-23T00:00:00Z"
BASE_DT = datetime(2026, 10, 23, 0, 0, 0, tzinfo=timezone.utc)

DEFAULT_MAX_AGENT_SLOTS = 330

# Simulated delivery characteristics per channel (illustrative, not measured
# from any live channel). Values are probabilities in [0, 1].
DEFAULT_CHANNEL_RATES: Dict[str, Dict[str, float]] = {
    "whatsapp": {"delivery": 0.98, "read": 0.85},
    "facebook": {"delivery": 0.92, "read": 0.60},
    "sms": {"delivery": 0.95, "read": 0.40},
    "email": {"delivery": 0.90, "read": 0.22},
}

# Regional delivery adjustments for MENA + emerging markets (illustrative).
REGION_MODIFIERS: Dict[str, Dict[str, float]] = {
    "MENA": {"delivery": 0.99, "read": 1.00},
    "UAE": {"delivery": 0.99, "read": 1.00},
    "KSA": {"delivery": 0.98, "read": 1.00},
    "QATAR": {"delivery": 0.99, "read": 1.00},
    "EGYPT": {"delivery": 0.95, "read": 0.95},
    "MOROCCO": {"delivery": 0.94, "read": 0.92},
    "NIGERIA": {"delivery": 0.90, "read": 0.85},
    "KENYA": {"delivery": 0.91, "read": 0.88},
    "BRAZIL": {"delivery": 0.92, "read": 0.90},
    "COLOMBIA": {"delivery": 0.91, "read": 0.89},
    "INDIA": {"delivery": 0.94, "read": 0.92},
    "INDONESIA": {"delivery": 0.93, "read": 0.90},
    "PHILIPPINES": {"delivery": 0.92, "read": 0.89},
}

# Illustrative conversion economics (not measured from live campaigns).
ILLUSTRATIVE_CONVERSION_RATE = 0.04  # share of reads that convert (illustrative)
ILLUSTRATIVE_CPA_USD = 2.50  # cost per acquisition in USD (illustrative)


def _broker_dir() -> Path:
    """State directory, overridable via C_UAS_BROKER_DIR for isolated runs."""
    return Path(os.environ.get("C_UAS_BROKER_DIR", str(Path.home() / ".c-uas-platform" / "broker")))


def _ensure_dir() -> None:
    _broker_dir().mkdir(parents=True, exist_ok=True)


def _load_json(path: Path) -> Any:
    _ensure_dir()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _save_json(path: Path, data: Any) -> None:
    _ensure_dir()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _content_id(*parts: str) -> str:
    """Content-addressed ID: SHA-256 over canonical JSON of the parts."""
    digest = hashlib.sha256(json.dumps(parts, sort_keys=True).encode("utf-8")).hexdigest()
    return digest[:12]


def _iso(seconds: int) -> str:
    return (BASE_DT + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


# ---------------------------------------------------------------------------
# Enums and dataclasses
# ---------------------------------------------------------------------------


class DistributionChannel(str, Enum):
    FACEBOOK = "facebook"
    WHATSAPP = "whatsapp"
    SMS = "sms"
    EMAIL = "email"

    @classmethod
    def has_value(cls, value: Any) -> bool:
        return any(item.value == value for item in cls)


@dataclass(frozen=True)
class BrokerTenant:
    """A registered broker tenant in the channel OS."""

    broker_id: str
    name: str
    region: str
    contact_email: str
    whatsapp_number: str
    facebook_page_id: str
    agent_slots_allocated: int  # slots currently in use (slots_used)
    max_agent_slots: int = DEFAULT_MAX_AGENT_SLOTS
    status: str = "active"  # active | suspended
    created_at: str = BASE_TS

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BrokerTenant":
        return cls(**data)


@dataclass(frozen=True)
class WaitlistEntry:
    broker_id: str
    requested_slots: int
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WaitlistEntry":
        return cls(**data)


@dataclass(frozen=True)
class Utilization:
    broker_id: str
    slots_used: int
    max_slots: int
    slots_free: int
    utilization_ratio: float  # slots_used / max_slots
    waitlisted: int  # total slots pending on the waitlist


@dataclass(frozen=True)
class Campaign:
    campaign_id: str
    broker_id: str
    channel: DistributionChannel
    target_region: str
    message_template: str
    recipient_count: int
    status: str = "created"  # created | dispatched
    created_at: str = BASE_TS
    sent_count: int = 0
    delivered_count: int = 0
    read_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["channel"] = self.channel.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Campaign":
        data = dict(data)
        data["channel"] = DistributionChannel(data["channel"])
        return cls(**data)


@dataclass(frozen=True)
class CampaignAnalytics:
    """Delivery analytics for one campaign. Financials are illustrative."""

    campaign_id: str
    delivery_rate: float  # delivered / sent
    read_rate: float  # read / delivered
    conversion_rate: float  # illustrative conversions / recipients
    cost_per_acquisition_usd: float  # illustrative
    basis: str  # disclosure label, e.g. "illustrative — simulated, not live"


# ---------------------------------------------------------------------------
# Persistence paths
# ---------------------------------------------------------------------------

_TENANTS_FILE = "tenants.json"
_WAITLIST_FILE = "waitlist.json"
_CAMPAIGNS_FILE = "campaigns.json"
_META_FILE = "meta.json"  # logical clock + per-broker campaign sequence


# ---------------------------------------------------------------------------
# BrokerTenantManager — registration + tenant CRUD
# ---------------------------------------------------------------------------


class BrokerTenantManager:
    """Registers brokers and keeps tenant records durable and deterministic."""

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.dir = base_dir or _broker_dir()
        _ensure_dir()

    # -- files --------------------------------------------------------------

    def _tenants_path(self) -> Path:
        return self.dir / _TENANTS_FILE

    # -- public API ---------------------------------------------------------

    def register(
        self,
        name: str,
        region: str,
        contact_email: str,
        whatsapp_number: str,
        facebook_page_id: str,
        max_agent_slots: int = DEFAULT_MAX_AGENT_SLOTS,
    ) -> BrokerTenant:
        """Register a broker. Content-addressed broker_id makes it idempotent:
        the same inputs always return the same tenant record, never a duplicate.
        """
        if not name or not region or not contact_email:
            raise ValueError("name, region, and contact_email are required")
        if max_agent_slots <= 0:
            raise ValueError("max_agent_slots must be positive")

        broker_id = "BR-" + _content_id(
            name.strip(),
            region.strip(),
            contact_email.strip().lower(),
            whatsapp_number.strip(),
            facebook_page_id.strip(),
        )
        existing = self.get(broker_id)
        if existing is not None:
            return existing

        clock = self._clock()
        self._set_clock(clock + 1)
        tenant = BrokerTenant(
            broker_id=broker_id,
            name=name.strip(),
            region=region.strip(),
            contact_email=contact_email.strip().lower(),
            whatsapp_number=whatsapp_number.strip(),
            facebook_page_id=facebook_page_id.strip(),
            agent_slots_allocated=0,
            max_agent_slots=max_agent_slots,
            status="active",
            created_at=_iso(clock),
        )
        tenant_dicts = [t.to_dict() for t in self.list_all()]
        tenant_dicts.append(tenant.to_dict())
        _save_json(self._tenants_path(), tenant_dicts)
        return tenant

    def get(self, broker_id: str) -> Optional[BrokerTenant]:
        for t in self._load_tenants():
            if t["broker_id"] == broker_id:
                return BrokerTenant.from_dict(t)
        return None

    def list_all(self) -> List[BrokerTenant]:
        return [BrokerTenant.from_dict(t) for t in self._load_tenants()]

    def set_status(self, broker_id: str, status: str) -> BrokerTenant:
        if status not in ("active", "suspended"):
            raise ValueError("status must be 'active' or 'suspended'")
        tenants = self._load_tenants()
        for _i, t in enumerate(tenants):
            if t["broker_id"] == broker_id:
                t["status"] = status
                _save_json(self._tenants_path(), tenants)
                return BrokerTenant.from_dict(t)
        raise KeyError(f"broker not found: {broker_id}")

    # -- internals ----------------------------------------------------------

    def _load_tenants(self) -> List[Dict[str, Any]]:
        data = _load_json(self._tenants_path())
        return data if isinstance(data, list) else []

    def _clock_path(self) -> Path:
        return self.dir / _META_FILE

    def _clock(self) -> int:
        meta = _load_json(self._clock_path()) or {}
        return int(meta.get("clock", 0))

    def _set_clock(self, value: int) -> None:
        meta = _load_json(self._clock_path()) or {}
        meta["clock"] = value
        _save_json(self._clock_path(), meta)

    def _bump_clock(self) -> None:
        meta = _load_json(self._clock_path()) or {}
        meta["clock"] = int(meta.get("clock", 0)) + 1
        _save_json(self._clock_path(), meta)

    def _next_campaign_seq(self, broker_id: str) -> int:
        meta = _load_json(self._clock_path()) or {}
        seqs = meta.get("campaign_seq", {})
        return int(seqs.get(broker_id, 0)) + 1

    def _bump_campaign_seq(self, broker_id: str) -> int:
        meta = _load_json(self._clock_path()) or {}
        seqs = meta.get("campaign_seq", {})
        seq = int(seqs.get(broker_id, 0)) + 1
        seqs[broker_id] = seq
        meta["campaign_seq"] = seqs
        _save_json(self._clock_path(), meta)
        return seq


# ---------------------------------------------------------------------------
# AgentSlotManager — allocate / revoke slots, utilization, waitlist
# ---------------------------------------------------------------------------


class AgentSlotManager:
    """Manages per-broker agent slots (330 default max) with a waitlist."""

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.dir = base_dir or _broker_dir()
        _ensure_dir()

    def _waitlist_path(self) -> Path:
        return self.dir / _WAITLIST_FILE

    def allocate(self, broker_id: str, slots: int) -> Utilization:
        """Allocate slots for a broker. If at capacity, the request is
        waitlisted and no slots are consumed. Returns current utilization."""
        if slots <= 0:
            raise ValueError("slots must be positive")
        tenant = self._require_tenant(broker_id)
        if tenant.status != "active":
            raise ValueError(f"broker {broker_id} is {tenant.status}; cannot allocate slots")

        waitlist = self._load_waitlist()
        if tenant.agent_slots_allocated + slots > tenant.max_agent_slots:
            waitlist.append(
                WaitlistEntry(
                    broker_id=broker_id,
                    requested_slots=slots,
                    created_at=_iso(self._clock()),
                ).to_dict()
            )
            _save_json(self._waitlist_path(), waitlist)
            return self.utilization(broker_id)

        tenant = BrokerTenant(
            **{**tenant.to_dict(), "agent_slots_allocated": tenant.agent_slots_allocated + slots}
        )
        self._persist_tenant(tenant)
        self._bump_clock()
        self._promote_waitlist()
        return self.utilization(broker_id)

    def revoke(self, broker_id: str, slots: int) -> Utilization:
        """Revoke slots from a broker, then promote waitlisted requests FIFO."""
        if slots <= 0:
            raise ValueError("slots must be positive")
        tenant = self._require_tenant(broker_id)
        new_used = max(0, tenant.agent_slots_allocated - slots)
        tenant = BrokerTenant(**{**tenant.to_dict(), "agent_slots_allocated": new_used})
        self._persist_tenant(tenant)
        self._bump_clock()
        self._promote_waitlist()
        return self.utilization(broker_id)

    def utilization(self, broker_id: str) -> Utilization:
        tenant = self._require_tenant(broker_id)
        waitlist = self._load_waitlist()
        waitlisted = sum(int(w["requested_slots"]) for w in waitlist if w["broker_id"] == broker_id)
        free = max(0, tenant.max_agent_slots - tenant.agent_slots_allocated)
        ratio = (
            tenant.agent_slots_allocated / tenant.max_agent_slots
            if tenant.max_agent_slots > 0
            else 0.0
        )
        return Utilization(
            broker_id=broker_id,
            slots_used=tenant.agent_slots_allocated,
            max_slots=tenant.max_agent_slots,
            slots_free=free,
            utilization_ratio=round(ratio, 4),
            waitlisted=waitlisted,
        )

    def waitlist(self, broker_id: str) -> List[WaitlistEntry]:
        waitlist = self._load_waitlist()
        return [WaitlistEntry.from_dict(w) for w in waitlist if w["broker_id"] == broker_id]

    # -- internals ----------------------------------------------------------

    def _require_tenant(self, broker_id: str) -> BrokerTenant:
        mgr = BrokerTenantManager(base_dir=self.dir)
        tenant = mgr.get(broker_id)
        if tenant is None:
            raise KeyError(f"broker not found: {broker_id}")
        return tenant

    def _persist_tenant(self, tenant: BrokerTenant) -> None:
        mgr = BrokerTenantManager(base_dir=self.dir)
        tenants = mgr._load_tenants()
        for i, t in enumerate(tenants):
            if t["broker_id"] == tenant.broker_id:
                tenants[i] = tenant.to_dict()
                break
        else:
            tenants.append(tenant.to_dict())
        _save_json(mgr._tenants_path(), tenants)

    def _clock_path(self) -> Path:
        return self.dir / _META_FILE

    def _clock(self) -> int:
        meta = _load_json(self._clock_path()) or {}
        return int(meta.get("clock", 0))

    def _bump_clock(self) -> None:
        meta = _load_json(self._clock_path()) or {}
        meta["clock"] = int(meta.get("clock", 0)) + 1
        _save_json(self._clock_path(), meta)

    def _load_waitlist(self) -> List[Dict[str, Any]]:
        data = _load_json(self._waitlist_path())
        return data if isinstance(data, list) else []

    def _save_waitlist(self, waitlist: List[Dict[str, Any]]) -> None:
        _save_json(self._waitlist_path(), waitlist)

    def _promote_waitlist(self) -> None:
        """Promote waitlisted requests in FIFO order while capacity allows."""
        waitlist = self._load_waitlist()
        if not waitlist:
            return
        promoted: List[Dict[str, Any]] = []
        remaining: List[Dict[str, Any]] = []
        for entry in waitlist:
            broker_id = entry["broker_id"]
            requested = int(entry["requested_slots"])
            try:
                tenant = self._require_tenant(broker_id)
            except KeyError:
                remaining.append(entry)
                continue
            if tenant.status != "active":
                remaining.append(entry)
                continue
            if tenant.agent_slots_allocated + requested <= tenant.max_agent_slots:
                tenant = BrokerTenant(
                    **{
                        **tenant.to_dict(),
                        "agent_slots_allocated": tenant.agent_slots_allocated + requested,
                    }
                )
                self._persist_tenant(tenant)
                promoted.append(entry)
            else:
                remaining.append(entry)
        if promoted:
            self._bump_clock()
        self._save_waitlist(remaining)


# ---------------------------------------------------------------------------
# CampaignManager — create and dispatch campaigns
# ---------------------------------------------------------------------------


class CampaignManager:
    """Creates campaigns and simulates deterministic delivery per channel."""

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.dir = base_dir or _broker_dir()
        _ensure_dir()

    def _campaigns_path(self) -> Path:
        return self.dir / _CAMPAIGNS_FILE

    def create_campaign(
        self,
        broker_id: str,
        channel: DistributionChannel,
        target_region: str,
        message_template: str,
        recipient_count: int,
    ) -> Campaign:
        """Create a campaign for a broker. Content-addressed campaign_id."""
        tenant_mgr = BrokerTenantManager(base_dir=self.dir)
        tenant = tenant_mgr.get(broker_id)
        if tenant is None:
            raise KeyError(f"broker not found: {broker_id}")
        if tenant.status != "active":
            raise ValueError(f"broker {broker_id} is {tenant.status}; cannot create campaigns")
        if not DistributionChannel.has_value(
            channel.value if isinstance(channel, DistributionChannel) else channel
        ):
            raise ValueError(f"unknown channel: {channel}")
        if recipient_count <= 0:
            raise ValueError("recipient_count must be positive")

        channel = (
            DistributionChannel(channel)
            if not isinstance(channel, DistributionChannel)
            else channel
        )
        seq = tenant_mgr._bump_campaign_seq(broker_id)
        clock = tenant_mgr._clock()
        campaign_id = "CAMP-" + _content_id(
            broker_id,
            channel.value,
            target_region.strip(),
            message_template,
            str(recipient_count),
            str(seq),
        )
        campaign = Campaign(
            campaign_id=campaign_id,
            broker_id=broker_id,
            channel=channel,
            target_region=target_region.strip(),
            message_template=message_template,
            recipient_count=recipient_count,
            status="created",
            created_at=_iso(clock),
        )
        campaigns = self._load_campaigns()
        campaigns.append(campaign.to_dict())
        _save_json(self._campaigns_path(), campaigns)
        return campaign

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        for c in self._load_campaigns():
            if c["campaign_id"] == campaign_id:
                return Campaign.from_dict(c)
        return None

    def list_campaigns(self, broker_id: Optional[str] = None) -> List[Campaign]:
        campaigns = [Campaign.from_dict(c) for c in self._load_campaigns()]
        if broker_id is not None:
            campaigns = [c for c in campaigns if c.broker_id == broker_id]
        return campaigns

    def dispatch_campaign(self, campaign_id: str) -> Campaign:
        """Simulate delivery: sent/delivered/read counts derived from channel
        and region rates. Deterministic — same input, same counts every time."""
        campaign = self.get_campaign(campaign_id)
        if campaign is None:
            raise KeyError(f"campaign not found: {campaign_id}")
        if campaign.status == "dispatched":
            return campaign

        tenant_mgr = BrokerTenantManager(base_dir=self.dir)
        tenant = tenant_mgr.get(campaign.broker_id)
        if tenant is None:
            raise KeyError(f"broker not found: {campaign.broker_id}")

        channel_rates = DEFAULT_CHANNEL_RATES[campaign.channel.value]
        region_key = tenant.region.upper()
        modifier = REGION_MODIFIERS.get(region_key, {"delivery": 1.0, "read": 1.0})
        delivery_rate = _clamp(channel_rates["delivery"] * modifier["delivery"])
        read_rate = _clamp(channel_rates["read"] * modifier["read"])

        sent = campaign.recipient_count
        delivered = int(round(sent * delivery_rate))
        read = int(round(delivered * read_rate))
        campaign_dict = campaign.to_dict()

        campaigns = self._load_campaigns()
        for i, c in enumerate(campaigns):
            if c["campaign_id"] == campaign_id:
                campaigns[i] = Campaign(
                    **{
                        **campaign_dict,
                        "channel": DistributionChannel(campaign_dict["channel"]),
                        "status": "dispatched",
                        "sent_count": sent,
                        "delivered_count": delivered,
                        "read_count": read,
                    }
                ).to_dict()
                break
        _save_json(self._campaigns_path(), campaigns)
        tenant_mgr._bump_clock()
        dispatched = self.get_campaign(campaign_id)
        if dispatched is None:
            raise RuntimeError(f"campaign vanished after dispatch: {campaign_id}")
        return dispatched

    # -- internals ----------------------------------------------------------

    def _load_campaigns(self) -> List[Dict[str, Any]]:
        data = _load_json(self._campaigns_path())
        return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# CampaignAnalytics — delivery + illustrative conversion economics
# ---------------------------------------------------------------------------


class CampaignAnalyticsEngine:
    """Computes delivery rates and illustrative conversion economics."""

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.dir = base_dir or _broker_dir()
        _ensure_dir()

    def analyze(self, campaign_id: str) -> CampaignAnalytics:
        campaigns_mgr = CampaignManager(base_dir=self.dir)
        campaign = campaigns_mgr.get_campaign(campaign_id)
        if campaign is None:
            raise KeyError(f"campaign not found: {campaign_id}")

        sent = campaign.sent_count
        delivered = campaign.delivered_count
        read = campaign.read_count

        delivery_rate = round(delivered / sent, 4) if sent > 0 else 0.0
        read_rate = round(read / delivered, 4) if delivered > 0 else 0.0

        # Illustrative: 4% of reads convert; labeled per grounding policy.
        conversions = round(read * ILLUSTRATIVE_CONVERSION_RATE)
        conversion_rate = (
            round(conversions / campaign.recipient_count, 6)
            if campaign.recipient_count > 0
            else 0.0
        )
        cpa = ILLUSTRATIVE_CPA_USD if conversions > 0 else 0.0

        basis = (
            "illustrative — simulated delivery counts, conversion rate and CPA "
            "are planning figures, not measured from live channel delivery"
        )
        return CampaignAnalytics(
            campaign_id=campaign_id,
            delivery_rate=delivery_rate,
            read_rate=read_rate,
            conversion_rate=conversion_rate,
            cost_per_acquisition_usd=cpa,
            basis=basis,
        )

    def broker_summary(self, broker_id: str) -> Dict[str, Any]:
        """Aggregate analytics across all campaigns of a broker."""
        campaigns_mgr = CampaignManager(base_dir=self.dir)
        campaigns = campaigns_mgr.list_campaigns(broker_id)
        if not campaigns:
            return {
                "broker_id": broker_id,
                "campaigns": 0,
                "total_sent": 0,
                "total_delivered": 0,
                "total_read": 0,
                "delivery_rate": 0.0,
                "read_rate": 0.0,
            }
        total_sent = sum(c.sent_count for c in campaigns)
        total_delivered = sum(c.delivered_count for c in campaigns)
        total_read = sum(c.read_count for c in campaigns)
        return {
            "broker_id": broker_id,
            "campaigns": len(campaigns),
            "total_sent": total_sent,
            "total_delivered": total_delivered,
            "total_read": total_read,
            "delivery_rate": round(total_delivered / total_sent, 4) if total_sent else 0.0,
            "read_rate": round(total_read / total_delivered, 4) if total_delivered else 0.0,
        }
