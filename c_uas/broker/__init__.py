"""
c_uas.broker — Broker Channel OS.

Multi-tenant broker registration, agent slot allocation (330 slots per broker
default), campaign dispatch via Facebook/WhatsApp/SMS/Email, and delivery
analytics for MENA and emerging markets.

All state persisted to ~/.c-uas-platform/broker/ (outside the repo).
Deterministic: fixed logical clock, content-addressed SHA-256 IDs.

Public API:
    from c_uas.broker import DistributionChannel, BrokerTenant, Campaign
    from c_uas.broker import CampaignAnalytics, Utilization, WaitlistEntry
    from c_uas.broker import BrokerTenantManager, AgentSlotManager
    from c_uas.broker import CampaignManager, CampaignAnalyticsEngine

License: AGPL-3.0. Publisher: Apex Growth Systems LLC (aah@a2zsoc.com).
"""

from .broker import (
    BASE_TS,
    DEFAULT_MAX_AGENT_SLOTS,
    AgentSlotManager,
    BrokerTenant,
    BrokerTenantManager,
    Campaign,
    CampaignAnalytics,
    CampaignAnalyticsEngine,
    CampaignManager,
    DistributionChannel,
    Utilization,
    WaitlistEntry,
)

__all__ = [
    "BASE_TS",
    "DEFAULT_MAX_AGENT_SLOTS",
    "AgentSlotManager",
    "BrokerTenant",
    "BrokerTenantManager",
    "Campaign",
    "CampaignAnalytics",
    "CampaignAnalyticsEngine",
    "CampaignManager",
    "DistributionChannel",
    "Utilization",
    "WaitlistEntry",
]
