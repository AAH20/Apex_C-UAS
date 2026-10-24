"""Deterministic tests for the Broker Channel OS.

Covers: broker registration (content-addressed, idempotent), agent slot
allocation/revocation with the 330-slot default and waitlist, campaign
creation and simulated dispatch, delivery analytics with illustrative
labels, and cross-run determinism from an empty state dir.

State is isolated under C_UAS_BROKER_DIR so tests never touch
~/.c-uas-platform/broker/.
"""

import json
import os
import shutil
import tempfile
import unittest
from dataclasses import asdict

from c_uas.broker import (
    AgentSlotManager,
    CampaignAnalytics,
    CampaignAnalyticsEngine,
    CampaignManager,
    DistributionChannel,
)
from c_uas.broker.broker import DEFAULT_MAX_AGENT_SLOTS, BrokerTenantManager

TEST_DIR = tempfile.mkdtemp(prefix="c-uas-broker-test-")
os.environ["C_UAS_BROKER_DIR"] = TEST_DIR


def _reset_state() -> None:
    for name in os.listdir(TEST_DIR):
        path = os.path.join(TEST_DIR, name)
        if os.path.isfile(path) or os.path.islink(path):
            os.remove(path)


class TestBrokerChannelOS(unittest.TestCase):
    def setUp(self) -> None:
        _reset_state()

    # --- channel enum -----------------------------------------------------

    def test_distribution_channel_enum(self):
        self.assertEqual(DistributionChannel.FACEBOOK.value, "facebook")
        self.assertEqual(DistributionChannel.WHATSAPP.value, "whatsapp")
        self.assertEqual(DistributionChannel.SMS.value, "sms")
        self.assertEqual(DistributionChannel.EMAIL.value, "email")
        self.assertEqual(DistributionChannel("whatsapp"), DistributionChannel.WHATSAPP)
        self.assertTrue(DistributionChannel.has_value("sms"))
        self.assertFalse(DistributionChannel.has_value("telegram"))
        with self.assertRaises(ValueError):
            DistributionChannel("telegram")

    # --- registration ------------------------------------------------------

    def test_register_tenant_defaults_to_330_slots(self):
        tenant = BrokerTenantManager().register(
            "Al Aman Security", "UAE", "ops@alaman.example", "+971500000001", "fb.com/alaman"
        )
        self.assertTrue(tenant.broker_id.startswith("BR-"))
        self.assertEqual(len(tenant.broker_id), 15)  # "BR-" + 12 hex chars
        self.assertEqual(tenant.max_agent_slots, DEFAULT_MAX_AGENT_SLOTS)
        self.assertEqual(tenant.max_agent_slots, 330)
        self.assertEqual(tenant.agent_slots_allocated, 0)
        self.assertEqual(tenant.status, "active")
        self.assertEqual(tenant.created_at, "2026-10-23T00:00:00Z")

    def test_registration_is_content_addressed_and_idempotent(self):
        mgr = BrokerTenantManager()
        t1 = mgr.register(
            "Al Aman Security", "UAE", "ops@alaman.example", "+971500000001", "fb.com/alaman"
        )
        t2 = mgr.register(
            "Al Aman Security", "UAE", "ops@alaman.example", "+971500000001", "fb.com/alaman"
        )
        self.assertEqual(t1.broker_id, t2.broker_id)

    def test_different_inputs_yield_different_broker_ids(self):
        mgr = BrokerTenantManager()
        t1 = mgr.register(
            "Al Aman Security", "UAE", "ops@alaman.example", "+971500000001", "fb.com/alaman"
        )
        t2 = mgr.register(
            "Al Aman Security", "KSA", "ops@alaman.example", "+971500000001", "fb.com/alaman"
        )
        t3 = mgr.register(
            "Other Security", "UAE", "ops@alaman.example", "+971500000001", "fb.com/alaman"
        )
        ids = {t1.broker_id, t2.broker_id, t3.broker_id}
        self.assertEqual(len(ids), 3)

    def test_register_rejects_missing_required_fields(self):
        mgr = BrokerTenantManager()
        with self.assertRaises(ValueError):
            mgr.register("", "UAE", "ops@alaman.example", "+971500000001", "fb.com/alaman")
        with self.assertRaises(ValueError):
            mgr.register(
                "Al Aman Security", "", "ops@alaman.example", "+971500000001", "fb.com/alaman"
            )
        with self.assertRaises(ValueError):
            mgr.register("Al Aman Security", "UAE", "", "+971500000001", "fb.com/alaman")

    def test_get_and_list_tenants(self):
        mgr = BrokerTenantManager()
        t1 = mgr.register(
            "First Broker", "EGYPT", "a@first.example", "+201000000001", "fb.com/first"
        )
        _t2 = mgr.register(
            "Second Broker", "NIGERIA", "b@second.example", "+234800000001", "fb.com/second"
        )
        self.assertIsNotNone(mgr.get(t1.broker_id))
        self.assertEqual(mgr.get(t1.broker_id).name, "First Broker")
        self.assertIsNone(mgr.get("BR-000000000000"))
        names = {t.name for t in mgr.list_all()}
        self.assertEqual(names, {"First Broker", "Second Broker"})

    def test_set_status_suspends_and_rejects_invalid_status(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "EGYPT", "a@first.example", "+201000000001", "fb.com/first"
        )
        suspended = mgr.set_status(tenant.broker_id, "suspended")
        self.assertEqual(suspended.status, "suspended")
        with self.assertRaises(ValueError):
            mgr.set_status(tenant.broker_id, "archived")
        with self.assertRaises(KeyError):
            mgr.set_status("BR-000000000000", "active")

    # --- agent slots -------------------------------------------------------

    def test_allocate_updates_utilization(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "EGYPT", "a@first.example", "+201000000001", "fb.com/first"
        )
        slots = AgentSlotManager()
        util = slots.allocate(tenant.broker_id, 100)
        self.assertEqual(util.slots_used, 100)
        self.assertEqual(util.max_slots, 330)
        self.assertEqual(util.slots_free, 230)
        self.assertAlmostEqual(util.utilization_ratio, 100 / 330, places=4)
        self.assertEqual(util.waitlisted, 0)

    def test_allocate_beyond_capacity_waitlists(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "EGYPT", "a@first.example", "+201000000001", "fb.com/first"
        )
        slots = AgentSlotManager()
        slots.allocate(tenant.broker_id, 330)  # at capacity
        util = slots.allocate(tenant.broker_id, 50)  # waitlisted, no slots consumed
        self.assertEqual(util.slots_used, 330)
        self.assertEqual(util.utilization_ratio, 1.0)
        self.assertEqual(util.waitlisted, 50)
        self.assertEqual(len(slots.waitlist(tenant.broker_id)), 1)
        self.assertEqual(slots.waitlist(tenant.broker_id)[0].requested_slots, 50)

    def test_revoke_frees_slots(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "EGYPT", "a@first.example", "+201000000001", "fb.com/first"
        )
        slots = AgentSlotManager()
        slots.allocate(tenant.broker_id, 100)
        util = slots.revoke(tenant.broker_id, 40)
        self.assertEqual(util.slots_used, 60)
        self.assertEqual(util.slots_free, 270)

    def test_revoke_promotes_waitlist_in_fifo_order(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "EGYPT", "a@first.example", "+201000000001", "fb.com/first"
        )
        slots = AgentSlotManager()
        slots.allocate(tenant.broker_id, 330)  # full
        slots.allocate(tenant.broker_id, 50)  # waitlist entry 1
        slots.allocate(tenant.broker_id, 30)  # waitlist entry 2
        self.assertEqual(slots.utilization(tenant.broker_id).waitlisted, 80)

        # Free 100 slots: entry 1 (50) promotes, then entry 2 (30) promotes.
        util = slots.revoke(tenant.broker_id, 100)
        self.assertEqual(util.slots_used, 310)  # 330 - 100 + 50 + 30
        self.assertEqual(util.waitlisted, 0)
        self.assertEqual(len(slots.waitlist(tenant.broker_id)), 0)

    def test_suspended_broker_cannot_allocate_slots(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "EGYPT", "a@first.example", "+201000000001", "fb.com/first"
        )
        mgr.set_status(tenant.broker_id, "suspended")
        slots = AgentSlotManager()
        with self.assertRaises(ValueError):
            slots.allocate(tenant.broker_id, 10)
        self.assertEqual(slots.utilization(tenant.broker_id).slots_used, 0)

    def test_allocate_rejects_invalid_slot_count_and_unknown_broker(self):
        slots = AgentSlotManager()
        with self.assertRaises(ValueError):
            slots.allocate("BR-000000000000", 0)
        with self.assertRaises(ValueError):
            slots.allocate("BR-000000000000", -5)
        with self.assertRaises(KeyError):
            slots.allocate("BR-000000000000", 10)
        with self.assertRaises(KeyError):
            slots.revoke("BR-000000000000", 10)

    # --- campaigns ---------------------------------------------------------

    def test_create_campaign_is_deterministic(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "EGYPT", "a@first.example", "+201000000001", "fb.com/first"
        )
        camps = CampaignManager()
        c1 = camps.create_campaign(
            tenant.broker_id,
            DistributionChannel.WHATSAPP,
            "EGYPT",
            "Protect your airspace demo C-UAS.",
            10000,
        )
        _c2 = camps.create_campaign(
            tenant.broker_id,
            DistributionChannel.WHATSAPP,
            "EGYPT",
            "Protect your airspace demo C-UAS.",
            10000,
        )
        self.assertTrue(c1.campaign_id.startswith("CAMP-"))
        self.assertEqual(len(c1.campaign_id), 17)  # "CAMP-" + 12 hex chars
        self.assertEqual(c1.broker_id, tenant.broker_id)
        self.assertEqual(c1.channel, DistributionChannel.WHATSAPP)
        self.assertEqual(c1.recipient_count, 10000)
        self.assertEqual(c1.status, "created")
        self.assertEqual(len(camps.list_campaigns(tenant.broker_id)), 2)

    def test_create_campaign_rejects_bad_inputs(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "EGYPT", "a@first.example", "+201000000001", "fb.com/first"
        )
        camps = CampaignManager()
        with self.assertRaises(KeyError):
            camps.create_campaign("BR-000000000000", DistributionChannel.WHATSAPP, "EGYPT", "x", 10)
        with self.assertRaises(ValueError):
            camps.create_campaign(tenant.broker_id, "telegram", "EGYPT", "x", 10)
        with self.assertRaises(ValueError):
            camps.create_campaign(tenant.broker_id, DistributionChannel.EMAIL, "EGYPT", "x", 0)
        mgr.set_status(tenant.broker_id, "suspended")
        with self.assertRaises(ValueError):
            camps.create_campaign(tenant.broker_id, DistributionChannel.WHATSAPP, "EGYPT", "x", 10)

    def test_dispatch_simulates_delivery_and_reads(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "UAE", "a@first.example", "+971500000001", "fb.com/first"
        )
        camps = CampaignManager()
        campaign = camps.create_campaign(
            tenant.broker_id,
            DistributionChannel.WHATSAPP,
            "UAE",
            "Protect your airspace demo C-UAS.",
            10000,
        )
        dispatched = camps.dispatch_campaign(campaign.campaign_id)
        self.assertEqual(dispatched.status, "dispatched")
        self.assertEqual(dispatched.sent_count, 10000)
        # WhatsApp 0.98 * UAE modifier 0.99 = 0.9702 -> 9702 delivered
        self.assertEqual(dispatched.delivered_count, 9702)
        # read 0.85 * 1.00 = 0.85 -> 8247 read
        self.assertEqual(dispatched.read_count, 8247)
        # idempotent re-dispatch returns same counts
        again = camps.dispatch_campaign(campaign.campaign_id)
        self.assertEqual(again.sent_count, dispatched.sent_count)
        self.assertEqual(again.delivered_count, dispatched.delivered_count)

    def test_dispatch_facebook_channel_rates(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "KSA", "a@first.example", "+966500000001", "fb.com/first"
        )
        camps = CampaignManager()
        campaign = camps.create_campaign(
            tenant.broker_id, DistributionChannel.FACEBOOK, "KSA", "hello", 1000
        )
        dispatched = camps.dispatch_campaign(campaign.campaign_id)
        # Facebook 0.92 * KSA modifier 0.98 = 0.9016 -> round(901.6) = 902 delivered;
        # read 0.60 -> round(541.2) = 541 read
        self.assertEqual(dispatched.delivered_count, 902)
        self.assertEqual(dispatched.read_count, 541)

    def test_analytics_rates_and_illustrative_labels(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "UAE", "a@first.example", "+971500000001", "fb.com/first"
        )
        camps = CampaignManager()
        campaign = camps.create_campaign(
            tenant.broker_id,
            DistributionChannel.WHATSAPP,
            "UAE",
            "Protect your airspace demo C-UAS.",
            10000,
        )
        camps.dispatch_campaign(campaign.campaign_id)
        report = CampaignAnalyticsEngine().analyze(campaign.campaign_id)
        self.assertIsInstance(report, CampaignAnalytics)
        self.assertAlmostEqual(report.delivery_rate, 0.9702, places=4)
        self.assertAlmostEqual(report.read_rate, 0.85, places=4)
        # conversions = round(8247 * 0.04) = 330; rate = 330 / 10000
        self.assertAlmostEqual(report.conversion_rate, 0.033, places=6)
        self.assertAlmostEqual(report.cost_per_acquisition_usd, 2.50, places=2)
        self.assertIn("illustrative", report.basis)

    def test_analytics_undispatched_campaign_has_zero_rates(self):
        mgr = BrokerTenantManager()
        tenant = mgr.register(
            "First Broker", "UAE", "a@first.example", "+971500000001", "fb.com/first"
        )
        camps = CampaignManager()
        campaign = camps.create_campaign(
            tenant.broker_id, DistributionChannel.EMAIL, "UAE", "hello", 1000
        )
        report = CampaignAnalyticsEngine().analyze(campaign.campaign_id)
        self.assertEqual(report.delivery_rate, 0.0)
        self.assertEqual(report.read_rate, 0.0)
        self.assertEqual(report.cost_per_acquisition_usd, 0.0)

    def test_analytics_rejects_unknown_campaign(self):
        with self.assertRaises(KeyError):
            CampaignAnalyticsEngine().analyze("CAMP-000000000000")

    def test_list_tenants_and_campaigns_across_manager_instances(self):
        # Persistence: a new manager instance reads the same durable state.
        mgr1 = BrokerTenantManager()
        tenant = mgr1.register(
            "First Broker", "EGYPT", "a@first.example", "+201000000001", "fb.com/first"
        )
        mgr2 = BrokerTenantManager()
        self.assertEqual(mgr2.get(tenant.broker_id).broker_id, tenant.broker_id)
        camps1 = CampaignManager()
        c = camps1.create_campaign(tenant.broker_id, DistributionChannel.SMS, "EGYPT", "x", 100)
        camps2 = CampaignManager()
        self.assertEqual(camps2.get_campaign(c.campaign_id).campaign_id, c.campaign_id)

    # --- determinism -------------------------------------------------------

    def test_same_sequence_produces_identical_state_across_fresh_dirs(self):
        sequence = [
            (
                "register",
                ("Alpha Broker", "BRAZIL", "a@alpha.example", "+551100000001", "fb.com/alpha"),
            ),
            (
                "register",
                ("Beta Broker", "INDIA", "b@beta.example", "+919000000002", "fb.com/beta"),
            ),
        ]

        def run_sequence(state_dir: str) -> dict:
            os.environ["C_UAS_BROKER_DIR"] = state_dir
            _reset_state()
            mgr = BrokerTenantManager()
            t1 = mgr.register(*sequence[0][1])
            t2 = mgr.register(*sequence[1][1])
            slots = AgentSlotManager()
            slots.allocate(t1.broker_id, 100)
            slots.allocate(t1.broker_id, 300)  # waitlist 300
            slots.revoke(t1.broker_id, 40)
            camps = CampaignManager()
            c = camps.create_campaign(
                t2.broker_id, DistributionChannel.WHATSAPP, "INDIA", "demo template", 5000
            )
            camps.dispatch_campaign(c.campaign_id)
            report = CampaignAnalyticsEngine().analyze(c.campaign_id)
            return {
                "tenants": [t.to_dict() for t in mgr.list_all()],
                "campaign": c.to_dict(),
                "analytics": asdict(report),
            }

        dir_a = tempfile.mkdtemp(prefix="det-a-")
        dir_b = tempfile.mkdtemp(prefix="det-b-")
        try:
            state_a = run_sequence(dir_a)
            state_b = run_sequence(dir_b)
            self.assertEqual(
                json.dumps(state_a, sort_keys=True), json.dumps(state_b, sort_keys=True)
            )
        finally:
            shutil.rmtree(dir_a, ignore_errors=True)
            shutil.rmtree(dir_b, ignore_errors=True)
            os.environ["C_UAS_BROKER_DIR"] = TEST_DIR


if __name__ == "__main__":
    unittest.main()
