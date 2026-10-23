"""Tests for STIX/TAXII threat intelligence export and alerting.

Deterministic scenarios only: same inputs produce identical bundles,
alerts fire on critical/spoof events, TAXII routes mount, and state
persists under ~/.c-uas-platform/threat_intel/.
"""

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from c_uas.forensics.airspace_dossier import AirspaceIntrusionDossier
from c_uas.threat_intel import (
    AlertEngine,
    Channel,
    ChannelConfig,
    CompetitiveIntelEntry,
    ConsoleChannel,
    DetectionEvent,
    EmailStubChannel,
    ForensicDossierRef,
    STIXBundleBuilder,
    app_factory,
    bundle_hash,
    detection_event_from_dict,
    forensic_dossier_from_dict,
)
from c_uas.threat_intel.alert_engine import DEFAULT_RULES
from c_uas.threat_intel.stix_builder import (
    STIX_NAMESPACE,
    _stix_id,
)
from c_uas.threat_intel.store import ThreatIntelStore


def _make_event(**overrides):
    data = dict(
        event_id="DET-EVT-01",
        timestamp="2026-10-23T10:15:00Z",
        source="rf_classifier",
        target_id="UAV-ROGUE-01",
        threat_level="CRITICAL",
        protocol="DJI_OCUSYNC_4",
        confidence=0.94,
        latitude=34.0522,
        longitude=-118.2437,
        anomalies=("SPOOFED_BROADCAST_ID",),
        metadata={},
    )
    data.update(overrides)
    return DetectionEvent(**data)


def _make_dossier_ref(**overrides):
    dossier = AirspaceIntrusionDossier.generate_signed_dossier(
        target_id="UAV-ROGUE-01",
        protocol="DJI_OCUSYNC_4",
        threat_level="CRITICAL",
        coordinates_path=[{"x": 1.0, "y": 2.0, "z": 3.0}],
        rf_anomalies=["SPOOFED_BROADCAST_ID"],
    )
    data = dict(
        dossier_id=dossier["dossier_id"],
        target_id=dossier["target_id"],
        threat_classification=dossier["threat_classification"],
        signature=dossier["signature"],
        public_key_pem=dossier["public_key_pem"],
        tamper_evident_hash=dossier["tamper_evident_hash"],
        timestamp_utc=dossier["timestamp_utc"],
    )
    data.update(overrides)
    return ForensicDossierRef(**data)


class TestStixBundleBuilder(unittest.TestCase):
    def test_bundle_has_required_stix_fields(self):
        builder = STIXBundleBuilder()
        builder.add_detection_event(_make_event())
        bundle = builder.build()
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        self.assertEqual(bundle["spec_version"], "2.1")
        self.assertIsInstance(bundle["objects"], list)

    def test_tlp_markings_included(self):
        builder = STIXBundleBuilder()
        bundle = builder.build()
        marking_ids = {o["id"] for o in bundle["objects"] if o["type"] == "marking-definition"}
        self.assertIn(_stix_id("marking-definition", "tlp-white"), marking_ids)
        self.assertIn(_stix_id("marking-definition", "tlp-amber"), marking_ids)
        self.assertIn(_stix_id("marking-definition", "tlp-red"), marking_ids)

    def test_detection_event_produces_observed_data_and_indicator(self):
        builder = STIXBundleBuilder()
        event = _make_event()
        oid = builder.add_detection_event(event)
        self.assertTrue(oid.startswith("observed-data--"))

        objs = {o["id"]: o for o in builder.build()["objects"]}
        observed = objs[oid]
        self.assertEqual(observed["type"], "observed-data")
        self.assertEqual(observed["number_observed"], 1)
        self.assertEqual(observed["objects"]["0"]["target_id"], "UAV-ROGUE-01")
        self.assertEqual(observed["objects"]["0"]["threat_level"], "CRITICAL")
        # TLP RED for CRITICAL.
        self.assertIn(_stix_id("marking-definition", "tlp-red"), observed["marking_refs"])

        # Indicator present: at least one indicator, pattern references the event.
        indicators = [o for o in builder.build()["objects"] if o["type"] == "indicator"]
        self.assertGreaterEqual(len(indicators), 1)
        self.assertIn("detection_id = 'DET-EVT-01'", indicators[0]["pattern"])

    def test_forensic_dossier_carries_ed25519_and_tlp_red(self):
        builder = STIXBundleBuilder()
        ref = _make_dossier_ref()
        oid = builder.add_forensic_dossier(ref)
        objs = {o["id"]: o for o in builder.build()["objects"]}
        observed = objs[oid]
        obs0 = observed["objects"]["0"]
        self.assertEqual(obs0["type"], "x_cuas_forensic_dossier")
        self.assertEqual(obs0["dossier_id"], ref.dossier_id)
        self.assertEqual(len(obs0["signature"]), 128)  # Ed25519 hex
        self.assertIn("-----BEGIN PUBLIC KEY-----", obs0["public_key_pem"])
        self.assertEqual(obs0["x_cuas_evidence_type"], "ed25519_signed_airspace_dossier")
        self.assertIn(_stix_id("marking-definition", "tlp-red"), observed["marking_refs"])

    def test_competitive_intel_tlp_white(self):
        builder = STIXBundleBuilder()
        entry = CompetitiveIntelEntry(
            name="DragonFire",
            origin="United Kingdom",
            developer="Dstl / MBDA UK",
            system_type="directed_energy_laser",
            power_class="~50 kW class",
            effective_range_km=5.0,
            role="C-UAS / air defense",
            public_status="Demonstrator",
            is_fielded=False,
        )
        builder.add_competitive_intel(entry)
        objs = {o["id"]: o for o in builder.build()["objects"]}
        comp = [
            o
            for o in objs.values()
            if o.get("type") == "observed-data"
            and o["objects"]["0"].get("type") == "x_cuas_competitive_system"
        ]
        self.assertEqual(len(comp), 1)
        self.assertEqual(comp[0]["objects"]["0"]["name"], "DragonFire")
        self.assertIn(_stix_id("marking-definition", "tlp-white"), comp[0]["marking_refs"])

    def test_bundle_determinism(self):
        e1 = _make_event()
        b1 = STIXBundleBuilder()
        b1.add_detection_event(e1)
        h1 = bundle_hash(b1.build())

        b2 = STIXBundleBuilder()
        b2.add_detection_event(_make_event(event_id="DET-EVT-01"))
        h2 = bundle_hash(b2.build())

        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)
        int(h1, 16)  # valid hex

    def test_bundle_hash_changes_with_content(self):
        b1 = STIXBundleBuilder()
        b1.add_detection_event(_make_event(target_id="UAV-001"))
        b2 = STIXBundleBuilder()
        b2.add_detection_event(_make_event(target_id="UAV-002"))
        self.assertNotEqual(bundle_hash(b1.build()), bundle_hash(b2.build()))

    def test_serialization_round_trip(self):
        event = _make_event()
        parsed = detection_event_from_dict(event.to_dict())
        self.assertEqual(parsed.event_id, event.event_id)
        self.assertEqual(parsed.threat_level, event.threat_level)
        self.assertEqual(parsed.anomalies, event.anomalies)

        ref = _make_dossier_ref()
        parsed_ref = forensic_dossier_from_dict(ref.to_dict())
        self.assertEqual(parsed_ref.dossier_id, ref.dossier_id)
        self.assertEqual(parsed_ref.signature, ref.signature)

    def test_stix_namespace_is_fixed(self):
        self.assertIsInstance(STIX_NAMESPACE, __import__("uuid").UUID)
        self.assertEqual(
            _stix_id("bundle", "x"), "bundle--" + str(__import__("uuid").uuid5(STIX_NAMESPACE, "x"))
        )


class TestAlertEngine(unittest.TestCase):
    def test_critical_event_fires_alert(self):
        engine = AlertEngine(
            channels=[Channel(config=ChannelConfig(kind="console"), send=ConsoleChannel().send)]
        )
        alerts = engine.process_event(_make_event(threat_level="CRITICAL"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "CRITICAL")
        self.assertIn("UAV-ROGUE-01", alerts[0].message)

    def test_spoof_detection_always_alerts(self):
        engine = AlertEngine()
        alerts = engine.process_event(_make_event(source="spoof_detector", threat_level="MEDIUM"))
        self.assertGreaterEqual(len(alerts), 1)

    def test_high_event_alerts(self):
        engine = AlertEngine(
            channels=[Channel(config=ChannelConfig(kind="console"), send=ConsoleChannel().send)]
        )
        alerts = engine.process_event(_make_event(threat_level="HIGH"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_alert_has_required_fields(self):
        engine = AlertEngine()
        alerts = engine.process_event(_make_event(threat_level="CRITICAL"))
        a = alerts[0]
        self.assertTrue(a.alert_id.startswith("alert--"))
        self.assertIn("T", a.timestamp)
        self.assertIn(a.severity, ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"))
        self.assertIsInstance(a.metadata, dict)

    def test_default_rules_present(self):
        rule_ids = {r.rule_id for r in DEFAULT_RULES}
        self.assertIn("spoof_detection", rule_ids)
        self.assertIn("high_confidence_track", rule_ids)
        self.assertIn("incident", rule_ids)
        self.assertIn("compliance_drop", rule_ids)

    def test_email_stub_is_log_only(self):
        engine = AlertEngine(
            channels=[
                Channel(
                    config=ChannelConfig(kind="email", email_to="soc@a2zsoc.com"),
                    send=EmailStubChannel("soc@a2zsoc.com").send,
                )
            ]
        )
        with patch("sys.stdout") as _mock_stdout:
            alerts = engine.process_event(_make_event(threat_level="CRITICAL"))
        self.assertEqual(len(alerts), 1)


class TestTaxiiServer(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app_factory())

    def test_discovery_endpoint(self):
        resp = self.client.get("/taxii2/")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["type"], "discovery")
        self.assertEqual(len(body["api_roots"]), 1)

    def test_list_collections(self):
        resp = self.client.get("/taxii2/collections/")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["type"], "collection-collection")
        self.assertEqual(len(body["collections"]), 1)
        self.assertEqual(body["collections"][0]["id"], "cuas-detections")

    def test_collection_detail(self):
        resp = self.client.get("/taxii2/collections/cuas-detections/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["id"], "cuas-detections")

    def test_unknown_collection_404(self):
        resp = self.client.get("/taxii2/collections/nope/")
        self.assertEqual(resp.status_code, 404)

    def test_get_objects_returns_bundle(self):
        resp = self.client.get("/taxii2/collections/cuas-detections/objects/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["type"], "bundle")
        self.assertEqual(resp.json()["spec_version"], "2.1")

    def test_get_objects_type_filter(self):
        resp = self.client.get(
            "/taxii2/collections/cuas-detections/objects/?type=marking-definition"
        )
        self.assertEqual(resp.status_code, 200)
        for obj in resp.json()["objects"]:
            self.assertEqual(obj["type"], "marking-definition")


class TestStorePersistence(unittest.TestCase):
    def test_save_and_list_bundle(self):
        store = ThreatIntelStore()
        builder = STIXBundleBuilder()
        builder.add_detection_event(_make_event())
        bundle = builder.build()
        before = len(store.list_bundles())
        store.save_bundle(bundle)
        after = len(store.list_bundles())
        self.assertEqual(after, before + 1)
        # Persisted bundle retains its id.
        ids = [b["id"] for b in store.list_bundles()]
        self.assertIn(bundle["id"], ids)


if __name__ == "__main__":
    unittest.main()
