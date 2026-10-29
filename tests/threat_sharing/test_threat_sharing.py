"""Tests for C-UAS Threat Intelligence Sharing & Community Feeds.

Deterministic scenarios only: same inputs produce identical bundles,
manifests are sorted by STIX id, feed ingest de-duplicates by STIX id,
and sharing policy enforces TLP trust-level caps.

State under ~/.c_uas-platform/threat_sharing/ is redirected to a temp
dir per test so runs are isolated and hermetic.
"""

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError

from fastapi.testclient import TestClient

import c_uas.threat_sharing.sharing as sharing
import c_uas.threat_sharing.taxii_server as taxii_server
from c_uas.threat_sharing.feed_client import (
    FeedResult,
    ParsedIndicator,
    confidence_of,
    deduplicate,
    filter_objects,
    ingest_feed,
    parse_bundle,
    relevance_of,
)
from c_uas.threat_sharing.sharing import (
    SharePolicy,
    ShareTrustLevel,
    enforce_policy,
    export_bundle,
    import_from_partner,
)
from c_uas.threat_sharing.taxii_server import (
    TAXIICollection,
    TAXIIManifestEntry,
    app_factory,
)


class _TempState:
    """Redirect threat_sharing state to an isolated temp directory."""

    def __init__(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="threat_sharing_test_")

    def apply(self) -> None:
        pathlib = __import__("pathlib")
        base = pathlib.Path(self.tmpdir)
        taxii_server.DATA_DIR = base
        taxii_server._COLLECTIONS_FILE = base / "collections.json"
        taxii_server._OBJECTS_FILE = base / "objects.json"
        sharing.DATA_DIR = base
        sharing._PARTNERS_FILE = base / "partners.json"
        sharing._SHARES_FILE = base / "shares.json"
        taxii_server._ensure_dir()


def _make_stix_object(stix_id, stix_type, confidence=None, marking=None, pattern=None):
    obj = {
        "id": stix_id,
        "type": stix_type,
        "spec_version": "2.1",
        "created": "2026-10-23T00:00:00Z",
    }
    if confidence is not None:
        obj["confidence"] = confidence
    if marking is not None:
        obj["marking_refs"] = [marking]
    if pattern is not None:
        obj["pattern"] = pattern
    if stix_type == "observed-data":
        obj["objects"] = {"0": {"type": "x_cuas_detection", "detection_id": stix_id}}
        obj["first_observed"] = "2026-10-23T00:00:00Z"
        obj["last_observed"] = "2026-10-23T00:00:00Z"
        obj["number_observed"] = 1
    return obj


def _make_bundle(objects):
    return {
        "type": "bundle",
        "id": "bundle--test",
        "spec_version": "2.1",
        "objects": objects,
    }


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        return None


class TestTaxiiServer(unittest.TestCase):
    def setUp(self):
        self.state = _TempState()
        self.state.apply()
        self.client = TestClient(app_factory())

    def test_discovery_endpoint(self):
        resp = self.client.get("/taxii2/")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["type"], "discovery")
        self.assertEqual(body["spec_version"], "2.1")
        self.assertEqual(len(body["api_roots"]), 1)
        self.assertEqual(body["api_roots"][0]["id"], "cuas-platform")

    def test_list_collections(self):
        resp = self.client.get("/taxii2/collections/")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["type"], "collection-collection")
        self.assertEqual(len(body["collections"]), 1)
        self.assertEqual(body["collections"][0]["id"], "cuas-indicators")

    def test_collection_detail(self):
        resp = self.client.get("/taxii2/collections/cuas-indicators/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["id"], "cuas-indicators")

    def test_unknown_collection_404(self):
        resp = self.client.get("/taxii2/collections/does-not-exist/")
        self.assertEqual(resp.status_code, 404)

    def test_post_objects_then_manifest_and_objects(self):
        objs = [
            _make_stix_object("indicator--aaa", "indicator", confidence=0.9),
            _make_stix_object("observed-data--bbb", "observed-data"),
        ]
        resp = self.client.post(
            "/taxii2/collections/cuas-indicators/objects/",
            json=_make_bundle(objs),
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "complete")

        manifest = self.client.get("/taxii2/collections/cuas-indicators/manifest/")
        self.assertEqual(manifest.status_code, 200)
        entries = manifest.json()["objects"]
        ids = sorted(e["id"] for e in entries)
        self.assertEqual(ids, ["indicator--aaa", "observed-data--bbb"])

        got = self.client.get("/taxii2/collections/cuas-indicators/objects/")
        self.assertEqual(got.json()["type"], "bundle")
        self.assertEqual(len(got.json()["objects"]), 2)

    def test_get_objects_type_filter(self):
        self.client.post(
            "/taxii2/collections/cuas-indicators/objects/",
            json=_make_bundle(
                [
                    _make_stix_object("indicator--aaa", "indicator"),
                    _make_stix_object("marking-definition--md", "marking-definition"),
                ]
            ),
        )
        resp = self.client.get("/taxii2/collections/cuas-indicators/objects/?type=indicator")
        self.assertEqual(resp.status_code, 200)
        for obj in resp.json()["objects"]:
            self.assertEqual(obj["type"], "indicator")


class TestManifestGeneration(unittest.TestCase):
    def setUp(self):
        self.state = _TempState()
        self.state.apply()
        self.client = TestClient(app_factory())

    def test_manifest_entries_sorted_by_stix_id(self):
        objs = [
            _make_stix_object("indicator--zeta", "indicator"),
            _make_stix_object("indicator--alpha", "indicator"),
            _make_stix_object("indicator--mid", "indicator"),
        ]
        self.client.post(
            "/taxii2/collections/cuas-indicators/objects/",
            json=_make_bundle(objs),
        )
        entries = self.client.get("/taxii2/collections/cuas-indicators/manifest/").json()["objects"]
        ids = [e["id"] for e in entries]
        self.assertEqual(ids, ["indicator--alpha", "indicator--mid", "indicator--zeta"])

    def test_manifest_dedup_by_stix_id(self):
        v1 = _make_stix_object("indicator--dup", "indicator")
        v2 = dict(v1, version="2")
        self.client.post(
            "/taxii2/collections/cuas-indicators/objects/",
            json=_make_bundle([v1]),
        )
        self.client.post(
            "/taxii2/collections/cuas-indicators/objects/",
            json=_make_bundle([v2]),
        )
        entries = self.client.get("/taxii2/collections/cuas-indicators/manifest/").json()["objects"]
        self.assertEqual(len(entries), 1)


class TestFeedClient(unittest.TestCase):
    def test_parse_bundle_extracts_objects(self):
        objs = [
            _make_stix_object("indicator--a", "indicator"),
            _make_stix_object("indicator--b", "indicator"),
        ]
        parsed = parse_bundle(_make_bundle(objs))
        self.assertEqual(len(parsed), 2)
        self.assertEqual([o["id"] for o in parsed], ["indicator--a", "indicator--b"])

    def test_parse_bundle_single_stix_object(self):
        parsed = parse_bundle(_make_stix_object("indicator--solo", "indicator"))
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["id"], "indicator--solo")

    def test_confidence_extraction(self):
        high = _make_stix_object("indicator--hi", "indicator", confidence=0.9)
        low = _make_stix_object("indicator--lo", "indicator", confidence=0.2)
        missing = _make_stix_object("indicator--none", "indicator")
        self.assertEqual(confidence_of(high), 0.9)
        self.assertEqual(confidence_of(low), 0.2)
        self.assertIsNone(confidence_of(missing))

    def test_relevance_scoring(self):
        plain = relevance_of(_make_stix_object("indicator--p", "indicator"))
        marked = relevance_of(_make_stix_object("indicator--m", "indicator", pattern="[x:y = 'z']"))
        self.assertGreaterEqual(marked, plain)
        self.assertLessEqual(marked, 1.0)

    def test_filter_objects_by_confidence_and_relevance(self):
        objs = [
            _make_stix_object("indicator--keep", "indicator", confidence=0.9),
            _make_stix_object("indicator--drop", "indicator", confidence=0.2),
        ]
        kept = filter_objects(objs, min_confidence=0.5, min_relevance=0.3)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].stix_id, "indicator--keep")

    def test_deduplicate_by_stix_id(self):
        existing = ["indicator--old"]
        incoming = [
            ParsedIndicator("indicator--old", "indicator", 0.9, 0.5, {}),
            ParsedIndicator("indicator--new", "indicator", 0.8, 0.6, {}),
        ]
        new_indicators, duplicates = deduplicate(existing, incoming)
        self.assertEqual(len(new_indicators), 1)
        self.assertEqual(new_indicators[0].stix_id, "indicator--new")
        self.assertEqual(duplicates, ["indicator--old"])

    def test_ingest_feed_deterministic(self):
        objs = [
            _make_stix_object("indicator--keep", "indicator", confidence=0.9),
            _make_stix_object("indicator--drop", "indicator", confidence=0.2),
        ]
        bundle = _make_bundle(objs)

        def _get(url):
            assert url == "https://partner.example/taxii2/collections/c1/objects/"
            return _FakeResponse(bundle)

        existing = []
        result = ingest_feed(
            "https://partner.example/taxii2/collections/c1/objects/",
            existing,
            _get,
            min_confidence=0.5,
            min_relevance=0.3,
        )
        self.assertIsInstance(result, FeedResult)
        self.assertEqual(result.objects_received, 2)
        self.assertEqual(result.objects_ingested, 1)
        self.assertEqual(result.filtered_out, 1)
        self.assertEqual(result.ingested_ids, ("indicator--keep",))
        self.assertEqual(len(result.sha256), 64)

        # Same input -> same result (determinism).
        result2 = ingest_feed(
            "https://partner.example/taxii2/collections/c1/objects/",
            existing,
            _get,
            min_confidence=0.5,
            min_relevance=0.3,
        )
        self.assertEqual(result2.sha256, result.sha256)
        self.assertEqual(result2.objects_ingested, result.objects_ingested)


class TestSharingPolicy(unittest.TestCase):
    def test_trust_level_can_receive_tlp_cap(self):
        untrusted = ShareTrustLevel("untrusted", "tlp-white")
        trusted = ShareTrustLevel("trusted", "tlp-amber")
        allied = ShareTrustLevel("allied", "tlp-red")

        self.assertTrue(untrusted.can_receive(["tlp-white"]))
        self.assertFalse(untrusted.can_receive(["tlp-amber"]))
        self.assertFalse(untrusted.can_receive(["tlp-red"]))
        self.assertTrue(trusted.can_receive(["tlp-amber", "tlp-white"]))
        self.assertFalse(trusted.can_receive(["tlp-red"]))
        self.assertTrue(allied.can_receive(["tlp-red"]))

    def test_enforce_policy_denies_above_tlp(self):
        policy = SharePolicy(
            trust_levels=(
                ShareTrustLevel("untrusted", "tlp-white"),
                ShareTrustLevel("trusted", "tlp-amber"),
            )
        )
        objects = [
            _make_stix_object("indicator--white", "indicator", marking="tlp-white"),
            _make_stix_object("indicator--red", "indicator", marking="tlp-red"),
        ]
        allowed, denied = enforce_policy(policy, "acme", "untrusted", objects)
        self.assertEqual(len(allowed), 1)
        self.assertEqual(allowed[0]["id"], "indicator--white")
        self.assertEqual(denied, ["indicator--red"])

    def test_unknown_trust_level_denies_all(self):
        policy = SharePolicy()
        objects = [_make_stix_object("indicator--x", "indicator", marking="tlp-white")]
        allowed, denied = enforce_policy(policy, "acme", "nonexistent", objects)
        self.assertEqual(allowed, [])
        self.assertEqual(denied, ["indicator--x"])


class TestBundleExport(unittest.TestCase):
    def test_export_bundle_produces_stix_bundle(self):
        policy = SharePolicy()
        objects = [
            _make_stix_object("indicator--a", "indicator", marking="tlp-amber"),
            _make_stix_object("indicator--b", "indicator", marking="tlp-white"),
        ]
        bundle, denied = export_bundle(objects, "acme", "trusted", policy=policy)
        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(bundle["spec_version"], "2.1")
        self.assertEqual(len(denied), 0)
        self.assertTrue(bundle["id"].startswith("bundle--"))

    def test_export_bundle_denies_above_partner_tlp(self):
        policy = SharePolicy()
        objects = [
            _make_stix_object("indicator--red", "indicator", marking="tlp-red"),
            _make_stix_object("indicator--white", "indicator", marking="tlp-white"),
        ]
        bundle, denied = export_bundle(objects, "acme", "untrusted", policy=policy)
        self.assertEqual(denied, ["indicator--red"])
        ids = [o["id"] for o in bundle.get("objects", []) if o.get("type") != "marking-definition"]
        self.assertNotIn("indicator--red", ids)

    def test_export_bundle_deterministic(self):
        policy = SharePolicy()
        objects = [
            _make_stix_object("indicator--a", "indicator", marking="tlp-amber"),
        ]
        b1, _ = export_bundle(objects, "acme", "trusted", policy=policy)
        b2, _ = export_bundle(objects, "acme", "trusted", policy=policy)
        self.assertEqual(json.dumps(b1, sort_keys=True), json.dumps(b2, sort_keys=True))

    def test_import_from_partner_applies_policy(self):
        policy = SharePolicy()
        bundle = _make_bundle(
            [
                _make_stix_object("indicator--red", "indicator", marking="tlp-red"),
                _make_stix_object("indicator--white", "indicator", marking="tlp-white"),
            ]
        )
        accepted, denied = import_from_partner(bundle, "acme", "untrusted", policy=policy)
        self.assertEqual(len(accepted), 1)
        self.assertEqual(accepted[0]["id"], "indicator--white")
        self.assertEqual(denied, ["indicator--red"])

    def test_record_and_list_shares(self):
        self.state = _TempState()
        self.state.apply()
        policy = SharePolicy()
        objects = [_make_stix_object("indicator--a", "indicator", marking="tlp-white")]
        bundle, _ = export_bundle(objects, "acme", "trusted", policy=policy)
        share = sharing.record_share("acme", "trusted", bundle, objects)
        self.assertTrue(share.share_id.startswith("share--"))
        self.assertEqual(share.partner, "acme")
        self.assertEqual(share.partner_trust_level, "trusted")
        self.assertEqual(share.object_ids, ("indicator--a",))

        shares = sharing.list_shares()
        self.assertEqual(len(shares), 1)
        self.assertEqual(shares[0].share_id, share.share_id)


class TestFrozenDataclasses(unittest.TestCase):
    def test_taxii_collection_frozen(self):
        c = TAXIICollection(id="c1", title="t", description="d")
        with self.assertRaises(FrozenInstanceError):
            c.id = "changed"

    def test_taxii_manifest_entry_frozen(self):
        m = TAXIIManifestEntry(
            id="ind--x", type="indicator", version="1", date_added="2026-01-01T00:00:00Z"
        )
        with self.assertRaises(FrozenInstanceError):
            m.type = "changed"


if __name__ == "__main__":
    unittest.main()
