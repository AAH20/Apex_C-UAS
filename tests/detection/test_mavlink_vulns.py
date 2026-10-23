"""Tests for MAVLink vulnerability database."""

import unittest

from c_uas.detection.mavlink_vulns import (
    MAVLINK_VULNERABILITIES,
    MavlinkVulnerabilityDatabase,
)


class TestMavlinkVulnerabilityDatabase(unittest.TestCase):
    def setUp(self):
        self.db = MavlinkVulnerabilityDatabase()

    def test_total_count(self):
        self.assertGreaterEqual(len(MAVLINK_VULNERABILITIES), 10)
        self.assertEqual(self.db.summary()["total"], len(MAVLINK_VULNERABILITIES))

    def test_get_by_id(self):
        vuln = self.db.get("MAV-2017-001")
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.cve, "CVE-2017-15872")
        self.assertEqual(vuln.severity, "HIGH")
        self.assertEqual(vuln.mavlink_version, "2.0")

    def test_get_by_cve(self):
        vuln = self.db.get_by_cve("CVE-2020-12092")
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.title, "MAVLink packet injection via missing authentication")

    def test_get_by_cve_not_found(self):
        self.assertIsNone(self.db.get_by_cve("CVE-9999-9999"))

    def test_list_by_version(self):
        v2 = self.db.list_by_version("2.0")
        self.assertGreater(len(v2), 0)
        for v in v2:
            self.assertTrue(v.mavlink_version == "2.0" or v.mavlink_version == "both")

        v1 = self.db.list_by_version("1.0")
        self.assertGreater(len(v1), 0)
        for v in v1:
            self.assertTrue(v.mavlink_version == "1.0" or v.mavlink_version == "both")

    def test_list_by_severity(self):
        critical = self.db.list_by_severity("CRITICAL")
        self.assertGreater(len(critical), 0)
        for v in critical:
            self.assertEqual(v.severity, "CRITICAL")

    def test_summary_has_severity_breakdown(self):
        summary = self.db.summary()
        self.assertIn("by_severity", summary)
        self.assertEqual(sum(summary["by_severity"].values()), summary["total"])

    def test_affected_messages_non_empty(self):
        for vuln in self.db.list_all():
            self.assertGreater(len(vuln.affected_messages), 0)
            self.assertGreater(len(vuln.detection_signature), 0)
            self.assertGreater(len(vuln.mitigation), 0)

    def test_detect_signatures_unsigned_packet(self):
        hits = self.db.detect_signatures_in_packet(
            message_name="COMMAND_LONG",
            system_id=1,
            component_id=1,
            has_valid_signature=False,
            seq=5,
            prev_seqs=[],
        )
        self.assertGreater(len(hits), 0)

    def test_detect_signatures_replayed_sequence(self):
        hits = self.db.detect_signatures_in_packet(
            message_name="HEARTBEAT",
            system_id=1,
            component_id=1,
            has_valid_signature=True,
            seq=10,
            prev_seqs=[10],
        )
        self.assertGreater(len(hits), 0)

    def test_new_cves_are_lookupable(self):
        for cve in [
            "CVE-2026-1579",
            "CVE-2026-32743",
            "CVE-2026-32724",
            "CVE-2024-33844",
            "CVE-2020-10282",
        ]:
            vuln = self.db.get_by_cve(cve)
            self.assertIsNotNone(vuln, f"{cve} not found in database")
            self.assertIsNotNone(vuln.title)
            self.assertGreater(len(vuln.detection_signature), 0)
            self.assertGreater(len(vuln.mitigation), 0)

    def test_critical_severity_count(self):
        critical = self.db.list_by_severity("CRITICAL")
        self.assertGreaterEqual(len(critical), 2)  # CVE-2026-1579, CVE-2020-10282

    def test_high_severity_count(self):
        high = self.db.list_by_severity("HIGH")
        self.assertGreaterEqual(len(high), 5)

    def test_medium_severity_count(self):
        medium = self.db.list_by_severity("MEDIUM")
        self.assertGreaterEqual(len(medium), 2)

    def test_severity_breakdown_sums_to_total(self):
        summary = self.db.summary()
        self.assertEqual(sum(summary["by_severity"].values()), summary["total"])
        self.assertEqual(summary["total"], 17)


if __name__ == "__main__":
    unittest.main()
