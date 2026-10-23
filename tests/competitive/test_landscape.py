"""Tests for the global C-UAS competitive landscape database."""

import unittest

from c_uas.competitive_landscape import CUASDatabase, CUASSystem


class TestCUASDatabase(unittest.TestCase):
    def setUp(self):
        self.db = CUASDatabase()

    def test_list_all_returns_systems(self):
        systems = self.db.list_all()
        self.assertGreater(len(systems), 0)
        self.assertIsInstance(systems[0], CUASSystem)

    def test_get_by_name(self):
        dragonfire = self.db.get("DragonFire")
        self.assertIsNotNone(dragonfire)
        self.assertEqual(dragonfire.name, "DragonFire")
        self.assertEqual(dragonfire.origin, "United Kingdom")
        self.assertEqual(dragonfire.system_type, "directed_energy_laser")

    def test_get_nonexistent(self):
        self.assertIsNone(self.db.get("Nonexistent System"))

    def test_list_by_origin(self):
        uk_systems = self.db.list_by_origin("United Kingdom")
        self.assertGreaterEqual(len(uk_systems), 1)
        self.assertTrue(all(s.origin == "United Kingdom" for s in uk_systems))

    def test_list_by_type(self):
        lasers = self.db.list_by_type("directed_energy_laser")
        self.assertGreaterEqual(len(lasers), 3)
        self.assertTrue(all(s.system_type == "directed_energy_laser" for s in lasers))

    def test_list_fielded(self):
        fielded = self.db.list_fielded()
        self.assertGreater(len(fielded), 0)
        self.assertTrue(all(s.is_fielded for s in fielded))

    def test_summary_structure(self):
        summary = self.db.summary()
        self.assertIn("total", summary)
        self.assertIn("fielded", summary)
        self.assertIn("by_type", summary)
        self.assertIn("origins", summary)
        self.assertGreater(summary["total"], 0)
        self.assertEqual(
            summary["fielded"] + summary["demonstrator_or_development"], summary["total"]
        )

    def test_system_properties(self):
        s = self.db.get("AN/TWQ-1 Avenger")
        self.assertTrue(s.is_fielded)
        self.assertTrue(s.has_unit_cost)
        self.assertFalse(s.has_cpe)

    def test_system_not_fielded(self):
        s = self.db.get("DragonFire")
        self.assertFalse(s.is_fielded)


if __name__ == "__main__":
    unittest.main()
