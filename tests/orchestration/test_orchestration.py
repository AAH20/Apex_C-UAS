"""Tests for the multi-site orchestration layer."""

import unittest

from c_uas.orchestration import (
    DroneTrack,
    Federation,
    SiteAgent,
    SiteConfig,
    build_demo_federation,
)
from c_uas.swarm import SwarmConfig, SwarmSimulator


class TestSiteAgent(unittest.TestCase):
    def test_site_agent_creation(self):
        site = SiteAgent(
            config=SiteConfig(
                site_id="s1", name="Site 1", latitude_deg=0.0, longitude_deg=0.0
            )
        )
        self.assertEqual(site.config.site_id, "s1")
        self.assertEqual(len(site.tracks), 0)

    def test_detect_and_track(self):
        site = SiteAgent(
            config=SiteConfig(
                site_id="s1", name="Site 1", latitude_deg=0.0, longitude_deg=0.0
            )
        )
        sim_config = SwarmConfig(
            num_drones=4, arrival_spread_s=5.0, speed_mps=30.0,
            start_distance_km=2.0, evasion_probability=0.0, seed=42,
        )
        from c_uas.swarm import SwarmSimulator

        sim = SwarmSimulator(sim_config)
        new_tracks = site.detect_and_track(sim)
        self.assertEqual(len(new_tracks), 4)
        self.assertEqual(len(site.tracks), 4)

    def test_schedule_engagements(self):
        site = SiteAgent(
            config=SiteConfig(
                site_id="s1", name="Site 1", latitude_deg=0.0, longitude_deg=0.0
            )
        )
        sim_config = SwarmConfig(
            num_drones=4, arrival_spread_s=5.0, speed_mps=30.0,
            start_distance_km=2.0, evasion_probability=0.0, seed=42,
        )
        from c_uas.swarm import SwarmSimulator

        sim = SwarmSimulator(sim_config)
        site.detect_and_track(sim)
        plan = site.schedule_engagements()
        self.assertIsNotNone(plan)
        self.assertGreaterEqual(plan.expected_kills, 0.0)

    def test_export_and_ingest_tracks(self):
        site_a = SiteAgent(
            config=SiteConfig(
                site_id="a", name="A", latitude_deg=0.0, longitude_deg=0.0
            )
        )
        site_b = SiteAgent(
            config=SiteConfig(
                site_id="b", name="B", latitude_deg=0.1, longitude_deg=0.0
            )
        )
        sim_config = SwarmConfig(
            num_drones=4, arrival_spread_s=5.0, speed_mps=30.0,
            start_distance_km=2.0, evasion_probability=0.0, seed=42,
        )
        from c_uas.swarm import SwarmSimulator

        sim = SwarmSimulator(sim_config)
        site_a.detect_and_track(sim)
        exported = site_a.export_tracks()
        self.assertEqual(len(exported), 4)
        ingested = site_b.ingest_peer_tracks(exported)
        self.assertEqual(ingested, 4)
        self.assertEqual(len(site_b.tracks), 4)

    def test_ingest_dedup(self):
        site_a = SiteAgent(
            config=SiteConfig(
                site_id="a", name="A", latitude_deg=0.0, longitude_deg=0.0
            )
        )
        site_b = SiteAgent(
            config=SiteConfig(
                site_id="b", name="B", latitude_deg=0.1, longitude_deg=0.0
            )
        )
        sim_config = SwarmConfig(
            num_drones=2, arrival_spread_s=5.0, speed_mps=30.0,
            start_distance_km=2.0, evasion_probability=0.0, seed=42,
        )
        from c_uas.swarm import SwarmSimulator

        sim = SwarmSimulator(sim_config)
        site_a.detect_and_track(sim)
        exported = site_a.export_tracks()
        site_b.ingest_peer_tracks(exported)
        # Re-ingest same tracks → should add 0
        ingested_again = site_b.ingest_peer_tracks(exported)
        self.assertEqual(ingested_again, 0)


class TestFederation(unittest.TestCase):
    def test_build_demo_federation(self):
        fed = build_demo_federation(num_sites=3)
        self.assertEqual(len(fed.sites), 3)
        self.assertEqual(len(fed.links), 6)  # full mesh: 3*2/2*2 directed

    def test_add_and_remove_site(self):
        fed = Federation()
        site = SiteAgent(
            config=SiteConfig(
                site_id="s1", name="S1", latitude_deg=0.0, longitude_deg=0.0
            )
        )
        fed.add_site(site)
        self.assertEqual(len(fed.sites), 1)
        fed.remove_site("s1")
        self.assertEqual(len(fed.sites), 0)

    def test_link_sites(self):
        fed = Federation()
        a = SiteAgent(
            config=SiteConfig(site_id="a", name="A", latitude_deg=0.0, longitude_deg=0.0)
        )
        b = SiteAgent(
            config=SiteConfig(site_id="b", name="B", latitude_deg=0.1, longitude_deg=0.0)
        )
        fed.add_site(a)
        fed.add_site(b)
        fed.link_sites("a", "b", latency_ms=10.0)
        self.assertEqual(fed.links[("a", "b")], 10.0)
        self.assertEqual(fed.links[("b", "a")], 10.0)

    def test_fuse_tracks(self):
        fed = build_demo_federation(num_sites=2)
        # Each site detects a different subset of the swarm (different seeds)
        sim_a = SwarmSimulator(SwarmConfig(
            num_drones=4, arrival_spread_s=5.0, speed_mps=30.0,
            start_distance_km=2.0, evasion_probability=0.0, seed=42,
        ))
        sim_b = SwarmSimulator(SwarmConfig(
            num_drones=4, arrival_spread_s=5.0, speed_mps=30.0,
            start_distance_km=2.0, evasion_probability=0.0, seed=99,
        ))
        site_a = list(fed.sites.values())[0]
        site_b = list(fed.sites.values())[1]
        site_a.detect_and_track(sim_a)
        site_b.detect_and_track(sim_b)
        self.assertEqual(len(site_a.tracks), 4)
        self.assertEqual(len(site_b.tracks), 4)
        # Offset site_b's track IDs so they don't collide with site_a's
        for tid in list(site_b.tracks.keys()):
            track = site_b.tracks.pop(tid)
            site_b.tracks[tid + 100] = DroneTrack(
                track_id=tid + 100,
                arrival_time_s=track.arrival_time_s,
                pk_base=track.pk_base,
                priority=track.priority,
            )
        fusion = fed.fuse_tracks()
        self.assertEqual(fusion["sites"], 2)
        self.assertGreater(fusion["total_tracks_exported"], 0)
        # After fusion, both sites should have all 8 unique tracks
        self.assertEqual(fusion["tracks_per_site"]["site-1"], 8)
        self.assertEqual(fusion["tracks_per_site"]["site-2"], 8)

    def test_deconflict_engagements(self):
        fed = build_demo_federation(num_sites=2)
        sim_config = SwarmConfig(
            num_drones=4, arrival_spread_s=5.0, speed_mps=30.0,
            start_distance_km=2.0, evasion_probability=0.0, seed=42,
        )
        report = fed.deconflict_engagements()
        self.assertIn("conflicts_detected", report)
        self.assertIn("conflicts_resolved", report)

    def test_run_round(self):
        fed = build_demo_federation(num_sites=2)
        sim_config = SwarmConfig(
            num_drones=4, arrival_spread_s=5.0, speed_mps=30.0,
            start_distance_km=2.0, evasion_probability=0.0, seed=42,
        )
        result = fed.run_round(sim_config)
        self.assertIn("detections", result)
        self.assertIn("fusion", result)
        self.assertIn("engagement_plans", result)
        self.assertIn("deconfliction", result)

    def test_summary(self):
        fed = build_demo_federation(num_sites=2)
        summary = fed.summary()
        self.assertEqual(len(summary["sites"]), 2)
        # 2 sites = 2 directed links (a->b, b->a)
        self.assertEqual(summary["links"], 2)


class TestOrchestrationEdgeCases(unittest.TestCase):
    def test_empty_federation_run_round(self):
        fed = Federation()
        sim_config = SwarmConfig(
            num_drones=2, arrival_spread_s=5.0, speed_mps=30.0,
            start_distance_km=2.0, evasion_probability=0.0, seed=42,
        )
        result = fed.run_round(sim_config)
        self.assertEqual(result["sites"], 0)
        self.assertEqual(result["fusion"]["sites"], 0)

    def test_single_site_federation(self):
        fed = build_demo_federation(num_sites=1)
        self.assertEqual(len(fed.sites), 1)
        self.assertEqual(len(fed.links), 0)


if __name__ == "__main__":
    unittest.main()
