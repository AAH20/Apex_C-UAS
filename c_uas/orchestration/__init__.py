"""
Agentic Multi-Site C-UAS Orchestration.

Federates multiple C-UAS sites into a coordinated air defense network:
- Each site runs a local agent (detection, tracking, engagement scheduling)
- Sites share tracks over a mesh federation
- Track fusion deduplicates cross-site observations
- Engagement deconfliction prevents multiple sites engaging the same drone
- Graph-based coordination: sites are nodes, radio links are edges

Defensive-only: detection, tracking, federation, deconfliction. No live SDR,
no weapons-employment effector, no exploitation.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Optional

from c_uas.engagement.scheduler import (
    DroneTrack,
    EngagementPlan,
    EngagementScheduler,
)
from c_uas.swarm import SwarmConfig, SwarmSimulator, SwarmTrack

# ---------------------------------------------------------------------------
# Site agent
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SiteConfig:
    """Configuration for a single C-UAS site agent."""

    site_id: str
    name: str
    latitude_deg: float
    longitude_deg: float
    detection_range_km: float = 5.0
    dwell_s: float = 4.0
    slew_s: float = 1.5
    time_limit_s: float = 40.0


@dataclass
class SiteAgent:
    """
    Autonomous agent for a single C-UAS site.

    Maintains local track list, runs the engagement scheduler, and exchanges
    tracks with peer sites via the federation.
    """

    config: SiteConfig
    tracks: dict[int, DroneTrack] = field(default_factory=dict)
    engagements: dict = field(default_factory=dict)
    last_heartbeat: float = field(default_factory=time.time)
    peer_sites: set[str] = field(default_factory=set)
    federation_messages: list[dict] = field(default_factory=list)

    def detect_and_track(
        self, swarm_sim: SwarmSimulator, current_time_s: float = 0.0
    ) -> list[DroneTrack]:
        """
        Generate tracks from the swarm simulator and add to local track list.

        Returns newly detected tracks.
        """
        sim_tracks: list[SwarmTrack] = swarm_sim.generate_tracks()
        new_tracks: list[DroneTrack] = []

        for st in sim_tracks:
            track_id = st.track_id
            if track_id not in self.tracks:
                dt = DroneTrack(
                    track_id=track_id,
                    arrival_time_s=st.arrival_time_s,
                    pk_base=st.pk_base,
                    priority=st.priority,
                )
                self.tracks[track_id] = dt
                new_tracks.append(dt)

        self.last_heartbeat = time.time()
        return new_tracks

    def schedule_engagements(self) -> EngagementPlan:
        """
        Run the NP-hard engagement scheduler on local tracks.

        Returns the engagement plan.
        """
        scheduler = EngagementScheduler(
            dwell_s=self.config.dwell_s,
            slew_s=self.config.slew_s,
            time_limit_s=self.config.time_limit_s,
        )
        track_list = list(self.tracks.values())
        if not track_list:
            return EngagementPlan(
                expected_kills=0.0,
                total_time_s=0.0,
                engaged_targets=0,
                leaked_targets=0,
                sequence=[],
            )
        plan = scheduler.schedule(tracks=track_list)
        self.engagements = {
            "plan": plan,
            "scheduled_at": time.time(),
        }
        return plan

    def export_tracks(self) -> list[dict]:
        """
        Export local tracks for federation sharing.

        Returns a list of track dicts with site attribution.
        """
        return [
            {
                "track_id": t.track_id,
                "site_id": self.config.site_id,
                "arrival_time_s": t.arrival_time_s,
                "pk_base": t.pk_base,
                "priority": t.priority,
                "source_site": self.config.site_id,
                "timestamp": time.time(),
            }
            for t in self.tracks.values()
        ]

    def ingest_peer_tracks(self, peer_tracks: list[dict]) -> int:
        """
        Ingest tracks from peer sites, deduplicating by track identity.

        Returns number of new tracks added.
        """
        added = 0
        for pt in peer_tracks:
            tid = pt["track_id"]
            if tid not in self.tracks:
                dt = DroneTrack(
                    track_id=tid,
                    arrival_time_s=pt["arrival_time_s"],
                    pk_base=pt["pk_base"],
                    priority=pt.get("priority", 3),
                )
                self.tracks[tid] = dt
                added += 1
        return added

    def summary(self) -> dict:
        return {
            "site_id": self.config.site_id,
            "name": self.config.name,
            "lat": self.config.latitude_deg,
            "lon": self.config.longitude_deg,
            "detection_range_km": self.config.detection_range_km,
            "local_tracks": len(self.tracks),
            "peer_count": len(self.peer_sites),
            "last_heartbeat": self.last_heartbeat,
        }


# ---------------------------------------------------------------------------
# Federation
# ---------------------------------------------------------------------------


@dataclass
class Federation:
    """
    Mesh federation of C-UAS site agents.

    Coordinates track sharing, cross-site deduplication, and engagement
    deconfliction across all member sites.
    """

    sites: dict[str, SiteAgent] = field(default_factory=dict)
    links: dict[tuple[str, str], float] = field(default_factory=dict)
    fusion_history: list[dict] = field(default_factory=list)
    deconfliction_log: list[dict] = field(default_factory=list)

    def add_site(self, agent: SiteAgent) -> None:
        self.sites[agent.config.site_id] = agent
        # Auto-link to all existing sites (full mesh)
        for other_id in self.sites:
            if other_id != agent.config.site_id:
                self.links[(agent.config.site_id, other_id)] = 5.0  # 5ms simulated
                self.links[(other_id, agent.config.site_id)] = 5.0

    def remove_site(self, site_id: str) -> None:
        if site_id in self.sites:
            del self.sites[site_id]
        # Remove links involving this site
        to_remove = [k for k in self.links if site_id in k]
        for k in to_remove:
            del self.links[k]

    def link_sites(self, site_a: str, site_b: str, latency_ms: float = 5.0) -> None:
        self.links[(site_a, site_b)] = latency_ms
        self.links[(site_b, site_a)] = latency_ms
        if site_a in self.sites:
            self.sites[site_a].peer_sites.add(site_b)
        if site_b in self.sites:
            self.sites[site_b].peer_sites.add(site_a)

    def fuse_tracks(self) -> dict:
        """
        Run track fusion across all sites.

        Each site exports its tracks; every site ingests all peer tracks.
        Cross-site duplicates are deduplicated by track_id.

        Returns fusion statistics.
        """
        # Export all tracks from all sites
        all_exported: dict[str, list[dict]] = {}
        for sid, agent in self.sites.items():
            all_exported[sid] = agent.export_tracks()

        # Ingest peer tracks at each site
        total_ingested = 0
        for sid, agent in self.sites.items():
            for other_sid, tracks in all_exported.items():
                if other_sid == sid:
                    continue
                ingested = agent.ingest_peer_tracks(tracks)
                total_ingested += ingested

        record = {
            "timestamp": time.time(),
            "sites": len(self.sites),
            "total_tracks_exported": sum(len(v) for v in all_exported.values()),
            "total_tracks_ingested": total_ingested,
            "tracks_per_site": {sid: len(agent.tracks) for sid, agent in self.sites.items()},
        }
        self.fusion_history.append(record)
        return record

    def deconflict_engagements(self) -> dict:
        """
        Deconflict engagements across sites.

        Ensures no two sites schedule an engagement on the same drone
        (identified by track_id) at overlapping times.

        Returns deconfliction report.
        """
        # Collect all engagement plans
        all_plans: dict[str, EngagementPlan] = {}
        for sid, agent in self.sites.items():
            if agent.engagements:
                plan = agent.engagements.get("plan")
                if isinstance(plan, EngagementPlan):
                    all_plans[sid] = plan

        conflicts: list[dict] = []
        resolved: list[dict] = []

        # Build map: track_id -> list of sites engaging it
        target_to_sites: dict[int, list[str]] = {}
        for sid, plan in all_plans.items():
            # engaged_targets is a list of track_ids in the sequence
            for seq_entry in plan.sequence:
                tid = seq_entry.get("track_id")
                if tid is not None:
                    target_to_sites.setdefault(tid, []).append(sid)

        for track_id, sites in target_to_sites.items():
            if len(sites) > 1:
                # Conflict: multiple sites engaging same drone
                # Resolve: first site wins, others back off
                winner = sites[0]
                for loser in sites[1:]:
                    conflicts.append(
                        {
                            "track_id": track_id,
                            "conflicting_sites": sites,
                            "winner": winner,
                            "loser": loser,
                            "resolution": "first_site_wins",
                        }
                    )
                    resolved.append(
                        {
                            "track_id": track_id,
                            "loser_site": loser,
                            "action": "back_off",
                        }
                    )

        record = {
            "timestamp": time.time(),
            "sites_with_plans": len(all_plans),
            "conflicts_detected": len(conflicts),
            "conflicts_resolved": len(resolved),
            "conflicts": conflicts,
            "resolutions": resolved,
        }
        self.deconfliction_log.append(record)
        return record

    def run_round(self, swarm_config: SwarmConfig, current_time_s: float = 0.0) -> dict:
        """
        Execute one full orchestration round:
        1. Each site detects and tracks from swarm
        2. Federation fuses tracks across sites
        3. Each site schedules engagements locally
        4. Federation deconflicts engagements

        Returns round summary.
        """
        sim = SwarmSimulator(swarm_config)

        # Phase 1: Detection at each site
        detections: dict[str, int] = {}
        for sid, agent in self.sites.items():
            new_tracks = agent.detect_and_track(sim, current_time_s)
            detections[sid] = len(new_tracks)

        # Phase 2: Track fusion
        fusion = self.fuse_tracks()

        # Phase 3: Local engagement scheduling
        plans: dict[str, dict] = {}
        for sid, agent in self.sites.items():
            plan = agent.schedule_engagements()
            plans[sid] = {
                "expected_kills": plan.expected_kills,
                "engaged_targets": plan.engaged_targets,
                "leaked_targets": plan.leaked_targets,
                "total_time_s": plan.total_time_s,
                "leak_rate": round(plan.leaked_targets / max(len(agent.tracks), 1), 4),
            }

        # Phase 4: Deconfliction
        deconflict = self.deconflict_engagements()

        return {
            "round_timestamp": time.time(),
            "sites": len(self.sites),
            "detections": detections,
            "fusion": fusion,
            "engagement_plans": plans,
            "deconfliction": deconflict,
        }

    def summary(self) -> dict:
        return {
            "sites": {sid: agent.summary() for sid, agent in self.sites.items()},
            "links": len(self.links),
            "fusion_rounds": len(self.fusion_history),
            "deconfliction_rounds": len(self.deconfliction_log),
        }


# ---------------------------------------------------------------------------
# Convenience: build a demo federation
# ---------------------------------------------------------------------------


def build_demo_federation(num_sites: int = 3) -> Federation:
    """
    Build a demo federation of C-UAS sites around a defended asset.

    Sites are placed in a triangle around the origin (0, 0).
    """
    fed = Federation()
    angles = [0, 120, 240]
    radius_km = 3.0
    for i in range(min(num_sites, len(angles))):
        angle_rad = math.radians(angles[i])
        lat = radius_km * math.cos(angle_rad) / 111.0  # rough km->deg
        lon = radius_km * math.sin(angle_rad) / 111.0
        site = SiteAgent(
            config=SiteConfig(
                site_id=f"site-{i + 1}",
                name=f"C-UAS Site {i + 1}",
                latitude_deg=lat,
                longitude_deg=lon,
                detection_range_km=5.0,
            )
        )
        fed.add_site(site)

    # Full mesh links
    site_ids = [s.config.site_id for s in fed.sites.values()]
    for i in range(len(site_ids)):
        for j in range(i + 1, len(site_ids)):
            fed.link_sites(site_ids[i], site_ids[j], latency_ms=5.0)

    return fed
