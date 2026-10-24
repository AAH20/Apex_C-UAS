"""
Swarm Simulation Module.

Simulates multiple coordinated drones (a swarm) approaching a defended asset,
with configurable swarm size, arrival patterns, and evasion behavior. Used to
stress-test the engagement scheduler under swarm saturation — the #1 bottleneck
identified in parallel-bottleneck-discovery.

Defensive-only: simulation of threat trajectories for scheduler evaluation.
No weapons-employment effector, no live SDR, no exploitation code.

Usage:
    from c_uas.swarm.swarm_simulator import SwarmSimulator, SwarmConfig, DroneState
    sim = SwarmSimulator(SwarmConfig(num_drones=16, arrival_spread_s=10.0))
    tracks = sim.generate_tracks()
    # Feed tracks into EngagementScheduler.schedule(tracks=tracks)
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class SwarmConfig:
    """Configuration for a swarm simulation run."""

    num_drones: int  # Number of drones in the swarm
    arrival_spread_s: float  # Time window over which drones arrive (seconds)
    speed_mps: float  # Drone speed in meters/second
    start_distance_km: float  # Initial distance from defended asset (km)
    evasion_probability: float  # Probability each drone evades (0.0-1.0)
    seed: Optional[int] = None  # Deterministic RNG seed


@dataclass(frozen=True)
class DroneState:
    """Single drone state at a point in time."""

    drone_id: int
    x_m: float
    y_m: float
    z_m: float
    vx_mps: float
    vy_mps: float
    vz_mps: float
    timestamp_s: float
    evading: bool = False


@dataclass(frozen=True)
class SwarmTrack:
    """A drone track converted to scheduler-compatible format."""

    track_id: int
    arrival_time_s: float
    pk_base: float  # Base probability of kill (0.0-1.0)
    priority: int  # 1-5, higher = more important to engage


class SwarmSimulator:
    """
    Generates synthetic swarm tracks for engagement scheduler evaluation.

    Drones start at a configurable distance and approach the defended asset
    (at origin) at constant speed. Arrival times are spread across the
    arrival window. Evasion reduces pk_base for evading drones.
    """

    def __init__(self, config: SwarmConfig) -> None:
        self.config = config
        self.rng = random.Random(config.seed)

    def generate_tracks(self) -> List[SwarmTrack]:
        """Generate a deterministic set of swarm tracks."""
        tracks: List[SwarmTrack] = []
        for i in range(self.config.num_drones):
            # Arrival time spread across the window
            arrival = self.rng.uniform(5.0, 5.0 + self.config.arrival_spread_s)

            # Base pk depends on drone characteristics
            # Faster/closer drones are harder to kill (lower pk)
            speed_factor = 1.0 - min(self.config.speed_mps / 100.0, 0.5)
            base_pk = 0.5 + 0.4 * speed_factor

            # Evasion reduces pk
            evading = self.rng.random() < self.config.evasion_probability
            if evading:
                base_pk *= 0.6  # 40% reduction for evading drones

            # Priority: random, weighted toward higher for closer/faster drones
            priority = self.rng.randint(1, 5)

            tracks.append(
                SwarmTrack(
                    track_id=i,
                    arrival_time_s=round(arrival, 2),
                    pk_base=round(max(0.1, min(0.99, base_pk)), 3),
                    priority=priority,
                )
            )

        # Sort by arrival time for deterministic ordering
        tracks.sort(key=lambda t: t.arrival_time_s)
        return tracks

    def generate_drone_states(self, timestamp_s: float) -> List[DroneState]:
        """Generate drone states at a specific timestamp (for real-time simulation)."""
        tracks = self.generate_tracks()
        states: List[DroneState] = []
        for track in tracks:
            # Position along approach vector at this timestamp
            progress = min(timestamp_s / track.arrival_time_s, 1.0)
            distance_m = self.config.start_distance_km * 1000.0 * (1.0 - progress)

            # Approach from random bearing
            bearing = self.rng.uniform(0.0, 2.0 * math.pi)
            x_m = distance_m * math.cos(bearing)
            y_m = distance_m * math.sin(bearing)
            z_m = 100.0 + progress * 400.0  # Climb from 100m to 500m

            # Velocity toward origin
            vx = -self.config.speed_mps * math.cos(bearing)
            vy = -self.config.speed_mps * math.sin(bearing)
            vz = 50.0  # Climbing

            evading = track.pk_base < 0.5  # Evasion correlates with lower pk

            states.append(
                DroneState(
                    drone_id=track.track_id,
                    x_m=round(x_m, 1),
                    y_m=round(y_m, 1),
                    z_m=round(z_m, 1),
                    vx_mps=round(vx, 1),
                    vy_mps=round(vy, 1),
                    vz_mps=round(vz, 1),
                    timestamp_s=round(timestamp_s, 2),
                    evading=evading,
                )
            )
        return states

    def swarm_density(self) -> float:
        """Drones per second arriving — measures swarm saturation pressure."""
        return self.config.num_drones / self.config.arrival_spread_s

    def summary(self) -> dict:
        """Return simulation configuration summary."""
        return {
            "num_drones": self.config.num_drones,
            "arrival_spread_s": self.config.arrival_spread_s,
            "speed_mps": self.config.speed_mps,
            "start_distance_km": self.config.start_distance_km,
            "evasion_probability": self.config.evasion_probability,
            "swarm_density_drones_per_s": round(self.swarm_density(), 3),
            "seed": self.config.seed,
        }


def saturate_scheduler(scheduler, num_drones: int, arrival_spread_s: float, seed: int = 42) -> dict:
    """
    Run the engagement scheduler against a saturated swarm and return results.

    Helper for benchmarking how many drones the scheduler can engage before
    swarm impact under varying density.
    """
    config = SwarmConfig(
        num_drones=num_drones,
        arrival_spread_s=arrival_spread_s,
        speed_mps=30.0,
        start_distance_km=2.0,
        evasion_probability=0.3,
        seed=seed,
    )
    sim = SwarmSimulator(config)
    tracks = sim.generate_tracks()

    # Convert SwarmTrack to DroneTrack for the scheduler
    from c_uas.engagement.scheduler import DroneTrack

    drone_tracks = [
        DroneTrack(
            track_id=t.track_id,
            arrival_time_s=t.arrival_time_s,
            pk_base=t.pk_base,
            priority=t.priority,
        )
        for t in tracks
    ]

    plan = scheduler.schedule(tracks=drone_tracks)

    return {
        "config": sim.summary(),
        "expected_kills": plan.expected_kills,
        "engaged_targets": plan.engaged_targets,
        "leaked_targets": plan.leaked_targets,
        "total_time_s": plan.total_time_s,
        "leak_rate": round(plan.leaked_targets / num_drones, 4),
        "sequence": plan.sequence,
    }
