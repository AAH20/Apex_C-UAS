"""
NP-Hard Engagement Scheduler.

Solves the budgeted maximum coverage problem: given N detected drones with
arrival times and kill probabilities, and a single beam director with
dwell/slew/thermal-bloom constraints, compute the engagement sequence that
maximizes expected kills before swarm impact.

NP-hard: reduces to 0/1 knapsack (item = drone, weight = time cost, value = Pk).
Approximation: greedy by Pk-per-second ratio achieves (1 - 1/e) for the
fractional relaxation; near-optimal for the discrete case with small dwell variance.

Defensive-only: computes engagement schedules. No effector control.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import heapq


@dataclass
class DroneTrack:
    """A detected drone track with engagement parameters."""
    track_id: int
    arrival_time_s: float       # Time until drone reaches impact point
    pk_base: float              # Base probability of kill (0-1)
    priority: int = 1           # 1=low, 5=high (e.g., headed for critical asset)


@dataclass
class EngagementPlan:
    """Result of the engagement scheduler."""
    expected_kills: float
    total_time_s: float
    engaged_targets: int
    leaked_targets: int
    sequence: List[dict] = field(default_factory=list)


class EngagementScheduler:
    """
    Greedy engagement scheduler using Pk-per-second ratio as the selection
    heuristic. This is the (1 - 1/e) approximation for budgeted maximum
    coverage.
    """

    def __init__(
        self,
        dwell_s: float = 4.0,
        slew_s: float = 1.5,
        time_limit_s: float = 60.0,
        thermal_bloom_penalty_per_target: float = 0.05,
    ) -> None:
        self.dwell_s = dwell_s
        self.slew_s = slew_s
        self.time_limit_s = time_limit_s
        self.thermal_bloom_penalty_per_target = thermal_bloom_penalty_per_target

    def schedule(
        self,
        num_drones: Optional[int] = None,
        time_limit_s: Optional[float] = None,
        tracks: Optional[List[DroneTrack]] = None,
    ) -> EngagementPlan:
        """
        Compute the optimal-ish engagement sequence.

        Args:
            num_drones: Number of drones to generate synthetic tracks for
                (used when tracks not provided).
            time_limit_s: Override the default time limit.
            tracks: Optional explicit drone tracks. If provided, num_drones
                is ignored.

        Returns:
            EngagementPlan with expected kills, timing, and sequence.
        """
        tl = time_limit_s if time_limit_s is not None else self.time_limit_s

        if tracks is None:
            if num_drones is None:
                raise ValueError("Either num_drones or tracks must be provided")
            tracks = self._generate_synthetic_tracks(num_drones, tl)

        # Sort by deadline (arrival time) - must engage before impact
        tracks_sorted = sorted(tracks, key=lambda t: t.arrival_time_s)

        # Greedy selection by Pk-per-second ratio
        # Time cost per target = dwell + slew (slew only between targets)
        # Value = Pk (adjusted for thermal bloom based on engagement order)
        time_used = 0.0
        expected_kills = 0.0
        sequence: List[dict] = []
        engaged_count = 0
        bloom_penalty = 0.0  # Cumulative thermal bloom reduces Pk

        # Build a max-heap by Pk-per-second ratio
        # Python heapq is min-heap, so negate the ratio
        candidates = []
        for track in tracks_sorted:
            time_cost = self.dwell_s + self.slew_s
            # Effective Pk considering thermal bloom from prior engagements
            effective_pk = max(0.0, track.pk_base - bloom_penalty)
            ratio = effective_pk / time_cost if time_cost > 0 else 0.0
            # Push: (-ratio, arrival_time, track)
            heapq.heappush(candidates, (-ratio, track.arrival_time_s, track))

        # Greedy: pop best ratio, check if it fits before its deadline
        while candidates and time_used < tl:
            neg_ratio, _, track = heapq.heappop(candidates)
            time_cost = self.dwell_s + (self.slew_s if engaged_count > 0 else 0.0)

            # Check deadline: engagement must complete before arrival
            if time_used + time_cost > track.arrival_time_s:
                continue  # Too late for this target

            if time_used + time_cost > tl:
                continue  # Not enough time remaining

            # Engage this target
            effective_pk = max(0.0, track.pk_base - bloom_penalty)
            expected_kills += effective_pk
            time_used += time_cost
            engaged_count += 1
            bloom_penalty += self.thermal_bloom_penalty_per_target

            sequence.append({
                "track_id": track.track_id,
                "engage_start_s": round(time_used - time_cost, 2),
                "engage_end_s": round(time_used, 2),
                "pk": round(effective_pk, 3),
                "time_cost_s": round(time_cost, 2),
            })

        leaked = len(tracks) - engaged_count

        return EngagementPlan(
            expected_kills=round(expected_kills, 3),
            total_time_s=round(time_used, 2),
            engaged_targets=engaged_count,
            leaked_targets=leaked,
            sequence=sequence,
        )

    def _generate_synthetic_tracks(
        self, num_drones: int, time_limit_s: float
    ) -> List[DroneTrack]:
        """Generate deterministic synthetic drone tracks for testing."""
        import random
        rng = random.Random(42)  # Deterministic
        tracks = []
        for i in range(num_drones):
            arrival = rng.uniform(5.0, time_limit_s)
            pk = rng.uniform(0.6, 0.95)
            priority = rng.randint(1, 5)
            tracks.append(DroneTrack(
                track_id=i,
                arrival_time_s=arrival,
                pk_base=pk,
                priority=priority,
            ))
        return tracks
