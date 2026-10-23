"""
Multi-sensor track fusion.

Fuses raw detections from SDR (rf), radar, and camera (visual) sensors into
unified drone tracks. Deduplicates by spatial proximity and time: detections
within proximity_m meters and time_window_s seconds of an existing cluster
are merged into one track using a confidence-weighted centroid.

Track IDs are content-addressed (uuid5 over the sorted member detection IDs)
so the same input detections always produce the same tracks. Deterministic
given the seed; no randomness affects fusion output.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from typing import List, Optional

from .sensor_interface import (
    FUSION_NAMESPACE,
    Detection,
    Track,
    track_distance_m,
)


@dataclass(frozen=True)
class FusionConfig:
    """Configuration for the SensorFusion fuser."""

    proximity_m: float = 50.0  # max distance to merge detections into one track
    time_window_s: float = 1.0  # max time spread within a cluster
    min_confidence: float = 0.1  # drop detections below this confidence


class SensorFusion:
    """Fuses multi-sensor detections into unified drone tracks."""

    def __init__(
        self,
        proximity_m: float = 50.0,
        time_window_s: float = 1.0,
        min_confidence: float = 0.1,
        seed: int = 42,
    ) -> None:
        self.config = FusionConfig(
            proximity_m=proximity_m,
            time_window_s=time_window_s,
            min_confidence=min_confidence,
        )
        self.seed = seed

    def fuse(self, detections: List[Detection]) -> List[Track]:
        """Fuse detections into tracks.

        Greedy single-pass clustering in timestamp order. A detection joins
        an open cluster when it is within proximity_m of the cluster's
        confidence-weighted centroid AND within time_window_s of the
        cluster's first detection; otherwise it opens a new cluster.

        Each cluster becomes one Track: weighted centroid position, average
        confidence (capped at 1.0), union of sensors and sources, and a
        deterministic track ID.
        """

        ordered = sorted(
            (d for d in detections if d.confidence >= self.config.min_confidence),
            key=lambda d: (d.timestamp, d.detection_id),
        )

        clusters: List[dict] = []
        for det in ordered:
            placed = False
            for cluster in clusters:
                if self._matches_cluster(det, cluster):
                    cluster["members"].append(det)
                    cluster["centroid"] = self._weighted_centroid(cluster["members"])
                    placed = True
                    break
            if not placed:
                clusters.append(
                    {
                        "t0": det.timestamp,
                        "members": [det],
                        "centroid": (det.x_m, det.y_m, det.z_m),
                    }
                )

        tracks: List[Track] = []
        for cluster in clusters:
            members = cluster["members"]
            cx, cy, cz = cluster["centroid"]
            total_conf = sum(m.confidence for m in members)
            count = len(members)
            confidence = min(1.0, total_conf / count) if count else 0.0
            ids = "+".join(sorted(m.detection_id for m in members))
            track_id = f"track--{uuid.uuid5(FUSION_NAMESPACE, ids)}"
            sensors = sorted({m.sensor_id for m in members})
            sources = sorted({m.source for m in members})
            # Velocity requires multi-frame history; single-frame fusion reports zero.
            tracks.append(
                Track(
                    track_id=track_id,
                    x_m=round(cx, 2),
                    y_m=round(cy, 2),
                    z_m=round(cz, 2),
                    vx_mps=0.0,
                    vy_mps=0.0,
                    vz_mps=0.0,
                    timestamp=members[-1].timestamp,
                    confidence=round(confidence, 3),
                    sensors=sensors,
                    sources=sources,
                )
            )
        return tracks

    def fuse_with_history(
        self,
        detections: List[Detection],
        previous_tracks: List[Track],
        max_assoc_distance_m: float = 100.0,
    ) -> List[Track]:
        """Fuse detections and associate with previous tracks by proximity.

        New detections are clustered as in fuse(). Each cluster is then
        associated with the nearest previous track within
        max_assoc_distance_m; associated tracks keep the previous track ID
        (continuity), unassociated clusters get new IDs.
        """

        new_tracks = self.fuse(detections)
        associations: List[Track] = []
        used_prev: List[int] = []
        for track in new_tracks:
            best_idx: Optional[int] = None
            best_dist = float("inf")
            for idx, prev in enumerate(previous_tracks):
                if idx in used_prev:
                    continue
                dist = track_distance_m(track, prev)
                if dist < best_dist:
                    best_dist = dist
                    best_idx = idx
            if best_idx is not None and best_dist <= max_assoc_distance_m:
                used_prev.append(best_idx)
                associations.append(
                    Track(
                        track_id=previous_tracks[best_idx].track_id,
                        x_m=track.x_m,
                        y_m=track.y_m,
                        z_m=track.z_m,
                        vx_mps=track.vx_mps,
                        vy_mps=track.vy_mps,
                        vz_mps=track.vz_mps,
                        timestamp=track.timestamp,
                        confidence=track.confidence,
                        sensors=list(
                            dict.fromkeys(previous_tracks[best_idx].sensors + track.sensors)
                        ),
                        sources=list(
                            dict.fromkeys(previous_tracks[best_idx].sources + track.sources)
                        ),
                    )
                )
            else:
                associations.append(track)
        return associations

    # ---- internal helpers ---------------------------------------------

    def _matches_cluster(self, det: Detection, cluster: dict) -> bool:
        cx, cy, cz = cluster["centroid"]
        dist = math.sqrt((det.x_m - cx) ** 2 + (det.y_m - cy) ** 2 + (det.z_m - cz) ** 2)
        time_ok = abs(det.timestamp - cluster["t0"]) <= self.config.time_window_s
        return dist <= self.config.proximity_m and time_ok

    @staticmethod
    def _weighted_centroid(members: List[Detection]):
        total = sum(m.confidence for m in members) or 1.0
        cx = sum(m.x_m * m.confidence for m in members) / total
        cy = sum(m.y_m * m.confidence for m in members) / total
        cz = sum(m.z_m * m.confidence for m in members) / total
        return cx, cy, cz
