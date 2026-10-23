"""
C-UAS Edge Computing Deployment.

Lightweight edge nodes for sensor deployment at C-UAS sites: local detection
and tracking without cloud dependency, edge-to-cloud synchronization when
connectivity is restored, and on-node health monitoring.

Defensive only: detection, tracking, and forensic-grade event queuing. No
weapons-employment effector, no live SDR integration.

State persists under ~/.c-uas-platform/edge/ (outside the repo).
"""

from .config import EdgeConfig
from .health import EdgeHealth, HealthReport
from .node import DeploymentReport, DetectionResult, EdgeNode
from .state import EDGE_ROOT, load_json, node_dir, save_json
from .sync import EdgeSync, QueuedDetection, SyncReport

__all__ = [
    "DeploymentReport",
    "DetectionResult",
    "EdgeConfig",
    "EdgeHealth",
    "EdgeNode",
    "EdgeSync",
    "HealthReport",
    "QueuedDetection",
    "SyncReport",
    "EDGE_ROOT",
    "load_json",
    "node_dir",
    "save_json",
]

__version__ = "0.1.0"
