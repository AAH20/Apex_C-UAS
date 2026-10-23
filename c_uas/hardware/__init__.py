"""
C-UAS Hardware Abstraction Layer.

Defensive-only sensor abstraction (RF/SDR, radar, camera) with deterministic
simulation mode and multi-sensor track fusion. No live SDR integration, no
weapons-employment effector, no facial recognition, no weapon targeting.

State persists under ~/.c-uas-platform/hardware/ (outside the repo).
"""

from .camera_adapter import CameraAdapter
from .radar_adapter import RadarAdapter
from .sdr_adapter import SDRAdapter
from .sensor_fusion import SensorFusion
from .sensor_interface import (
    FUSION_NAMESPACE,
    Detection,
    HardwareCapability,
    RadarTrack,
    SensorInterface,
    SensorStatus,
    Signal,
    Track,
    distance_m,
    track_distance_m,
)

__all__ = [
    "CameraAdapter",
    "Detection",
    "FUSION_NAMESPACE",
    "HardwareCapability",
    "RadarAdapter",
    "RadarTrack",
    "SensorFusion",
    "SensorInterface",
    "SensorStatus",
    "SDRAdapter",
    "Signal",
    "Track",
    "distance_m",
    "track_distance_m",
]

__version__ = "0.1.0"
