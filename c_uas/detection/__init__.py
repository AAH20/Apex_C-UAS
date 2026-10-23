"""RF detection and GNSS spoofing sub-package."""

from .controller_locator import (
    ControllerLocationEstimate,
    ControllerLocator,
    Detection,
    SensorSite,
    bearing_deg,
    haversine_km,
)
from .mavlink_vulns import (
    MAVLINK_VULNERABILITIES,
    MavlinkVulnerability,
    MavlinkVulnerabilityDatabase,
)
from .rf_classifier import RFSignalClassifier
from .spoof_detector import GNSSMeasurement, GNSSSpoofDetector

__all__ = [
    "RFSignalClassifier",
    "GNSSSpoofDetector",
    "GNSSMeasurement",
    "MavlinkVulnerability",
    "MavlinkVulnerabilityDatabase",
    "MAVLINK_VULNERABILITIES",
    "SensorSite",
    "Detection",
    "ControllerLocationEstimate",
    "ControllerLocator",
    "haversine_km",
    "bearing_deg",
]
