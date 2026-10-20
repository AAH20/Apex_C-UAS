"""RF detection and GNSS spoofing sub-package."""

from .rf_classifier import RFSignalClassifier
from .spoof_detector import GNSSSpoofDetector, GNSSMeasurement
from .mavlink_vulns import (
    MavlinkVulnerability,
    MavlinkVulnerabilityDatabase,
    MAVLINK_VULNERABILITIES,
)
from .controller_locator import (
    SensorSite,
    Detection,
    ControllerLocationEstimate,
    ControllerLocator,
    haversine_km,
    bearing_deg,
)

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
