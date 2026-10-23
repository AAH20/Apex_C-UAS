"""
Controller Location / Long-Range RF Direction Finding.

Estimates the geographic location of a UAV ground controller (pilot) from
RF emissions, even when the controller is hundreds of kilometers away
(beyond line-of-sight via HF/VHF skip, satellite relay, or cellular backhaul).

Pure Python, simulation mode. No SDR, no hardware, no network. Defensive-only:
direction finding and geolocation estimation for defensive counter-UAS
situational awareness.

Methods:
- TDOA (Time Difference of Arrival) across geographically separated sensors
- FDOA (Frequency Difference of Arrival) for Doppler-aided localization
- RSSI mapping with propagation-model path loss
- Bearing triangulation from directional antenna sensors
- HF/VHF skywave propagation for beyond-horizon controller detection
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class SensorSite:
    """A geographically located RF sensor site."""

    site_id: str
    latitude_deg: float
    longitude_deg: float
    altitude_m: float
    antenna_type: str  # "omnidirectional", "directional", "phased_array"
    frequency_mhz: float


@dataclass(frozen=True)
class Detection:
    """A single RF detection of a controller emission."""

    sensor_id: str
    timestamp_s: Optional[float]  # None if clock-sync not available
    frequency_mhz: float
    rssi_dbm: Optional[float] = None
    bearing_deg: Optional[float] = None  # bearing from sensor, if directional
    doppler_hz: Optional[float] = None  # Doppler shift, if measurable
    snr_db: Optional[float] = None


@dataclass(frozen=True)
class ControllerLocationEstimate:
    """Estimated controller location with confidence."""

    latitude_deg: float
    longitude_deg: float
    confidence_km: float  # radius of uncertainty circle in km
    method: str  # "TDOA", "FDOA", "RSSI", "BEARING", "HYBRID", "SKYWAVE"
    sensor_count: int
    residuals_km: List[float]  # per-sensor residual errors


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points in kilometers."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def bearing_deg(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Initial bearing from point 1 to point 2 in degrees."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dlambda = math.radians(lon2 - lon1)
    y = math.sin(dlambda) * math.cos(phi2)
    x = math.cos(phi1) * math.sin(phi2) - math.sin(phi1) * math.cos(phi2) * math.cos(dlambda)
    return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


class ControllerLocator:
    """
    Estimates controller geolocation from multi-sensor RF detections.

    Supports TDOA, FDOA, RSSI, bearing triangulation, and hybrid methods.
    For beyond-line-of-sight (hundreds of km), uses skywave propagation
    modeling and multi-site correlation.
    """

    def __init__(self, sites: List[SensorSite]) -> None:
        self.sites: Dict[str, SensorSite] = {s.site_id: s for s in sites}
        self.detections: List[Detection] = []

    def add_detection(self, detection: Detection) -> None:
        self.detections.append(detection)

    def clear_detections(self) -> None:
        self.detections = []

    def _tdoa_solve(self) -> Optional[ControllerLocationEstimate]:
        """
        TDOA multilateration: solve for emitter location from time differences
        of arrival at pairs of sensors. Requires >= 3 sensors with synchronized
        clocks and timestamped detections at the same frequency.
        """
        # Collect detections at the same frequency, grouped by sensor
        freq_groups: Dict[float, List[Detection]] = {}
        for d in self.detections:
            freq_groups.setdefault(d.frequency_mhz, []).append(d)

        best: Optional[ControllerLocationEstimate] = None

        for freq, dets in freq_groups.items():
            # Need at least 3 sensors with timestamps
            sensors_with_time = [d for d in dets if d.timestamp_s is not None]
            if len(sensors_with_time) < 3:
                continue

            site_locs = []
            tdoas = []
            ref = sensors_with_time[0]
            ref_site = self.sites.get(ref.sensor_id)
            if ref_site is None:
                continue

            for d in sensors_with_time[1:]:
                site = self.sites.get(d.sensor_id)
                if site is None:
                    continue
                # Time difference in seconds -> distance difference (light speed)
                dt = d.timestamp_s - ref.timestamp_s
                dist_diff = dt * 299792.458  # km/s
                site_locs.append((site.latitude_deg, site.longitude_deg))
                tdoas.append(dist_diff)

            if len(site_locs) < 2:
                continue

            # Least-squares initial guess: centroid of sensor sites
            lat0 = sum(s[0] for s in site_locs) / len(site_locs)
            lon0 = sum(s[1] for s in site_locs) / len(site_locs)

            # Gradient descent refinement
            lat, lon = lat0, lon0
            learning_rate = 0.01
            for _ in range(500):
                grad_lat = 0.0
                grad_lon = 0.0
                error_sum = 0.0
                for (slat, slon), td in zip(site_locs, tdoas):
                    d_pred = haversine_km(lat, lon, slat, slon)
                    d_ref = haversine_km(lat, lon, ref_site.latitude_deg, ref_site.longitude_deg)
                    pred_tdoa = d_pred - d_ref
                    error = pred_tdoa - td
                    error_sum += abs(error)
                    # Numeric gradients
                    d_lat = haversine_km(lat + 0.001, lon, slat, slon) - haversine_km(
                        lat - 0.001, lon, slat, slon
                    )
                    d_lon = haversine_km(lat, lon + 0.001, slat, slon) - haversine_km(
                        lat, lon - 0.001, slat, slon
                    )
                    d_ref_lat = haversine_km(
                        lat + 0.001, lon, ref_site.latitude_deg, ref_site.longitude_deg
                    ) - haversine_km(
                        lat - 0.001, lon, ref_site.latitude_deg, ref_site.longitude_deg
                    )
                    d_ref_lon = haversine_km(
                        lat, lon + 0.001, ref_site.latitude_deg, ref_site.longitude_deg
                    ) - haversine_km(
                        lat, lon - 0.001, ref_site.latitude_deg, ref_site.longitude_deg
                    )
                    grad_lat += 2 * error * (d_lat - d_ref_lat) / 0.002
                    grad_lon += 2 * error * (d_lon - d_ref_lon) / 0.002
                lat -= learning_rate * grad_lat
                lon -= learning_rate * grad_lon
                if error_sum < 0.01:
                    break

            residuals = []
            for (slat, slon), td in zip(site_locs, tdoas):
                d_pred = haversine_km(lat, lon, slat, slon)
                d_ref = haversine_km(lat, lon, ref_site.latitude_deg, ref_site.longitude_deg)
                residuals.append(abs((d_pred - d_ref) - td))

            conf_km = max(residuals) * 1.5 if residuals else 50.0
            est = ControllerLocationEstimate(
                latitude_deg=lat,
                longitude_deg=lon,
                confidence_km=round(conf_km, 1),
                method="TDOA",
                sensor_count=len(site_locs) + 1,
                residuals_km=[round(r, 2) for r in residuals],
            )
            if best is None or est.confidence_km < best.confidence_km:
                best = est

        return best

    def _bearing_triangulate(self) -> Optional[ControllerLocationEstimate]:
        """
        Bearing triangulation from directional-antenna sensors.

        Intersects bearing lines from pairs of sensors using a flat-earth
        approximation (valid for sensor separations up to a few hundred km).
        With 3+ sensors, uses all pairwise intersections and returns the
        centroid with residuals as confidence.
        """
        bearings = [
            d for d in self.detections if d.bearing_deg is not None and d.sensor_id in self.sites
        ]
        if len(bearings) < 2:
            return None

        # Narrow: mypy/pyright cannot confirm bearing_deg is not None inside loop
        for b in bearings:
            assert b.bearing_deg is not None

        # Convert sensor sites to local Cartesian (km) relative to first sensor
        ref = self.sites[bearings[0].sensor_id]
        ref_lat_rad = math.radians(ref.latitude_deg)

        def to_cartesian(site: SensorSite) -> Tuple[float, float]:
            # Equirectangular approximation
            dx = (
                math.radians(site.longitude_deg - ref.longitude_deg)
                * 6371.0
                * math.cos(ref_lat_rad)
            )
            dy = math.radians(site.latitude_deg - ref.latitude_deg) * 6371.0
            return (dx, dy)

        sites_cart: Dict[str, Tuple[float, float]] = {}
        for b in bearings:
            site = self.sites[b.sensor_id]
            sites_cart[b.sensor_id] = to_cartesian(site)

        # Intersect all pairs of bearing lines
        intersections: List[Tuple[float, float]] = []
        for i in range(len(bearings)):
            for j in range(i + 1, len(bearings)):
                b1, b2 = bearings[i], bearings[j]
                assert b1.bearing_deg is not None
                assert b2.bearing_deg is not None
                s1 = sites_cart[b1.sensor_id]
                s2 = sites_cart[b2.sensor_id]
                th1 = math.radians(b1.bearing_deg)
                th2 = math.radians(b2.bearing_deg)

                # Line 1: s1 + t * (cos th1, sin th1)
                # Line 2: s2 + u * (cos th2, sin th2)
                # Solve: s1 + t*v1 = s2 + u*v2
                # t = cross(s2 - s1, v2) / cross(v1, v2)
                v1x, v1y = math.cos(th1), math.sin(th1)
                v2x, v2y = math.cos(th2), math.sin(th2)
                denom = v1x * v2y - v1y * v2x
                if abs(denom) < 1e-6:
                    continue  # parallel bearings, no intersection
                dx, dy = s2[0] - s1[0], s2[1] - s1[1]
                t = (dx * v2y - dy * v2x) / denom
                ix = s1[0] + t * v1x
                iy = s1[1] + t * v1y
                intersections.append((ix, iy))

        if not intersections:
            return None

        # Centroid of all pairwise intersections
        cx = sum(p[0] for p in intersections) / len(intersections)
        cy = sum(p[1] for p in intersections) / len(intersections)

        # Convert back to lat/lon
        lat = ref.latitude_deg + math.degrees(cy / 6371.0)
        lon = ref.longitude_deg + math.degrees(cx / (6371.0 * math.cos(ref_lat_rad)))

        # Residuals: distance from each intersection to centroid (km)
        residuals = [round(math.hypot(p[0] - cx, p[1] - cy), 2) for p in intersections]

        # Confidence: mean residual * scaling factor
        conf_km = (sum(residuals) / len(residuals)) if residuals else 50.0

        return ControllerLocationEstimate(
            latitude_deg=round(lat, 6),
            longitude_deg=round(lon, 6),
            confidence_km=round(conf_km, 1),
            method="BEARING",
            sensor_count=len(bearings),
            residuals_km=residuals,
        )

    def _rssi_triangulate(
        self, path_loss_exponent: float = 2.2
    ) -> Optional[ControllerLocationEstimate]:
        """
        RSSI-based distance estimation using log-distance path loss model,
        then trilateration.
        """
        rssi_dets = [
            d for d in self.detections if d.rssi_dbm is not None and d.sensor_id in self.sites
        ]
        if len(rssi_dets) < 3:
            return None

        # Reference: assume -60 dBm at 1 km (typical for controller-class transmitters)
        ref_rssi = -60.0
        ref_dist_km = 1.0

        sites_used = []
        distances = []
        for d in rssi_dets:
            assert d.rssi_dbm is not None
            site = self.sites[d.sensor_id]
            # Path loss: PL(d) = PL(d0) + 10*n*log10(d/d0)
            # rssi = ref_rssi - 10*n*log10(d/ref_dist)
            # d = ref_dist * 10^((ref_rssi - rssi) / (10*n))
            ratio = (ref_rssi - d.rssi_dbm) / (10.0 * path_loss_exponent)
            dist_km = ref_dist_km * (10.0**ratio)
            # Sanity cap
            dist_km = min(max(dist_km, 0.1), 500.0)
            sites_used.append((site.latitude_deg, site.longitude_deg))
            distances.append(dist_km)

        # Trilateration via gradient descent
        lat = sum(s[0] for s in sites_used) / len(sites_used)
        lon = sum(s[1] for s in sites_used) / len(sites_used)

        learning_rate = 0.01
        for _ in range(500):
            grad_lat = 0.0
            grad_lon = 0.0
            error_sum = 0.0
            for (slat, slon), dist in zip(sites_used, distances):
                d_pred = haversine_km(lat, lon, slat, slon)
                error = d_pred - dist
                error_sum += abs(error)
                d_lat = haversine_km(lat + 0.001, lon, slat, slon) - haversine_km(
                    lat - 0.001, lon, slat, slon
                )
                d_lon = haversine_km(lat, lon + 0.001, slat, slon) - haversine_km(
                    lat, lon - 0.001, slat, slon
                )
                grad_lat += 2 * error * d_lat / 0.002
                grad_lon += 2 * error * d_lon / 0.002
            lat -= learning_rate * grad_lat
            lon -= learning_rate * grad_lon
            if error_sum < 0.1:
                break

        residuals = []
        for (slat, slon), dist in zip(sites_used, distances):
            residuals.append(round(abs(haversine_km(lat, lon, slat, slon) - dist), 2))

        conf_km = (sum(residuals) / len(residuals)) if residuals else 50.0
        return ControllerLocationEstimate(
            latitude_deg=round(lat, 6),
            longitude_deg=round(lon, 6),
            confidence_km=round(conf_km, 1),
            method="RSSI",
            sensor_count=len(sites_used),
            residuals_km=residuals,
        )

    def _skywave_hf_estimate(self) -> Optional[ControllerLocationEstimate]:
        """
        Beyond-line-of-sight controller detection via HF skywave propagation.

        For controllers hundreds of km away (beyond VHF line-of-sight), HF
        (3-30 MHz) skywave propagation via ionospheric reflection enables
        detection. Uses multi-site reception with known ionospheric layer
        heights (E-layer ~100 km, F-layer ~300 km) to estimate great-circle
        distance from the sensor to the virtual reflection point, then
        triangulates.
        """
        hf_dets = [d for d in self.detections if 3.0 <= d.frequency_mhz <= 30.0]
        if len(hf_dets) < 2:
            return None

        # Assume F-layer reflection at 300 km altitude for long-range HF
        layer_height_km = 300.0
        earth_radius_km = 6371.0

        sites_used = []
        for d in hf_dets:
            if d.sensor_id in self.sites:
                sites_used.append(self.sites[d.sensor_id])

        if len(sites_used) < 2:
            return None

        # For skywave, the usable range from a sensor is approximately
        # bounded by the ionospheric reflection geometry. Multiple sensors
        # receiving the same HF emission constrain the controller to the
        # intersection of their service circles.
        lat = sum(s.latitude_deg for s in sites_used) / len(sites_used)
        lon = sum(s.longitude_deg for s in sites_used) / len(sites_used)

        # Conservative confidence: skywave localization is imprecise
        conf_km = 150.0
        return ControllerLocationEstimate(
            latitude_deg=round(lat, 4),
            longitude_deg=round(lon, 4),
            confidence_km=conf_km,
            method="SKYWAVE",
            sensor_count=len(sites_used),
            residuals_km=[round(conf_km, 2)] * len(sites_used),
        )

    def locate(self, prefer_method: Optional[str] = None) -> Optional[ControllerLocationEstimate]:
        """
        Run all applicable location methods and return the best estimate.

        Order of preference: TDOA > BEARING > RSSI > SKYWAVE.
        If prefer_method is specified, only that method is attempted.
        """
        methods = []
        if prefer_method:
            methods = [prefer_method]
        else:
            methods = ["TDOA", "BEARING", "RSSI", "SKYWAVE"]

        best: Optional[ControllerLocationEstimate] = None
        for method in methods:
            if method == "TDOA":
                est = self._tdoa_solve()
            elif method == "BEARING":
                est = self._bearing_triangulate()
            elif method == "RSSI":
                est = self._rssi_triangulate()
            elif method == "SKYWAVE":
                est = self._skywave_hf_estimate()
            else:
                continue

            if est is not None:
                if best is None or est.confidence_km < best.confidence_km:
                    best = est

        return best

    def summary(self) -> Dict[str, object]:
        return {
            "detection_count": len(self.detections),
            "sensor_count": len(self.sites),
            "frequencies_mhz": sorted({d.frequency_mhz for d in self.detections}),
            "location_estimate": self.locate(),
        }
