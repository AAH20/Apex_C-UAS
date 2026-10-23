"""
Expanded Directed-Energy Beam Modeling.

Adds atmospheric attenuation (ITU-R P.676 / P.835 models), multi-wavelength
support, adaptive optics compensation, and real-world DEW system comparisons.
Modeling only — no hardware control, no weapons-employment effector.

All physics formulas are standard open literature. No classified data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Atmospheric attenuation models (open literature, ITU-R P.676 / P.835)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AtmosphericConditions:
    """Atmospheric state for attenuation calculations."""

    temperature_c: float = 15.0  # Ambient temperature (C)
    pressure_hpa: float = 1013.25  # Pressure (hPa)
    humidity_percent: float = 50.0  # Relative humidity (%)
    rainfall_mm_hr: float = 0.0  # Rain rate (mm/hr)
    aerosol_visibility_km: float = 20.0  # Visibility (km)


def oxygen_attenuation_db_km(
    freq_ghz: float,
    temp_c: float,
    pressure_hpa: float,
) -> float:
    """
    Specific attenuation due to atmospheric oxygen (dB/km).

    Simplified ITU-R P.676 model. Valid 1-1000 GHz.
    """
    # Rough approximation; real P.676 has many absorption lines.
    # For C-UAS relevant wavelengths (optical/laser), this is not used;
    # included for completeness for RF/microwave DEW.
    t = temp_c + 273.15
    p = pressure_hpa
    # Simplified: oxygen absorption ~0.01-0.1 dB/km in clear air at RF
    return 0.05 * (p / 1013.25) * (288.15 / t)


def water_vapor_attenuation_db_km(
    freq_ghz: float,
    temp_c: float,
    pressure_hpa: float,
    humidity: float,
) -> float:
    """
    Specific attenuation due to water vapor (dB/km).

    Simplified ITU-R P.676 model.
    """
    # Simplified approximation
    return 0.02 * humidity * (pressure_hpa / 1013.25)


def rain_attenuation_db_km(
    freq_ghz: float,
    rain_rate_mm_hr: float,
) -> float:
    """
    Specific attenuation due to rain (dB/km).

    ITU-R P.838 simplified model: gamma_R = k * R^alpha.
    Coefficients are frequency-dependent; using a representative
    optical-wavelength scaling for illustration.
    """
    if rain_rate_mm_hr <= 0:
        return 0.0
    # Simplified: rain attenuation grows with frequency and rain rate
    k = 0.0001 * (freq_ghz**0.5)  # representative
    alpha = 0.7
    return k * (rain_rate_mm_hr**alpha)


def aerosol_attenuation_db_km(
    wavelength_nm: float,
    visibility_km: float,
) -> float:
    """
    Aerosol attenuation (dB/km) using Kruse model.

    Applicable to optical/laser wavelengths (visible to near-IR).
    """
    if visibility_km <= 0:
        return float("inf")
    # Kruse model: beta = 3.912 / V * (lambda/550)^(-q)
    # q depends on visibility; using q=1.3 for good visibility
    q = 1.3
    beta = (3.912 / visibility_km) * (wavelength_nm / 550.0) ** (-q)
    # Convert extinction coefficient (1/km) to dB/km: 1 dB/km = 0.2303 * beta
    return beta * 4.343  # 10 / ln(10) ≈ 4.343


def total_attenuation_db_km(
    wavelength_nm: Optional[float] = None,
    freq_ghz: Optional[float] = None,
    conditions: Optional[AtmosphericConditions] = None,
) -> float:
    """
    Total specific attenuation (dB/km) for given wavelength or frequency.

    For laser DEW (optical wavelengths), uses aerosol + rain.
    For RF/microwave DEW, uses oxygen + water vapor + rain.
    """
    c = conditions or AtmosphericConditions()
    total = 0.0

    if wavelength_nm is not None:
        # Optical / laser path
        total += aerosol_attenuation_db_km(wavelength_nm, c.aerosol_visibility_km)
        if c.rainfall_mm_hr > 0:
            # Approximate optical rain attenuation
            total += 0.1 * c.rainfall_mm_hr  # rough dB/km per mm/hr

    if freq_ghz is not None:
        # RF / microwave path
        total += oxygen_attenuation_db_km(freq_ghz, c.temperature_c, c.pressure_hpa)
        total += water_vapor_attenuation_db_km(
            freq_ghz, c.temperature_c, c.pressure_hpa, c.humidity_percent
        )
        if c.rainfall_mm_hr > 0:
            total += rain_attenuation_db_km(freq_ghz, c.rainfall_mm_hr)

    return max(0.0, total)


# ---------------------------------------------------------------------------
# Multi-wavelength laser models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LaserSpec:
    """Laser system specification."""

    name: str
    wavelength_nm: float  # Laser wavelength (nm)
    power_kw: float  # Output power (kW)
    m2: float  # Beam quality (M^2, 1.0 = diffraction limited)
    jitter_urad: float  # Pointing jitter (microradians)
    aperture_cm: float  # Transmit aperture diameter (cm)
    wall_plug_efficiency: float = 0.30  # Efficiency (0-1)
    adaptive_optics: bool = False  # Whether AO compensates turbulence


# Representative laser systems (public specs)
LASER_SPECS: dict[str, LaserSpec] = {
    "fiber_50kw": LaserSpec(
        name="50 kW Fiber Laser",
        wavelength_nm=1070.0,
        power_kw=50.0,
        m2=1.2,
        jitter_urad=5.0,
        aperture_cm=20.0,
    ),
    "fiber_100kw": LaserSpec(
        name="100 kW Fiber Laser",
        wavelength_nm=1070.0,
        power_kw=100.0,
        m2=1.5,
        jitter_urad=7.0,
        aperture_cm=30.0,
    ),
    "solid_state_150kw": LaserSpec(
        name="150 kW Solid-State Laser",
        wavelength_nm=1064.0,
        power_kw=150.0,
        m2=2.0,
        jitter_urad=10.0,
        aperture_cm=40.0,
    ),
    "chemical_100kw": LaserSpec(
        name="100 kW Chemical Laser (class)",
        wavelength_nm=3080.0,
        power_kw=100.0,
        m2=3.0,
        jitter_urad=15.0,
        aperture_cm=50.0,
    ),
}


def diffraction_limit_spot_cm(
    wavelength_nm: float,
    range_m: float,
    aperture_cm: float,
    m2: float = 1.0,
) -> float:
    """
    Diffraction-limited spot diameter at range (cm).

    spot = 2.44 * lambda * range / aperture * M^2
    """
    lam_m = wavelength_nm * 1e-9
    ap_m = aperture_cm / 100.0
    spot_m = 2.44 * lam_m * range_m / ap_m * m2
    return spot_m * 100.0  # cm


def jitter_spot_cm(
    jitter_urad: float,
    range_m: float,
) -> float:
    """
    Spot diameter contribution from pointing jitter (cm).

    spot = 2 * jitter * range
    """
    return 2.0 * jitter_urad * 1e-6 * range_m * 100.0  # cm


def effective_spot_cm(
    spec: LaserSpec,
    range_m: float,
    conditions: Optional[AtmosphericConditions] = None,
    use_adaptive_optics: bool = False,
) -> float:
    """
    Effective spot diameter at range combining diffraction, jitter,
    atmospheric turbulence, and attenuation.

    Returns spot diameter in cm.
    """
    c = conditions or AtmosphericConditions()

    # Diffraction limit
    diff_cm = diffraction_limit_spot_cm(spec.wavelength_nm, range_m, spec.aperture_cm, spec.m2)

    # Jitter contribution
    jit_cm = jitter_spot_cm(spec.jitter_urad, range_m)

    # Turbulence (Fried parameter approximation, simplified)
    # r0 ~ 10 cm at good sites; turbulence blur angle ~ lambda / r0 (radians)
    # spot = angle * range
    r0_m = 0.10 * (c.aerosol_visibility_km / 20.0) ** 0.6  # Fried parameter in meters
    lam_m = spec.wavelength_nm * 1e-9  # wavelength in meters
    turb_angle_rad = lam_m / r0_m
    turb_cm = turb_angle_rad * range_m * 100.0  # convert m to cm

    if use_adaptive_optics and spec.adaptive_optics:
        turb_cm *= 0.2  # AO corrects ~80% of turbulence

    # RSS combination
    spot_cm = (diff_cm**2 + jit_cm**2 + turb_cm**2) ** 0.5

    # Attenuation reduces effective power but doesn't change spot size;
    # accounted separately in fluence calculation.
    return spot_cm


def fluence_on_target_j_per_cm2(
    spec: LaserSpec,
    range_m: float,
    dwell_s: float,
    conditions: Optional[AtmosphericConditions] = None,
    use_adaptive_optics: bool = False,
) -> float:
    """
    Fluence on target (J/cm^2) after atmospheric attenuation.

    Computes energy delivered per unit area at the target.
    """
    c = conditions or AtmosphericConditions()

    # Total attenuation along path
    att_db_km = total_attenuation_db_km(wavelength_nm=spec.wavelength_nm, conditions=c)
    path_km = range_m / 1000.0
    transmission = 10.0 ** (-(att_db_km * path_km) / 10.0)

    # Output energy
    energy_j = spec.power_kw * 1000.0 * dwell_s  # J
    transmitted_energy_j = energy_j * transmission

    # Spot area
    spot_cm = effective_spot_cm(spec, range_m, c, use_adaptive_optics)
    spot_radius_cm = spot_cm / 2.0
    import math

    area_cm2 = math.pi * spot_radius_cm**2

    if area_cm2 <= 0:
        return 0.0

    return transmitted_energy_j / area_cm2


def time_to_kill_with_attenuation(
    spec: LaserSpec,
    range_m: float,
    target_material: str = "aluminum",
    conditions: Optional[AtmosphericConditions] = None,
    use_adaptive_optics: bool = False,
) -> dict:
    """
    Time-to-kill with full atmospheric attenuation modeling.

    Returns dict with dwell time, fluence, transmission, spot size.
    """
    c = conditions or AtmosphericConditions()

    from c_uas.dew.time_to_kill import (
        DEFAULT_ABSORPTION,
        DEFAULT_ENERGY_KJ,
        MATERIAL_ABSORPTION,
        MATERIAL_ENERGY_KJ,
    )

    energy_kj = MATERIAL_ENERGY_KJ.get(target_material, DEFAULT_ENERGY_KJ)
    absorption = MATERIAL_ABSORPTION.get(target_material, DEFAULT_ABSORPTION)

    # Required fluence on target (J/cm^2) for mission kill
    # Assume kill threshold: energy_kj kJ absorbed over ~10 cm^2 spot
    required_fluence_j_cm2 = (energy_kj * 1000.0 * absorption) / 100.0  # J/cm^2

    # Binary search for dwell time
    lo, hi = 0.001, 300.0  # 1 ms to 5 min
    for _ in range(50):
        mid = (lo + hi) / 2.0
        fluence = fluence_on_target_j_per_cm2(spec, range_m, mid, c, use_adaptive_optics)
        if fluence >= required_fluence_j_cm2:
            hi = mid
        else:
            lo = mid

    dwell_s = hi
    actual_fluence = fluence_on_target_j_per_cm2(spec, range_m, dwell_s, c, use_adaptive_optics)
    att_db_km = total_attenuation_db_km(wavelength_nm=spec.wavelength_nm, conditions=c)
    transmission = 10.0 ** (-(att_db_km * (range_m / 1000.0)) / 10.0)
    spot_cm = effective_spot_cm(spec, range_m, c, use_adaptive_optics)

    return {
        "dwell_s": round(dwell_s, 3),
        "fluence_j_cm2": round(actual_fluence, 3),
        "required_fluence_j_cm2": round(required_fluence_j_cm2, 3),
        "transmission": round(transmission, 4),
        "attenuation_db_km": round(att_db_km, 4),
        "spot_cm": round(spot_cm, 2),
        "range_m": range_m,
        "material": target_material,
        "laser": spec.name,
    }


# ---------------------------------------------------------------------------
# DEW system comparison table
# ---------------------------------------------------------------------------

DEW_SYSTEMS: dict[str, dict] = {
    "dragonfire_uk": {
        "name": "DragonFire (UK)",
        "developer": "Dstl / MBDA UK / Leonardo UK / QinetiQ",
        "wavelength_nm": 1070.0,
        "power_kw": 50.0,
        "status": "demonstrator",
        "range_km": 5.0,
        "cost_per_shot_gbp": "10-20",
    },
    "iron_beam_israel": {
        "name": "Iron Beam (Israel)",
        "developer": "Rafael / IMOD",
        "wavelength_nm": 1070.0,
        "power_kw": 100.0,
        "status": "in_development",
        "range_km": 10.0,
        "cost_per_shot_usd": "low",
    },
    "helios_us": {
        "name": "HELIOS (US Navy)",
        "developer": "Lockheed Martin",
        "wavelength_nm": 1064.0,
        "power_kw": 60.0,
        "status": "integration_trials",
        "range_km": None,
        "cost_per_shot_usd": "low",
    },
    "locust_x3_us": {
        "name": "LOCUST X3 (US)",
        "developer": "AeroVironment",
        "wavelength_nm": None,
        "power_kw": None,
        "status": "demonstrator",
        "range_km": None,
        "cost_per_shot_usd": 5.0,
    },
}
