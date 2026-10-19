"""
Engagement constraint models: thermal bloom, beam quality, and dwell time.

Pure physics models used by the engagement scheduler to compute realistic
time-to-kill and probability-of-kill adjustments. No hardware control.
"""

from typing import Optional


class ThermalBloomModel:
    """
    Models beam quality degradation from sustained lasing.

    Thermal bloom heats the air column along the beam path, acting like a
    diverging lens that spreads spot size and reduces fluence on target.
    Penalty grows with number of consecutive engagements on a fixed azimuth.
    """

    def __init__(
        self,
        base_penalty: float = 0.05,
        max_penalty: float = 0.5,
    ) -> None:
        self.base_penalty_per_target = base_penalty
        self.max_penalty = max_penalty

    def penalty(self, targets_engaged: int) -> float:
        """Returns the fractional Pk reduction (0.0 to max_penalty)."""
        if targets_engaged <= 0:
            return 0.0
        raw = self.base_penalty_per_target * targets_engaged
        return min(raw, self.max_penalty)


class BeamQualityModel:
    """
    Models beam quality (M^2) and pointing jitter effects on fluence-on-target.

    A 50 kW beam with M^2=1.1 and 5 µrad jitter delivers more fluence than
    a 100 kW beam with M^2=2.0 and 15 µrad jitter. Headline wattage is not
    the spec that matters.
    """

    def __init__(self, reference_range_m: float = 1000.0) -> None:
        self.reference_range_m = reference_range_m

    def fluence_factor(
        self,
        m2: float,
        jitter_urad: float,
        range_m: float,
    ) -> float:
        """
        Returns a fluence delivery factor in [0, 1].

        Lower M^2 and lower jitter = higher factor (closer to 1.0).
        Longer range = lower factor (inverse square spreading).
        """
        # M^2 penalty: ideal diffraction-limited is M^2 = 1.0
        m2_factor = 1.0 / max(m2, 1.0)

        # Jitter penalty: Gaussian beam spreading from pointing error
        # Spot growth factor ~ 1 + (jitter * range / diffraction_limit)^2
        jitter_factor = 1.0 / (1.0 + (jitter_urad * range_m / 1e6) ** 2)

        # Range penalty: inverse square from reference range
        range_factor = (self.reference_range_m / max(range_m, 1.0)) ** 2

        factor = m2_factor * jitter_factor * range_factor
        return max(0.0, min(1.0, factor))


class DwellModel:
    """
    Converts laser power and required energy into dwell time.

    Energy delivered = Power * time * absorption.
    time = Energy / (Power * absorption).
    """

    def __init__(self, min_dwell_s: float = 0.5) -> None:
        self.min_dwell_s = min_dwell_s

    def dwell_time_s(
        self,
        laser_power_kw: float,
        energy_required_kj: float,
        absorption: float = 0.8,
    ) -> float:
        """
        Returns dwell time in seconds.

        Args:
            laser_power_kw: Laser output power in kilowatts.
            energy_required_kj: Energy required on target in kilojoules.
            absorption: Target material absorptivity (0-1).
        """
        if laser_power_kw <= 0 or absorption <= 0:
            return float("inf")
        t = energy_required_kj / (laser_power_kw * absorption)
        return max(t, self.min_dwell_s)
