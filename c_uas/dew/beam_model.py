"""
Directed-energy beam quality and thermal bloom models (modeling only).

These models quantify why beam quality (M^2) and pointing jitter matter more
than headline kilowatts, and why thermal bloom limits sustained engagement.
No hardware control — pure physics modeling.
"""


class DewBeamQualityModel:
    """
    Beam quality (M^2) and jitter effects on fluence-on-target.

    A 50 kW beam with M^2=1.1 and 5 µrad jitter delivers more fluence than
    a 100 kW beam with M^2=2.0 and 15 µrad jitter.
    """

    def __init__(self, reference_range_m: float = 1000.0) -> None:
        self.reference_range_m = reference_range_m

    def fluence_factor(
        self,
        m2: float,
        jitter_urad: float,
        range_m: float,
    ) -> float:
        """Returns fluence delivery factor in [0, 1]. Higher = better."""
        # M^2 penalty: diffraction-limited is M^2 = 1.0
        m2_factor = 1.0 / max(m2, 1.0)

        # Jitter penalty: pointing error grows spot size
        jitter_factor = 1.0 / (1.0 + (jitter_urad * range_m / 1e6) ** 2)

        # Range penalty: inverse square from reference
        range_factor = (self.reference_range_m / max(range_m, 1.0)) ** 2

        factor = m2_factor * jitter_factor * range_factor
        return max(0.0, min(1.0, factor))


class DewThermalBloomModel:
    """
    Thermal bloom: sustained lasing heats the air column, defocusing the beam.

    Worse for down-the-throat (head-on) engagements where beam position is
    static; crossing targets have less heating effect.
    """

    def __init__(
        self,
        base_rate_per_second: float = 0.02,
        max_penalty: float = 0.5,
    ) -> None:
        self.base_rate_per_second = base_rate_per_second
        self.max_penalty = max_penalty

    def penalty(
        self,
        continuous_fire_s: float,
        geometry: str = "crossing",
    ) -> float:
        """Returns fractional Pk reduction (0.0 to max_penalty)."""
        if continuous_fire_s <= 0:
            return 0.0
        geometry_multiplier = 1.5 if geometry == "head_on" else 1.0
        raw = self.base_rate_per_second * continuous_fire_s * geometry_multiplier
        return min(raw, self.max_penalty)
