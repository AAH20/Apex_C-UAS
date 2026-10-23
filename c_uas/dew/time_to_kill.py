"""
Time-to-kill model for directed-energy engagements.

Computes dwell time required to defeat a target based on laser power,
target material, range, and beam quality. Modeling only — no hardware.
"""

from typing import Optional

# Energy required (kJ) to achieve mission kill on different materials
MATERIAL_ENERGY_KJ = {
    "carbon_fiber": 200.0,  # Composite airframe - needs ablation
    "aluminum": 150.0,  # Metal skin - needs melting
    "plastic": 50.0,  # Hobby drone - weak structure
    "composite": 180.0,  # Mixed materials
}

# Absorptivity by material (0-1)
MATERIAL_ABSORPTION = {
    "carbon_fiber": 0.85,
    "aluminum": 0.70,
    "plastic": 0.60,
    "composite": 0.75,
}

# Default values for unknown materials
DEFAULT_ENERGY_KJ = 150.0
DEFAULT_ABSORPTION = 0.70


class TimeToKillModel:
    def __init__(
        self,
        laser_power_kw: float = 50.0,
        min_dwell_s: float = 1.0,
    ) -> None:
        self.laser_power_kw = laser_power_kw
        self.min_dwell_s = min_dwell_s

    def time_to_kill_s(
        self,
        laser_power_kw: Optional[float] = None,
        target_material: str = "aluminum",
        range_m: float = 3000.0,
        m2: float = 1.5,
        jitter_urad: float = 5.0,
    ) -> float:
        """
        Returns dwell time in seconds to achieve mission kill.

        Args:
            laser_power_kw: Override instance power.
            target_material: Target material type.
            range_m: Slant range to target in meters.
            m2: Beam quality factor (1.0 = diffraction limited).
            jitter_urad: Pointing jitter in microradians.
        """
        power = laser_power_kw if laser_power_kw is not None else self.laser_power_kw
        if power <= 0:
            return float("inf")

        energy_kj = MATERIAL_ENERGY_KJ.get(target_material, DEFAULT_ENERGY_KJ)
        absorption = MATERIAL_ABSORPTION.get(target_material, DEFAULT_ABSORPTION)

        # Base dwell: Energy / (Power * absorption)
        base_dwell = energy_kj / (power * absorption)

        # Beam quality penalty: worse beam = longer dwell (fluence already
        # accounts for range, so don't double-count)
        from c_uas.dew.beam_model import DewBeamQualityModel

        bqm = DewBeamQualityModel()
        fluence = bqm.fluence_factor(m2=m2, jitter_urad=jitter_urad, range_m=range_m)
        beam_factor = 1.0 / max(fluence, 0.01)

        dwell = base_dwell * beam_factor
        return max(dwell, self.min_dwell_s)
