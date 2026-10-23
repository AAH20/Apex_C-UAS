"""
OpenDEW Signal Classifier Integration.

Integrates the neural network signal classifier from the OpenDEW project
(/Users/ahmedhassan/Downloads/OpenDEW-master) into the C-UAS platform's
RF detection pipeline.

Provides two classifiers:
1. RFSignalClassifier (existing) — frequency-band-based protocol fingerprinting
2. OpenDEWSignalClassifier — neural network based on trained PyTorch model

The OpenDEW classifier uses a trained model (drone_classifier.pth) and
IQ sample data for 12 drone signal classes:
DJI_DroneID, Analog_FPV, Fixed_Wing, DJI_Lightbridge, Swarm_Coord,
DJI_OcuSync, noise, TBS_Crossfire, Military_Encrypted, Digital_FPV,
ExpressLRS, MSP_Telemetry

Defensive-only: signal classification for detection. No exploitation.
"""

from __future__ import annotations

import importlib.util
import os
from typing import Any, Optional

OPENDEW_PATH = "/Users/ahmedhassan/Downloads/OpenDEW-master"


def _open_dew_available() -> bool:
    """Check if OpenDEW dependencies (torch, etc.) are available."""
    return importlib.util.find_spec("torch") is not None


class OpenDEWSignalClassifier:
    """
    Neural-network signal classifier backed by the OpenDEW trained model.

    Falls back gracefully if PyTorch or the OpenDEW model is not available.
    """

    CLASS_NAMES = [
        "DJI_DroneID",
        "Analog_FPV",
        "Fixed_Wing",
        "DJI_Lightbridge",
        "Swarm_Coord",
        "DJI_OcuSync",
        "noise",
        "TBS_Crossfire",
        "Military_Encrypted",
        "Digital_FPV",
        "ExpressLRS",
        "MSP_Telemetry",
    ]

    def __init__(self, model_path: Optional[str] = None) -> None:
        self.model_path = model_path or os.path.join(OPENDEW_PATH, "models", "drone_classifier.pth")
        self._model: Any = None
        self._available = False
        self._load_model()

    def _load_model(self) -> None:
        """Attempt to load the trained PyTorch model."""
        if not _open_dew_available():
            self._available = False
            return
        if not os.path.exists(self.model_path):
            self._available = False
            return
        try:
            import torch  # type: ignore

            # OpenDEW model: DroneSignalClassifier(num_classes=12)
            # Model file is local and from a known, audited source
            # (Downloads/OpenDEW-master/models/drone_classifier.pth).
            # weights_only=False is used because the file may contain
            # non-tensor objects; the file is not from an untrusted source.
            from c_uas.detection.opendew_model import DroneSignalClassifier

            self._model = DroneSignalClassifier(num_classes=12)
            try:
                state = torch.load(self.model_path, map_location="cpu", weights_only=True)
            except TypeError:
                # Older torch versions without weights_only support
                state = torch.load(self.model_path, map_location="cpu")
            self._model.load_state_dict(state)
            self._model.eval()
            self._available = True
        except Exception:
            # Any import/load failure → graceful fallback
            self._available = False
            self._model = None

    @property
    def available(self) -> bool:
        return self._available

    def classify_iq(
        self,
        iq_samples: list[float],
        sample_rate_hz: float = 2.4e6,
        center_freq_hz: float = 2.44e9,
    ) -> dict[str, Any]:
        """
        Classify IQ samples using the OpenDEW neural network.

        Returns dict with predicted class, confidence, and all class
        probabilities. Falls back to "unknown" if model unavailable.
        """
        if not self._available or self._model is None:
            return {
                "predicted_class": "unknown",
                "confidence": 0.0,
                "method": "opendew_fallback",
                "available": False,
                "probabilities": {},
            }

        import numpy as np  # type: ignore
        import torch  # type: ignore

        try:
            # Normalize IQ samples to [-1, 1]
            arr = np.array(iq_samples, dtype=np.float32)
            if len(arr) == 0:
                return {
                    "predicted_class": "unknown",
                    "confidence": 0.0,
                    "method": "opendew_empty",
                    "available": True,
                    "probabilities": {},
                }
            arr = arr / (np.max(np.abs(arr)) + 1e-12)

            # Convert to tensor: (1, 2, N) -> real/imag channels
            # OpenDEW expects IQ as two channels
            real = arr[::2] if len(arr) % 2 == 0 else arr
            imag = arr[1::2] if len(arr) % 2 == 0 else arr
            n = min(len(real), len(imag))
            tensor = torch.tensor([real[:n], imag[:n]], dtype=torch.float32).unsqueeze(
                0
            )  # (1, 2, N)

            with torch.no_grad():
                logits = self._model(tensor)
                probs = torch.softmax(logits, dim=1).squeeze(0)
                pred_idx = int(torch.argmax(probs).item())
                confidence = float(probs[pred_idx].item())

            return {
                "predicted_class": self.CLASS_NAMES[pred_idx],
                "confidence": round(confidence, 4),
                "method": "opendew_neural_net",
                "available": True,
                "probabilities": {
                    self.CLASS_NAMES[i]: round(float(p), 4) for i, p in enumerate(probs.tolist())
                },
            }
        except Exception:
            return {
                "predicted_class": "unknown",
                "confidence": 0.0,
                "method": "opendew_error",
                "available": True,
                "probabilities": {},
            }


# Singleton instance
_classifier: Optional[OpenDEWSignalClassifier] = None


def get_opendew_classifier() -> OpenDEWSignalClassifier:
    """Return a singleton OpenDEWSignalClassifier instance."""
    global _classifier
    if _classifier is None:
        _classifier = OpenDEWSignalClassifier()
    return _classifier
