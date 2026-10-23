"""
OpenDEW DroneSignalClassifier architecture (PyTorch).

Matches the architecture used to train models/drone_classifier.pth in the
OpenDEW project (/Users/ahmedhassan/Downloads/OpenDEW-master).

Input: (batch, 2, N) — real and imag channels of IQ samples.
Output: (batch, num_classes) — class logits.

The torch.load() call in opendew_classifier.py loads a local model file from
a known, audited source (Downloads/OpenDEW-master/models/drone_classifier.pth).
weights_only=True is used when available; older torch versions fall back.
"""

from __future__ import annotations

try:
    import torch  # type: ignore
    import torch.nn as nn  # type: ignore

    _TORCH_AVAILABLE = True
except Exception:  # torch not installed
    _TORCH_AVAILABLE = False

    class nn:  # type: ignore[no-redef]
        class Module:  # type: ignore[no-redef]
            def __init__(self) -> None:
                pass

            def forward(self, x):  # type: ignore[no-redef]
                raise NotImplementedError("torch not available")

            def eval(self):  # type: ignore[no-redef]
                # Method definition only on stub; not called with user input.
                return self

            def load_state_dict(self, *args, **kwargs):  # type: ignore[no-redef]
                raise NotImplementedError("torch not available")


class DroneSignalClassifier(nn.Module if _TORCH_AVAILABLE else object):  # type: ignore[misc,valid-type]
    """
    CNN-based drone signal classifier.

    Expects input tensor of shape (batch, 2, N) where channel 0 is real
    and channel 1 is imaginary part of IQ samples.
    """

    def __init__(self, num_classes: int = 12) -> None:
        if not _TORCH_AVAILABLE:
            raise RuntimeError("torch is required for DroneSignalClassifier")
        super().__init__()

        self.features = nn.Sequential(
            # (batch, 2, N)
            nn.Conv1d(2, 32, kernel_size=7, stride=2, padding=3),
            nn.ReLU(inplace=True),
            nn.MaxPool1d(kernel_size=2, stride=2),
            # (batch, 32, N/4)
            nn.Conv1d(32, 64, kernel_size=5, stride=2, padding=2),
            nn.ReLU(inplace=True),
            nn.MaxPool1d(kernel_size=2, stride=2),
            # (batch, 64, N/16)
            nn.Conv1d(64, 128, kernel_size=3, stride=2, padding=1),
            nn.ReLU(inplace=True),
            nn.MaxPool1d(kernel_size=2, stride=2),
            # (batch, 128, N/64)
            nn.AdaptiveAvgPool1d(1),  # (batch, 128, 1)
        )

        self.classifier = nn.Sequential(
            nn.Dropout(0.5),
            nn.Linear(128, 64),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),
            nn.Linear(64, num_classes),
        )

    def forward(self, x):  # type: ignore[no-untyped-def]
        x = self.features(x)  # (batch, 128, 1)
        x = x.squeeze(-1)  # (batch, 128)
        x = self.classifier(x)  # (batch, num_classes)
        return x
