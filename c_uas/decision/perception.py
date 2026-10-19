"""
Perception Module: sensor fusion and environment perception.

Handles RF detections, direction-finding results, and classification
outputs. Produces a situation summary for the decision engine.
"""

import time
from typing import Any, Dict, List


class PerceptionModule:
    def __init__(self) -> None:
        self.rf_detections: List[Dict[str, Any]] = []
        self.df_results: List[Dict[str, Any]] = []
        self.classification_results: List[Dict[str, Any]] = []

    def update_rf(self, detections: List[Dict[str, Any]]) -> None:
        self.rf_detections = detections

    def update_df(self, results: List[Dict[str, Any]]) -> None:
        self.df_results = results

    def update_classification(self, results: List[Dict[str, Any]]) -> None:
        self.classification_results = results

    def get_situation_summary(self) -> Dict[str, Any]:
        return {
            "num_rf_detections": len(self.rf_detections),
            "num_df_results": len(self.df_results),
            "num_drones_classified": len(self.classification_results),
            "timestamp": time.time(),
        }
