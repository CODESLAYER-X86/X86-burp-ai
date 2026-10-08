from __future__ import annotations
from typing import Dict, List, Optional
from .base import SecurityDetector


class DetectorRegistry:
    """Central registry of pluggable security detectors."""
    def __init__(self):
        self._detectors: Dict[str, SecurityDetector] = {}

    def register(self, detector: SecurityDetector):
        self._detectors[detector.name] = detector

    def get(self, name: str) -> Optional[SecurityDetector]:
        return self._detectors.get(name)

    def list_all(self) -> List[SecurityDetector]:
        return list(self._detectors.values())

    def list_names(self) -> List[str]:
        return list(self._detectors.keys())
