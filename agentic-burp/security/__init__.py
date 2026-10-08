from .base import SecurityDetector, SecurityContext, DetectorResult
from .registry import DetectorRegistry
from .sqli import SQLiDetector
from .xss import XSSDetector
from .idor import IDORDetector
from .auth import AuthDetector
from .ssrf import SSRFDetector
from .csrf import CSRFDetector
from .cors import CORSDetector


def get_default_detector_registry() -> DetectorRegistry:
    registry = DetectorRegistry()
    registry.register(SQLiDetector())
    registry.register(XSSDetector())
    registry.register(IDORDetector())
    registry.register(AuthDetector())
    registry.register(SSRFDetector())
    registry.register(CSRFDetector())
    registry.register(CORSDetector())
    return registry


__all__ = [
    "SecurityDetector",
    "SecurityContext",
    "DetectorResult",
    "DetectorRegistry",
    "SQLiDetector",
    "XSSDetector",
    "IDORDetector",
    "AuthDetector",
    "SSRFDetector",
    "CSRFDetector",
    "CORSDetector",
    "get_default_detector_registry",
]
