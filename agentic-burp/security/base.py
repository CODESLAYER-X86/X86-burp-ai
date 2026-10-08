from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from models.endpoint import Endpoint
from models.evidence import Evidence
from models.finding import Finding
from models.observation import Observation
from models.request import HTTPRequest
from models.response import HTTPResponse
from models.session import AssessmentSession


class SecurityContext:
    """Bounded, target-specific context passed to detectors."""
    def __init__(
        self,
        assessment_id: str,
        endpoint: Endpoint,
        baseline_request: HTTPRequest,
        baseline_response: HTTPResponse,
        sessions: Optional[Dict[str, AssessmentSession]] = None,
        observations: Optional[List[Observation]] = None
    ):
        self.assessment_id = assessment_id
        self.endpoint = endpoint
        self.baseline_request = baseline_request
        self.baseline_response = baseline_response
        self.sessions = sessions or {}
        self.observations = observations or []


class DetectorResult:
    """Standardized result returned by all security detectors."""
    def __init__(
        self,
        detector_name: str,
        status: str, # NOT_APPLICABLE | CANDIDATE | INVESTIGATING | SUPPORTED | REFUTED | INCONCLUSIVE
        evidence_list: Optional[List[Evidence]] = None,
        candidate_findings: Optional[List[Finding]] = None,
        recommended_next_steps: Optional[List[str]] = None,
        summary: str = ""
    ):
        self.detector_name = detector_name
        self.status = status
        self.evidence_list = evidence_list or []
        self.candidate_findings = candidate_findings or []
        self.recommended_next_steps = recommended_next_steps or []
        self.summary = summary


class SecurityDetector(ABC):
    """Abstract base class for all deterministic security test detectors."""
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def can_analyze(self, context: SecurityContext) -> bool:
        """Deterministic applicability gate: avoids running inapplicable detectors."""
        pass

    @abstractmethod
    async def analyze(self, context: SecurityContext, http_client: Any) -> DetectorResult:
        """Executes bounded security verification and returns structured evidence."""
        pass
