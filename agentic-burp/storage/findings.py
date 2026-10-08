from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from .database import Database
from models.finding import Finding


class FindingsRepository:
    def __init__(self, db: Database):
        self.db = db

    def save_finding(self, assessment_id: str, finding: Finding):
        query = """
        INSERT OR REPLACE INTO findings (
            id, assessment_id, finding_type, title, severity, confidence,
            status, endpoint, method, parameter, description, impact,
            remediation, detector, evidence_ids_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.db.execute_write(query, (
            finding.id, assessment_id, finding.finding_type, finding.title,
            finding.severity, finding.confidence, finding.status,
            finding.endpoint or "", finding.method or "", finding.parameter or "",
            finding.description, finding.impact, finding.remediation,
            finding.detector, json.dumps(finding.evidence_ids),
            finding.created_at, finding.updated_at
        ))

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        if row and "evidence_ids_json" in row:
            row["evidence_ids"] = json.loads(row["evidence_ids_json"])
        return row

    def list_findings(self, assessment_id: str) -> List[Dict[str, Any]]:
        rows = self.db.query_all(
            "SELECT * FROM findings WHERE assessment_id = ? ORDER BY created_at DESC",
            (assessment_id,)
        )
        for r in rows:
            if "evidence_ids_json" in r:
                r["evidence_ids"] = json.loads(r["evidence_ids_json"])
        return rows

    def save_evidence(self, assessment_id: str, evidence_id: str, evidence_type: str,
                      description: str, request_id: str = "", response_id: str = "",
                      baseline_request_id: str = "", baseline_response_id: str = "",
                      data: Optional[Dict[str, Any]] = None, reproducible: bool = True):
        import time
        query = """
        INSERT OR REPLACE INTO evidence (
            id, assessment_id, evidence_type, request_id, response_id,
            baseline_request_id, baseline_response_id, description, data_json,
            reproducible, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.db.execute_write(query, (
            evidence_id, assessment_id, evidence_type, request_id, response_id,
            baseline_request_id, baseline_response_id, description,
            json.dumps(data or {}), 1 if reproducible else 0, time.time()
        ))

    def get_evidence_for_finding(self, evidence_ids: List[str]) -> List[Dict[str, Any]]:
        if not evidence_ids:
            return []
        placeholders = ",".join("?" for _ in evidence_ids)
        rows = self.db.query_all(f"SELECT * FROM evidence WHERE id IN ({placeholders})", tuple(evidence_ids))
        for r in rows:
            if "data_json" in r:
                r["data"] = json.loads(r["data_json"])
        return rows
