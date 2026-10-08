from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from .database import Database
from models.observation import Observation


class ObservationRepository:
    def __init__(self, db: Database):
        self.db = db

    def save_observation(self, assessment_id: str, obs: Observation):
        query = """
        INSERT OR REPLACE INTO observations (
            id, assessment_id, category, source, request_id,
            endpoint, parameter, signals_json, severity_hint,
            interesting, summary, data_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.db.execute_write(query, (
            obs.id, assessment_id, obs.category, obs.source, obs.request_id or "",
            obs.endpoint, obs.parameter or "", json.dumps(obs.signals), obs.severity_hint,
            1 if obs.interesting else 0, obs.summary,
            json.dumps({"baseline": obs.baseline, "result": obs.result, "differences": obs.differences}),
            obs.created_at
        ))

    def list_observations(self, assessment_id: str, interesting_only: bool = False, limit: int = 50) -> List[Dict[str, Any]]:
        if interesting_only:
            query = "SELECT * FROM observations WHERE assessment_id = ? AND interesting = 1 ORDER BY created_at DESC LIMIT ?"
        else:
            query = "SELECT * FROM observations WHERE assessment_id = ? ORDER BY created_at DESC LIMIT ?"
        rows = self.db.query_all(query, (assessment_id, limit))
        for r in rows:
            if "signals_json" in r:
                r["signals"] = json.loads(r["signals_json"])
            if "data_json" in r:
                r["data"] = json.loads(r["data_json"])
        return rows
