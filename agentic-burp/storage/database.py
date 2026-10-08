from __future__ import annotations
import json
import sqlite3
import os
import threading
from typing import Any, Dict, List, Optional, Tuple


class Database:
    """
    SQLite persistent storage with WAL mode, foreign keys, and indexed queries.
    Stores complete historical traffic, findings, evidence, and audit logs.
    """
    def __init__(self, db_path: str = "agentic_burp.sqlite3"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_schema()

    def get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self):
        conn = self.get_connection()
        with conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                mode TEXT NOT NULL DEFAULT 'assessment',
                status TEXT NOT NULL DEFAULT 'CREATED',
                phase TEXT NOT NULL DEFAULT 'DISCOVERY',
                config_json TEXT NOT NULL DEFAULT '{}',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS assessment_sessions (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                name TEXT NOT NULL,
                principal TEXT NOT NULL,
                auth_state TEXT NOT NULL DEFAULT 'UNAUTHENTICATED',
                cookies_json TEXT NOT NULL DEFAULT '{}',
                headers_json TEXT NOT NULL DEFAULT '{}',
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS http_traffic (
                request_id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                session_id TEXT NOT NULL DEFAULT 'default',
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                headers_json TEXT NOT NULL DEFAULT '{}',
                query_params_json TEXT NOT NULL DEFAULT '[]',
                cookies_json TEXT NOT NULL DEFAULT '{}',
                request_body TEXT,
                status_code INTEGER,
                response_headers_json TEXT NOT NULL DEFAULT '{}',
                response_body TEXT,
                body_size INTEGER NOT NULL DEFAULT 0,
                content_type TEXT NOT NULL DEFAULT '',
                sha256 TEXT NOT NULL DEFAULT '',
                elapsed_ms REAL NOT NULL DEFAULT 0.0,
                truncated INTEGER NOT NULL DEFAULT 0,
                timestamp REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_traffic_assessment ON http_traffic(assessment_id);
            CREATE INDEX IF NOT EXISTS idx_traffic_url ON http_traffic(url);
            CREATE INDEX IF NOT EXISTS idx_traffic_status ON http_traffic(status_code);

            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                method TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                path TEXT NOT NULL,
                parameters_json TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL DEFAULT 'crawler',
                discovered_at REAL NOT NULL,
                UNIQUE(assessment_id, method, host, port, path)
            );

            CREATE TABLE IF NOT EXISTS observations (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                category TEXT NOT NULL,
                source TEXT NOT NULL,
                request_id TEXT,
                endpoint TEXT NOT NULL,
                parameter TEXT,
                signals_json TEXT NOT NULL DEFAULT '[]',
                severity_hint TEXT NOT NULL DEFAULT 'info',
                interesting INTEGER NOT NULL DEFAULT 0,
                summary TEXT NOT NULL DEFAULT '',
                data_json TEXT NOT NULL DEFAULT '{}',
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_obs_assessment ON observations(assessment_id);
            CREATE INDEX IF NOT EXISTS idx_obs_interesting ON observations(interesting);

            CREATE TABLE IF NOT EXISTS hypotheses (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                hypothesis_type TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                parameter TEXT,
                state TEXT NOT NULL DEFAULT 'PROPOSED',
                confidence REAL NOT NULL DEFAULT 0.5,
                description TEXT NOT NULL DEFAULT '',
                evidence_json TEXT NOT NULL DEFAULT '[]',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'MEDIUM',
                confidence TEXT NOT NULL DEFAULT 'MEDIUM',
                status TEXT NOT NULL DEFAULT 'SUSPECTED',
                endpoint TEXT,
                method TEXT,
                parameter TEXT,
                description TEXT NOT NULL,
                impact TEXT NOT NULL DEFAULT '',
                remediation TEXT NOT NULL DEFAULT '',
                detector TEXT NOT NULL DEFAULT '',
                evidence_ids_json TEXT NOT NULL DEFAULT '[]',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                request_id TEXT,
                response_id TEXT,
                baseline_request_id TEXT,
                baseline_response_id TEXT,
                description TEXT NOT NULL,
                data_json TEXT NOT NULL DEFAULT '{}',
                reproducible INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS detector_runs (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                detector_name TEXT NOT NULL,
                target_endpoint TEXT NOT NULL,
                status TEXT NOT NULL,
                requests_count INTEGER NOT NULL DEFAULT 0,
                result_json TEXT NOT NULL DEFAULT '{}',
                start_time REAL NOT NULL,
                end_time REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp REAL NOT NULL,
                data_json TEXT NOT NULL DEFAULT '{}'
            );
            """)

    def execute_insert(self, query: str, params: Tuple[Any, ...]) -> int:
        conn = self.get_connection()
        with conn:
            cursor = conn.execute(query, params)
            return cursor.lastrowid or 0

    def execute_write(self, query: str, params: Tuple[Any, ...]):
        conn = self.get_connection()
        with conn:
            conn.execute(query, params)

    def query_one(self, query: str, params: Tuple[Any, ...] = ()) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None

    def query_all(self, query: str, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
