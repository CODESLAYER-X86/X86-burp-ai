from __future__ import annotations
import difflib
import hashlib
import re
from typing import Any, Dict, List, Optional
from models.response import HTTPResponse


def calculate_similarity(text_a: str, text_b: str) -> float:
    """Computes similarity ratio between 0.0 and 1.0."""
    if text_a == text_b:
        return 1.0
    if not text_a or not text_b:
        return 0.0
    # Sample up to 10000 chars for efficiency
    sample_a = text_a[:10000]
    sample_b = text_b[:10000]
    matcher = difflib.SequenceMatcher(None, sample_a, sample_b)
    return round(matcher.quick_ratio(), 4)


def extract_relevant_excerpt(text: str, keywords: List[str], window: int = 200) -> str:
    """Extracts high-value snippet around specified keywords rather than blind truncation."""
    if not text:
        return ""
    text_lower = text.lower()
    matches = []
    for kw in keywords:
        kw_low = kw.lower()
        idx = text_lower.find(kw_low)
        if idx != -1:
            start = max(0, idx - window)
            end = min(len(text), idx + len(kw) + window)
            matches.append(text[start:end].strip())

    if matches:
        return " ... \n".join(matches[:3])
    return text[:min(len(text), 400)]


def compare_responses(baseline: HTTPResponse, test: HTTPResponse) -> Dict[str, Any]:
    """
    Deterministic response comparator returning structured deltas.
    Used by repeater, fuzzer, and security detectors.
    """
    status_changed = baseline.status_code != test.status_code
    body_length_delta = test.body_size - baseline.body_size
    content_type_changed = baseline.content_type != test.content_type
    body_hash_changed = baseline.sha256 != test.sha256
    similarity = calculate_similarity(baseline.body_text, test.body_text)

    # Header differences
    changed_headers = []
    for k in set(baseline.headers.keys()).union(test.headers.keys()):
        base_val = baseline.headers.get(k)
        test_val = test.headers.get(k)
        if base_val != test_val:
            changed_headers.append(k.lower())

    interesting = False
    reasons = []

    if status_changed:
        interesting = True
        reasons.append(f"Status changed from {baseline.status_code} to {test.status_code}")

    if content_type_changed:
        interesting = True
        reasons.append(f"Content-type changed from {baseline.content_type} to {test.content_type}")

    if abs(body_length_delta) > 50:
        if similarity < 0.85:
            interesting = True
            reasons.append(f"Body length delta {body_length_delta}B with similarity {similarity}")

    # Detect database error signatures
    sql_errors = [
        "syntax error", "sqlstate", "sqlite3.operationalerror",
        "pg_query", "mysql_fetch", "ora-01756", "unclosed quotation mark"
    ]
    test_low = test.body_text.lower()
    for sig in sql_errors:
        if sig in test_low and sig not in baseline.body_text.lower():
            interesting = True
            reasons.append(f"Server error signature detected: '{sig}'")
            break

    return {
        "status_changed": status_changed,
        "baseline_status": baseline.status_code,
        "test_status": test.status_code,
        "body_length_delta": body_length_delta,
        "baseline_length": baseline.body_size,
        "test_length": test.body_size,
        "content_type_changed": content_type_changed,
        "body_hash_changed": body_hash_changed,
        "similarity": similarity,
        "changed_headers": changed_headers,
        "interesting": interesting,
        "reasons": reasons,
    }
