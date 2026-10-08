from __future__ import annotations
import urllib.parse
from typing import Any, Dict, List, Optional
from models.scope import ScopePolicy


def create_default_policy(targets: Optional[List[str]] = None) -> ScopePolicy:
    return ScopePolicy(
        targets=targets or ["http://127.0.0.1:8080"],
        allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        allowed_ports=[80, 443, 8080, 8443, 3000],
        allow_subdomains=False,
        allow_external_hosts=False,
        allow_internal_loopback=True,
        max_requests_per_minute=60,
    )
