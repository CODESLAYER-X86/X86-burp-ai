from __future__ import annotations
from typing import List, Optional
from .base import Model


class ScopePolicy(Model):
    targets: List[str] = []
    allowed_methods: List[str] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    allowed_ports: List[int] = [80, 443, 8080, 8443, 3000]
    allow_subdomains: bool = False
    allow_external_hosts: bool = False
    allow_internal_loopback: bool = True  # True for authorized local labs / CTFs
    max_requests_per_minute: int = 60

    def __init__(self, **kwargs):
        if "targets" not in kwargs:
            kwargs["targets"] = []
        if "allowed_methods" not in kwargs:
            kwargs["allowed_methods"] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        if "allowed_ports" not in kwargs:
            kwargs["allowed_ports"] = [80, 443, 8080, 8443, 3000]
        super().__init__(**kwargs)
