from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from .base import Model


class ParameterInfo(Model):
    name: str = ""
    location: str = "query" # query | body | header | path
    observed_types: List[str] = []
    sample_values: List[str] = []

    def __init__(self, **kwargs):
        if "observed_types" not in kwargs:
            kwargs["observed_types"] = []
        if "sample_values" not in kwargs:
            kwargs["sample_values"] = []
        super().__init__(**kwargs)


class Endpoint(Model):
    method: str = "GET"
    scheme: str = "http"
    host: str = ""
    port: int = 80
    path: str = "/"
    parameters: List[str] = []
    source: str = "crawler" # crawler | passive | proxy | manual
    parameter_details: Dict[str, ParameterInfo] = {}
    discovered_at: float = 0.0

    def __init__(self, **kwargs):
        if "discovered_at" not in kwargs or not kwargs["discovered_at"]:
            kwargs["discovered_at"] = datetime.now(timezone.utc).timestamp()
        if "parameters" not in kwargs:
            kwargs["parameters"] = []
        if "parameter_details" not in kwargs:
            kwargs["parameter_details"] = {}
        if "method" in kwargs:
            kwargs["method"] = kwargs["method"].upper()
        super().__init__(**kwargs)

    @property
    def full_path(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def canonical_url(self) -> str:
        port_part = f":{self.port}" if (self.scheme == "http" and self.port != 80) or (self.scheme == "https" and self.port != 443) else ""
        return f"{self.scheme}://{self.host}{port_part}{self.path}"
