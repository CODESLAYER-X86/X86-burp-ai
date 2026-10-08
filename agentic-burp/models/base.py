"""
Dual-compatibility base model support for Agentic-Burp.
Seamlessly uses Pydantic when installed, with a robust fallback to dataclasses.
"""
from __future__ import annotations
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

try:
    from pydantic import BaseModel as _PydanticBaseModel, Field
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    Field = lambda default=None, **kwargs: default


if HAS_PYDANTIC:
    class Model(_PydanticBaseModel):
        class Config:
            arbitrary_types_allowed = True

        def to_dict(self) -> Dict[str, Any]:
            if hasattr(self, "model_dump"):
                return self.model_dump()
            return self.dict()

        def to_json(self) -> str:
            if hasattr(self, "model_dump_json"):
                return self.model_dump_json()
            return self.json()
else:
    from dataclasses import dataclass, asdict, is_dataclass, fields

    class Model:
        """Lightweight Pydantic-compatible model using Python standard library dataclasses."""
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def to_dict(self) -> Dict[str, Any]:
            def _serialize(obj):
                if isinstance(obj, Model):
                    return obj.to_dict()
                if isinstance(obj, datetime):
                    return obj.isoformat()
                if isinstance(obj, list):
                    return [_serialize(item) for item in obj]
                if isinstance(obj, dict):
                    return {k: _serialize(v) for k, v in obj.items()}
                return obj

            res = {}
            for k, v in self.__dict__.items():
                if not k.startswith("_"):
                    res[k] = _serialize(v)
            return res

        def dict(self) -> Dict[str, Any]:
            return self.to_dict()

        def model_dump(self) -> Dict[str, Any]:
            return self.to_dict()

        def to_json(self) -> str:
            return json.dumps(self.to_dict(), default=str)

        def model_dump_json(self) -> str:
            return self.to_json()

        def json(self) -> str:
            return self.to_json()

        @classmethod
        def model_validate(cls, data: Dict[str, Any]):
            return cls(**data)

        @classmethod
        def parse_obj(cls, data: Dict[str, Any]):
            return cls(**data)
