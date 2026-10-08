from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional
from models.base import Model


class ToolDefinition(Model):
    name: str
    description: str
    permission: str # READ | ACTIVE | DESTRUCTIVE
    handler: Optional[Any] = None
    input_schema: Dict[str, Any] = {}


class ToolRegistry:
    """Registry maintaining available registered tools and their permissions."""
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition):
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_tools(self) -> List[ToolDefinition]:
        return list(self._tools.values())

    def get_llm_tool_declarations(self) -> List[Dict[str, Any]]:
        """Exports compact tool descriptions for Gemini reasoning."""
        declarations = []
        for t in self._tools.values():
            declarations.append({
                "name": t.name,
                "description": t.description,
                "permission": t.permission,
                "parameters": t.input_schema
            })
        return declarations
