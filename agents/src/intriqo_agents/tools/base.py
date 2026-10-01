"""Tool abstraction and execution results for agent capabilities.

SECURITY PRINCIPLE
──────────────────
Agents are never given unrestricted execution environments or generic shell
commands.  Tools must be strictly scoped, strongly typed, and implement
explicit input schemas.  Every tool invocation goes through:

    Agent → Tool.execute() → validate_input() → _run() → ToolResult

The agent proposes.  The deterministic security boundary executes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import logging
from typing import Any, Mapping, Optional


logger = logging.getLogger("intriqo.agents.tools")


@dataclass(frozen=True)
class ToolResult:
    """Structured outcome of a tool execution."""

    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.success, bool):
            raise TypeError("ToolResult.success must be a boolean")
        if not isinstance(self.data, (dict, Mapping)):
            raise TypeError("ToolResult.data must be a dictionary or mapping")
        if self.error is not None and not isinstance(self.error, str):
            raise TypeError("ToolResult.error must be None or a string")
        if not isinstance(self.metadata, (dict, Mapping)):
            raise TypeError("ToolResult.metadata must be a dictionary or mapping")
        object.__setattr__(self, "data", dict(self.data))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def ok(cls, data: dict[str, Any], metadata: Optional[dict[str, Any]] = None) -> ToolResult:
        return cls(success=True, data=data, metadata=metadata or {})

    @classmethod
    def fail(cls, error: str, metadata: Optional[dict[str, Any]] = None) -> ToolResult:
        return cls(success=False, data={}, error=error, metadata=metadata or {})


class Tool(ABC):
    """Abstract base class for all tools accessible by agents."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier of the tool."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human/machine-readable description of what this tool performs."""

    @property
    @abstractmethod
    def input_schema(self) -> dict[str, Any]:
        """Schema specifying required and optional input parameters."""

    def validate_input(self, input_data: dict[str, Any]) -> None:
        """Validate input parameters against the tool's input schema.

        Raises:
            ValueError: If a required parameter is missing or empty.
            TypeError: If input_data is not a dictionary.
        """
        if not isinstance(input_data, dict):
            raise TypeError(
                f"Tool '{self.name}' expects input_data to be a dict, "
                f"got {type(input_data).__name__}"
            )
        for req_field in self.input_schema.get("required", []):
            if req_field not in input_data or input_data[req_field] is None:
                raise ValueError(
                    f"Tool '{self.name}' missing required input field: '{req_field}'"
                )
            val = input_data[req_field]
            if isinstance(val, str) and not val.strip():
                raise ValueError(
                    f"Tool '{self.name}' field '{req_field}' cannot be empty"
                )

    def execute(self, input_data: dict[str, Any]) -> ToolResult:
        """Execute the tool with input validation and defensive error handling."""
        logger.info("Executing tool '%s' with inputs: %s", self.name, list(input_data.keys()))
        try:
            self.validate_input(input_data)
            result = self._run(input_data)
            if not isinstance(result, ToolResult):
                logger.error(
                    "Tool '%s' returned invalid result type: %s", self.name, type(result)
                )
                return ToolResult.fail(
                    error=f"Malformed tool return type: {type(result).__name__}",
                    metadata={"tool": self.name},
                )
            return result
        except (ValueError, TypeError) as val_err:
            logger.warning("Tool '%s' input validation failed: %s", self.name, val_err)
            return ToolResult.fail(
                error=f"Input validation error: {val_err}", metadata={"tool": self.name}
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(
                "Tool '%s' unhandled execution failure: %s", self.name, exc, exc_info=True
            )
            return ToolResult.fail(
                error=f"Execution error: {exc}", metadata={"tool": self.name}
            )

    @abstractmethod
    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        """Internal execution implementation for subclasses."""
