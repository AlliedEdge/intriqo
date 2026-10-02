"""Shared schema primitives — error responses, pagination."""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    """Standard error envelope returned by all API error handlers."""
    error: ErrorDetail


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated list response."""
    items: list[T]
    total: int
    page: int
    page_size: int
    has_next: bool

    model_config = {"arbitrary_types_allowed": True}
