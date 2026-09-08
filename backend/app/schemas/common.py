"""Shared response schemas."""

from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    field: str | None = Field(default=None, description="Dotted path of the offending input field.")
    message: str


class ErrorBody(BaseModel):
    code: str = Field(description="Stable, machine-readable error identifier.")
    message: str = Field(description="Human-readable message safe to show to the user.")
    details: list[ErrorDetail] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    """Every non-2xx response from this API uses this shape."""

    error: ErrorBody


class MessageResponse(BaseModel):
    message: str


class HealthResponse(BaseModel):
    status: str
    database: str
    environment: str


def _example(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": []}}


# Reusable OpenAPI response blocks.
UNAUTHORIZED_RESPONSE: dict[int | str, dict[str, Any]] = {
    401: {
        "model": ErrorResponse,
        "description": "Missing, invalid or expired credentials.",
        "content": {"application/json": {"example": _example("unauthorized", "Authentication is required.")}},
    }
}
NOT_FOUND_RESPONSE: dict[int | str, dict[str, Any]] = {
    404: {
        "model": ErrorResponse,
        "description": "Resource not found, or not owned by the caller.",
        "content": {"application/json": {"example": _example("not_found", "Scan not found.")}},
    }
}
