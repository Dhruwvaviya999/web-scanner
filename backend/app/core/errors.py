"""Application error types and the structured error payload they serialise to.

Every failure the API returns deliberately goes through one of these types so
that clients see a stable `{"error": {"code", "message", "details"}}` shape and
never an internal traceback.
"""

from typing import Any

from fastapi import status


class AppError(Exception):
    """Base class for expected, client-facing failures."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    code: str = "internal_error"
    message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        details: list[dict[str, Any]] | None = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.details = details or []
        super().__init__(self.message)


class BadRequestError(AppError):
    status_code = status.HTTP_400_BAD_REQUEST
    code = "bad_request"
    message = "The request could not be processed."


class UnauthorizedError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthorized"
    message = "Authentication is required."


class ForbiddenError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"
    message = "You do not have access to this resource."


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"
    message = "The requested resource was not found."


class ConflictError(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"
    message = "The resource already exists."


class UnprocessableEntityError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "unprocessable_entity"
    message = "The request payload failed validation."


def error_payload(
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details or []}}
