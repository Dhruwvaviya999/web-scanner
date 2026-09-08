"""Authentication request/response schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.schemas.user import UserRead, normalize_email


class LoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        return normalize_email(value)


class AuthResponse(BaseModel):
    """Returned by register and login.

    The access token itself is delivered as an httpOnly cookie and is
    deliberately absent from this body, so page scripts can never read it.
    `expires_at` is included purely so the UI can pre-empt an expired session.
    """

    user: UserRead
    expires_at: datetime
    token_type: str = "cookie"
