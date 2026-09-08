"""User request/response schemas."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

NAME_MIN_LENGTH = 2
NAME_MAX_LENGTH = 120
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128

Name = Annotated[str, Field(min_length=NAME_MIN_LENGTH, max_length=NAME_MAX_LENGTH)]
Password = Annotated[str, Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)]

_HAS_LETTER = re.compile(r"[A-Za-z]")
_HAS_DIGIT = re.compile(r"\d")


def normalize_email(value: str) -> str:
    """Lower-case and trim an address so lookups and uniqueness are consistent."""
    return value.strip().lower()


def _validate_password_strength(value: str) -> str:
    if not _HAS_LETTER.search(value) or not _HAS_DIGIT.search(value):
        raise ValueError("Password must contain at least one letter and one number.")
    return value


class UserCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: Name
    email: EmailStr
    password: Password
    confirm_password: Password

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        return normalize_email(value)

    @field_validator("password")
    @classmethod
    def _check_strength(cls, value: str) -> str:
        return _validate_password_strength(value)

    @model_validator(mode="after")
    def _check_passwords_match(self) -> "UserCreate":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class UserUpdate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: Name


class UserRead(BaseModel):
    """The public representation of a user. Never includes `password_hash`."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    email: EmailStr
    created_at: datetime
    updated_at: datetime
