"""Shared FastAPI dependencies."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.errors import UnauthorizedError
from app.core.security import decode_access_token
from app.models.user import User
from app.services import auth_service

DbSession = Annotated[Session, Depends(get_db)]


def _read_token(request: Request) -> str:
    """Pull the access token out of the httpOnly auth cookie."""
    token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if not token:
        raise UnauthorizedError("Authentication is required.", code="not_authenticated")
    return token


def get_current_user(request: Request, db: DbSession) -> User:
    """Resolve the authenticated user, or raise 401.

    Every protected route depends on this, so ownership checks elsewhere can
    assume a real, active user.
    """
    payload = decode_access_token(_read_token(request))

    try:
        user_id = uuid.UUID(payload.subject)
    except ValueError as exc:
        raise UnauthorizedError("Invalid authentication token.", code="invalid_token") from exc

    user = auth_service.get_user_by_id(db, user_id)
    if user is None:
        # Token is validly signed but the account is gone.
        raise UnauthorizedError("Authentication is required.", code="not_authenticated")
    if not user.is_active:
        raise UnauthorizedError("This account has been disabled.", code="account_disabled")

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
