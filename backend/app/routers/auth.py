"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from app.core.cookies import clear_auth_cookie, set_auth_cookie
from app.core.deps import CurrentUser, DbSession
from app.core.security import create_access_token
from app.models.user import User
from app.schemas.auth import AuthResponse, LoginRequest
from app.schemas.common import UNAUTHORIZED_RESPONSE, ErrorResponse, MessageResponse
from app.schemas.user import UserCreate, UserRead
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


def _issue_session(response: Response, user: User) -> AuthResponse:
    """Mint an access token, attach it as a cookie and describe the session."""
    token, expires_at = create_access_token(subject=str(user.id))
    set_auth_cookie(response, token)
    return AuthResponse(user=UserRead.model_validate(user), expires_at=expires_at)


@router.post(
    "/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an account and start a session",
    responses={409: {"model": ErrorResponse, "description": "Email already registered."}},
)
def register(payload: UserCreate, response: Response, db: DbSession) -> AuthResponse:
    user = auth_service.register_user(db, payload)
    return _issue_session(response, user)


@router.post(
    "/login",
    response_model=AuthResponse,
    summary="Exchange credentials for a session cookie",
    responses=UNAUTHORIZED_RESPONSE,
)
def login(payload: LoginRequest, response: Response, db: DbSession) -> AuthResponse:
    user = auth_service.authenticate_user(db, payload.email, payload.password)
    return _issue_session(response, user)


@router.post("/logout", response_model=MessageResponse, summary="Clear the session cookie")
def logout(response: Response) -> MessageResponse:
    # Unauthenticated on purpose: logging out must succeed even if the token has
    # already expired, so the browser is never left holding a stale cookie.
    clear_auth_cookie(response)
    return MessageResponse(message="Signed out.")


@router.get(
    "/me",
    response_model=UserRead,
    summary="The currently authenticated user",
    responses=UNAUTHORIZED_RESPONSE,
)
def read_current_user(current_user: CurrentUser) -> UserRead:
    return UserRead.model_validate(current_user)
