"""User profile endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from app.core.deps import CurrentUser, DbSession
from app.schemas.common import UNAUTHORIZED_RESPONSE
from app.schemas.user import UserRead, UserUpdate
from app.services import auth_service

router = APIRouter(prefix="/users", tags=["users"], responses=UNAUTHORIZED_RESPONSE)


@router.get("/me", response_model=UserRead, summary="Read the caller's profile")
def read_profile(current_user: CurrentUser) -> UserRead:
    return UserRead.model_validate(current_user)


@router.patch("/me", response_model=UserRead, summary="Update the caller's display name")
def update_profile(payload: UserUpdate, current_user: CurrentUser, db: DbSession) -> UserRead:
    user = auth_service.update_user_name(db, current_user, payload.name)
    return UserRead.model_validate(user)
