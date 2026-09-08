"""Registration, credential verification and user lookup."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, UnauthorizedError
from app.core.security import hash_password, needs_rehash, verify_password
from app.models.user import User
from app.schemas.user import UserCreate

# Deliberately identical for "unknown email" and "wrong password" so the
# response cannot be used to enumerate registered addresses.
_INVALID_CREDENTIALS = "Incorrect email or password."


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def get_user_by_id(db: Session, user_id: uuid.UUID) -> User | None:
    return db.get(User, user_id)


def register_user(db: Session, payload: UserCreate) -> User:
    """Create a new account, or raise `ConflictError` if the email is taken."""
    if get_user_by_email(db, payload.email) is not None:
        raise ConflictError("An account with this email already exists.", code="email_already_registered")

    user = User(
        name=payload.name,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        # Two concurrent registrations for the same address: the unique index is
        # the real guard, the check above is only for a friendlier common path.
        db.rollback()
        raise ConflictError(
            "An account with this email already exists.", code="email_already_registered"
        ) from exc
    db.refresh(user)
    return user


def authenticate_user(db: Session, email: str, password: str) -> User:
    """Return the matching user, or raise `UnauthorizedError`."""
    user = get_user_by_email(db, email)

    # Called even when `user` is None so both branches cost one Argon2 verify.
    if not verify_password(password, user.password_hash if user else None):
        raise UnauthorizedError(_INVALID_CREDENTIALS, code="invalid_credentials")

    assert user is not None  # verify_password only returns True for a real hash
    if not user.is_active:
        raise UnauthorizedError("This account has been disabled.", code="account_disabled")

    # Transparently upgrade hashes whenever the Argon2 parameters change.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.commit()

    return user


def update_user_name(db: Session, user: User, name: str) -> User:
    user.name = name
    db.commit()
    db.refresh(user)
    return user
