"""Password hashing (Argon2id) and JWT access-token handling.

All cryptographic decisions live here so they can be changed in one place.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.profiles import RFC_9106_LOW_MEMORY

from app.core.config import settings
from app.core.errors import UnauthorizedError

# Argon2id with the RFC 9106 "low memory" profile (64 MiB, t=3, p=4) — the
# OWASP-recommended baseline for interactive logins on commodity hardware.
_hasher = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)

# Verified against this when the email is unknown, so that a request for a
# non-existent account costs the same time as one for a real account.
_DUMMY_HASH = _hasher.hash("mn9NCiF7ky2CT4pxbP6qSbxV1PqmxIVi")

TOKEN_TYPE = "access"


@dataclass(frozen=True, slots=True)
class TokenPayload:
    subject: str
    issued_at: datetime
    expires_at: datetime
    token_id: str


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Return True when `password` matches `password_hash`.

    Passing `password_hash=None` still performs a full Argon2 verification
    against a dummy hash, keeping the response time of "unknown email" and
    "wrong password" indistinguishable.
    """
    try:
        _hasher.verify(password_hash or _DUMMY_HASH, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return password_hash is not None


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash predates the current Argon2 parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def create_access_token(subject: str, expires_delta: timedelta | None = None) -> tuple[str, datetime]:
    """Return `(encoded_jwt, expires_at)` for the given subject (a user id)."""
    now = datetime.now(UTC)
    expires_at = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    claims = {
        "sub": subject,
        "typ": TOKEN_TYPE,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(claims, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, expires_at


def decode_access_token(token: str) -> TokenPayload:
    """Decode and validate a token, or raise `UnauthorizedError`."""
    try:
        claims = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise UnauthorizedError("Your session has expired. Please sign in again.", code="token_expired") from exc
    except jwt.InvalidTokenError as exc:
        raise UnauthorizedError("Invalid authentication token.", code="invalid_token") from exc

    if claims.get("typ") != TOKEN_TYPE:
        raise UnauthorizedError("Invalid authentication token.", code="invalid_token")

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise UnauthorizedError("Invalid authentication token.", code="invalid_token")

    return TokenPayload(
        subject=subject,
        issued_at=datetime.fromtimestamp(claims["iat"], tz=UTC),
        expires_at=datetime.fromtimestamp(claims["exp"], tz=UTC),
        token_id=str(claims.get("jti", "")),
    )
