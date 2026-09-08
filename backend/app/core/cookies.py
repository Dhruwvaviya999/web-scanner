"""Auth cookie handling.

The access token travels in an httpOnly cookie rather than a JS-readable store,
so a cross-site scripting bug on the frontend cannot exfiltrate a session.
`SameSite=Lax` additionally stops other origins from driving state-changing
requests (CSRF) with the user's cookie attached.
"""

from __future__ import annotations

from fastapi import Response

from app.core.config import settings


def set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path=settings.AUTH_COOKIE_PATH,
        domain=settings.AUTH_COOKIE_DOMAIN,
        secure=settings.AUTH_COOKIE_SECURE,
        httponly=True,
        samesite=settings.AUTH_COOKIE_SAMESITE,
    )


def clear_auth_cookie(response: Response) -> None:
    # Attributes must match the ones used when setting it, or the browser keeps
    # the original cookie alongside the deletion.
    response.delete_cookie(
        key=settings.AUTH_COOKIE_NAME,
        path=settings.AUTH_COOKIE_PATH,
        domain=settings.AUTH_COOKIE_DOMAIN,
        secure=settings.AUTH_COOKIE_SECURE,
        httponly=True,
        samesite=settings.AUTH_COOKIE_SAMESITE,
    )
