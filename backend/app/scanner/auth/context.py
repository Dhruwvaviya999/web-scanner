"""Building an `AuthenticationContext` from user-supplied material.

One function, so there is exactly one path from "what the user typed" to "what
gets sent". It validates first and binds the origin second, which is what makes
the resulting context safe to hand to the transport: by the time it exists, the
material is transmittable and the single origin it may be sent to is fixed.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.scanner.auth.types import AuthenticationContext, AuthMode
from app.scanner.auth.validation import (
    AuthConfigError,
    validate_bearer_token,
    validate_cookies,
    validate_mode_payload,
)
from app.scanner.crawler.url_normalizer import origin_of
from app.scanner.url_validator import parse_target_url
from app.scanner.types import ScannerError


def build_context(
    mode: AuthMode,
    target_url: str,
    *,
    token: str | None = None,
    cookies: Sequence[tuple[str, str]] | None = None,
) -> AuthenticationContext:
    """Validate material and bind it to the origin of `target_url`.

    The origin comes from the URL the user asked to scan, not from wherever the
    target later redirects. That is the whole point: if the target bounces the
    scan to another host, the credentials stay behind.
    """
    validate_mode_payload(mode, token=token, cookies=cookies)

    if mode is AuthMode.NONE:
        return AuthenticationContext.none()

    try:
        parsed = parse_target_url(target_url)
    except ScannerError as exc:
        raise AuthConfigError(exc.message) from exc

    origin = origin_of(parsed.normalized_url)
    if origin is None:  # pragma: no cover - a parsed target always has an origin
        raise AuthConfigError("The target URL has no origin to authenticate against.")

    if mode is AuthMode.BEARER_TOKEN:
        return AuthenticationContext(
            mode=mode, origin=origin, token=validate_bearer_token(token or "")
        )

    return AuthenticationContext(
        mode=mode, origin=origin, cookies=validate_cookies(cookies or ())
    )
