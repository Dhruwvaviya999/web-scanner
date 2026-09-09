"""Validation of user-supplied target-authentication material.

Everything here runs before a credential is ever put into a header. The point
is not to judge whether a token is *correct* — only the target can say that —
but to guarantee that whatever the user supplied can be transmitted as a header
without changing the shape of the request.

The threat this closes is header injection: a value containing CR or LF would
end the header and let the rest be read as further headers, or as a second
request. Rejecting is the only safe response; sanitising by stripping would
silently alter a credential the user believes they supplied.

Every message raised here describes the *problem*, never the value.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from app.scanner.auth.types import AuthMode, CookieCredential

#: Generous, but bounded. A JWT with several claims sits well under this; a
#: value larger than this is a mistake or an attempt to abuse the header.
MAX_TOKEN_LENGTH = 8192
MAX_COOKIE_NAME_LENGTH = 256
MAX_COOKIE_VALUE_LENGTH = 4096
MAX_COOKIES = 20
#: Cap on the assembled `Cookie` header. Most servers refuse more than 8 KB of
#: header, and a request that the target will reject outright helps nobody.
MAX_COOKIE_HEADER_LENGTH = 8192

#: RFC 6265 cookie-name: an RFC 7230 token.
_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

#: RFC 6265 cookie-octet: printable ASCII except space, comma, semicolon,
#: backslash and double quote. Exactly the set that survives a `Cookie` header
#: without quoting, which is why nothing here needs to re-encode a value.
_COOKIE_VALUE_RE = re.compile(r"^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$")

#: Bearer credentials are `token68`, plus the punctuation JWTs and opaque
#: tokens use in practice. No space, no control character, no CR/LF.
_TOKEN_RE = re.compile(r"^[\x21-\x7E]+$")


class AuthConfigError(ValueError):
    """Supplied authentication material cannot be used.

    A `ValueError` so the API layer surfaces it as a 422 through the same path
    as any other invalid field, rather than needing a new error class.
    """


def validate_bearer_token(raw: str) -> str:
    """Check a bearer token and return the value that will be sent.

    Outer whitespace is removed — a token pasted from a terminal or a JSON
    response routinely arrives with a trailing newline, and that newline is
    never part of the credential. Nothing *inside* the token is touched: it is
    opaque, and altering it would break a signature.
    """
    if raw is None:
        raise AuthConfigError("A bearer token is required for this mode.")

    token = raw.strip()
    if not token:
        raise AuthConfigError("The bearer token must not be empty.")
    if len(token) > MAX_TOKEN_LENGTH:
        raise AuthConfigError(
            f"The bearer token must be at most {MAX_TOKEN_LENGTH} characters."
        )
    if not _TOKEN_RE.fullmatch(token):
        raise AuthConfigError(
            "The bearer token contains characters that cannot be sent in a header. "
            "Line breaks, spaces and control characters are not allowed."
        )
    if token.lower().startswith("bearer "):
        raise AuthConfigError(
            'Supply the token only — the "Bearer " prefix is added by the scanner.'
        )
    return token


def validate_cookie(name: str, value: str) -> CookieCredential:
    """Check one cookie name/value pair.

    The value is **not** normalised. A signed or encrypted session cookie is a
    single opaque string; trimming, re-encoding or re-quoting it would break the
    signature and turn a working credential into a mysterious 401.
    """
    if name is None or not name.strip():
        raise AuthConfigError("Each cookie must have a name.")

    cookie_name = name.strip()
    if len(cookie_name) > MAX_COOKIE_NAME_LENGTH:
        raise AuthConfigError(
            f"A cookie name must be at most {MAX_COOKIE_NAME_LENGTH} characters."
        )
    if not _COOKIE_NAME_RE.fullmatch(cookie_name):
        raise AuthConfigError(
            f"Cookie name {cookie_name!r} is not valid. Use letters, digits or "
            "the characters ! # $ % & ' * + - . ^ _ ` | ~"
        )

    if value is None:
        raise AuthConfigError(f"Cookie {cookie_name!r} has no value.")
    if len(value) > MAX_COOKIE_VALUE_LENGTH:
        raise AuthConfigError(
            f"The value of cookie {cookie_name!r} must be at most "
            f"{MAX_COOKIE_VALUE_LENGTH} characters."
        )

    # A quoted value is legal in the header and is passed through as written.
    inner = value[1:-1] if len(value) >= 2 and value.startswith('"') and value.endswith('"') else value
    if not _COOKIE_VALUE_RE.fullmatch(inner):
        raise AuthConfigError(
            f"The value of cookie {cookie_name!r} contains characters that cannot "
            "be sent in a header. Line breaks, semicolons, commas, spaces, "
            "backslashes, quotes and control characters are not allowed."
        )

    return CookieCredential(name=cookie_name, value=value)


def validate_cookies(pairs: Iterable[tuple[str, str]]) -> tuple[CookieCredential, ...]:
    """Check a whole cookie set, including its size and uniqueness."""
    items = list(pairs)
    if not items:
        raise AuthConfigError("At least one cookie is required for this mode.")
    if len(items) > MAX_COOKIES:
        raise AuthConfigError(f"At most {MAX_COOKIES} cookies can be supplied.")

    cookies: list[CookieCredential] = []
    seen: set[str] = set()
    for name, value in items:
        cookie = validate_cookie(name, value)
        # A repeated name is ambiguous: the target would see both and pick one.
        if cookie.name.lower() in seen:
            raise AuthConfigError(f"Cookie {cookie.name!r} was supplied more than once.")
        seen.add(cookie.name.lower())
        cookies.append(cookie)

    header_length = sum(len(c.name) + len(c.value) + 2 for c in cookies)
    if header_length > MAX_COOKIE_HEADER_LENGTH:
        raise AuthConfigError(
            f"The combined cookies exceed the {MAX_COOKIE_HEADER_LENGTH} character "
            "limit for a Cookie header."
        )

    return tuple(cookies)


def validate_mode_payload(
    mode: AuthMode, *, token: str | None, cookies: Sequence[tuple[str, str]] | None
) -> None:
    """Check that the material supplied matches the mode chosen.

    Refusing a token in COOKIE mode is not pedantry: silently ignoring it would
    leave the user believing a credential is in use when it is not, and every
    later result would be interpreted against the wrong assumption.
    """
    has_token = token is not None and token != ""
    has_cookies = bool(cookies)

    if mode is AuthMode.NONE:
        if has_token or has_cookies:
            raise AuthConfigError(
                "Authentication mode NONE does not accept a token or cookies."
            )
        return

    if mode is AuthMode.BEARER_TOKEN:
        if not has_token:
            raise AuthConfigError("A bearer token is required for this mode.")
        if has_cookies:
            raise AuthConfigError("Bearer token mode does not accept cookies.")
        return

    if mode is AuthMode.COOKIE:
        if not has_cookies:
            raise AuthConfigError("At least one cookie is required for this mode.")
        if has_token:
            raise AuthConfigError("Cookie mode does not accept a bearer token.")
        return

    raise AuthConfigError(f"Unsupported authentication mode: {mode}")
