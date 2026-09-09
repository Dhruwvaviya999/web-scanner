"""Target authentication for a scan.

Authorized use only: every credential here is supplied by the scanner's user
for an application they are authorized to test. Nothing in this package
discovers, guesses, brute-forces, cracks or refreshes a credential, and nothing
attacks an authentication system. See `types.py` for the distinction between
this and the scanner's own user login.

Only the leaf modules are re-exported here. `context` and `health` need the URL
validator and the HTTP transport, and both of those import this package's
types — so importing them from this file would make every `auth.types` import
circular. Take those two from their own modules:

    from app.scanner.auth.context import build_context
    from app.scanner.auth.health import AuthenticationCheckModule
"""

from app.scanner.auth.types import (
    AuthenticationContext,
    AuthMode,
    AuthOutcome,
    AuthStatus,
    CookieCredential,
    format_cookie_header,
)
from app.scanner.auth.validation import (
    MAX_COOKIE_HEADER_LENGTH,
    MAX_COOKIE_NAME_LENGTH,
    MAX_COOKIE_VALUE_LENGTH,
    MAX_COOKIES,
    MAX_TOKEN_LENGTH,
    AuthConfigError,
    validate_bearer_token,
    validate_cookie,
    validate_cookies,
    validate_mode_payload,
)

__all__ = [
    "MAX_COOKIES",
    "MAX_COOKIE_HEADER_LENGTH",
    "MAX_COOKIE_NAME_LENGTH",
    "MAX_COOKIE_VALUE_LENGTH",
    "MAX_TOKEN_LENGTH",
    "AuthConfigError",
    "AuthMode",
    "AuthOutcome",
    "AuthStatus",
    "AuthenticationContext",
    "CookieCredential",
    "format_cookie_header",
    "validate_bearer_token",
    "validate_cookie",
    "validate_cookies",
    "validate_mode_payload",
]
