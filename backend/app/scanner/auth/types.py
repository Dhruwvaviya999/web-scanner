"""Target authentication: modes, status, and the context that carries secrets.

**This is not the scanner's own login.** Two unrelated things are called
"authentication" in this project:

* *Scanner-user authentication* — the JWT session that says who is using this
  application. It lives in `app.core.security` and is untouched by this package.
* *Target authentication* — credentials the authorized user supplies so a scan
  can reach pages of **their own application** that require a login. That is
  what lives here.

The scanner never discovers, guesses, brute-forces or refreshes credentials. It
is handed material by someone who already has it and applies that material to
requests, nothing more.

Everything secret is confined to `AuthenticationContext`. The context is the
only object that ever holds a token or a cookie value, it is the only thing that
can turn one into a header, and it refuses to render itself — `repr`, `str` and
formatting all produce a redacted description, so a secret cannot reach a log
line or a traceback through an f-string by accident.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from app.scanner.crawler.url_normalizer import Origin, is_same_origin


class AuthMode(str, enum.Enum):
    """How a scan authenticates to the target.

    Deliberately small. Username/password login automation, OAuth, SAML, MFA
    and browser-driven flows are **not** implemented: each is a workflow that
    interacts with an authentication system rather than merely presenting
    material the user already holds, and none is in scope here.
    """

    NONE = "NONE"
    BEARER_TOKEN = "BEARER_TOKEN"
    COOKIE = "COOKIE"


class AuthStatus(str, enum.Enum):
    """What one initial access check concluded about the supplied material.

    A judgement about a single request to the scan origin at one moment — not a
    claim that the credentials are valid everywhere in the target, or that they
    will still be valid later in the scan.
    """

    #: No authentication was supplied. The scan is unauthenticated.
    NOT_CONFIGURED = "NOT_CONFIGURED"
    #: The origin answered the check without rejecting the credentials.
    AVAILABLE = "AVAILABLE"
    #: The origin refused: 401, 403, or a redirect to a sign-in page.
    REJECTED = "REJECTED"
    #: The check could not conclude — the origin was unreachable, errored, or
    #: answered in a way that says nothing either way.
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class AuthOutcome:
    """Safe, persistable summary of a scan's authentication.

    Deliberately contains no secret and no reference to one, so it can travel
    onto the scan row, into the report and out through the API unchanged.
    """

    mode: AuthMode = AuthMode.NONE
    status: AuthStatus = AuthStatus.NOT_CONFIGURED

    @property
    def authenticated(self) -> bool:
        """Whether credentials were configured at all — not whether they worked."""
        return self.mode is not AuthMode.NONE


@dataclass(frozen=True, slots=True, repr=False)
class CookieCredential:
    """One user-supplied cookie. The value is a secret and never renders."""

    name: str
    value: str

    def __repr__(self) -> str:
        return f"CookieCredential(name={self.name!r}, value=<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticationContext:
    """Immutable target-authentication material, scoped to one origin.

    Two rules make this safe, and both are enforced here rather than at each
    call site:

    1. **Scope.** `headers_for` returns nothing unless the URL is same-origin
       with `origin` — the origin of the URL the user asked to scan, fixed when
       the context is built. A redirect cannot move it, a crawler cannot widen
       it, and a detector cannot override it, so credentials cannot leave the
       authorized origin even if some other layer's scope check were wrong.

    2. **Opacity.** The secret material is only ever read by `headers_for`.
       Every rendering path is redacted, so a `%s`, an f-string or an exception
       repr cannot leak a token.
    """

    mode: AuthMode = AuthMode.NONE
    #: The one origin these credentials may be sent to. `None` only for NONE.
    origin: Origin | None = None
    token: str | None = None
    cookies: tuple[CookieCredential, ...] = field(default_factory=tuple)

    @classmethod
    def none(cls) -> "AuthenticationContext":
        """An unauthenticated context. Adds no header to any request."""
        return cls()

    @property
    def configured(self) -> bool:
        return self.mode is not AuthMode.NONE

    def applies_to(self, url: str) -> bool:
        """Whether credentials may be sent to `url`.

        False for every URL outside the authorized origin, and for an
        unauthenticated context.
        """
        if not self.configured or self.origin is None:
            return False
        return is_same_origin(url, self.origin)

    def headers_for(self, url: str) -> Mapping[str, str]:
        """The authentication headers for one request, or nothing.

        The single place a credential becomes a header. Detectors, the crawler
        and the probe engine all reach the network through a transport that
        calls this, so none of them constructs an `Authorization` or `Cookie`
        header itself.
        """
        if not self.applies_to(url):
            return {}

        if self.mode is AuthMode.BEARER_TOKEN and self.token:
            return {"Authorization": f"Bearer {self.token}"}

        if self.mode is AuthMode.COOKIE and self.cookies:
            return {"Cookie": format_cookie_header(self.cookies)}

        return {}

    def describe(self) -> dict[str, str]:
        """Safe metadata about this context. Contains no secret."""
        return {
            "mode": self.mode.value,
            "origin": self.origin.base_url if self.origin else "",
            "cookie_names": ",".join(cookie.name for cookie in self.cookies),
        }

    def __repr__(self) -> str:
        if not self.configured:
            return "AuthenticationContext(mode=NONE)"
        names = ",".join(cookie.name for cookie in self.cookies)
        return (
            f"AuthenticationContext(mode={self.mode.value}, "
            f"origin={self.origin.base_url if self.origin else None}, "
            f"cookies=[{names}], secret=<redacted>)"
        )

    __str__ = __repr__


def format_cookie_header(cookies: Sequence[CookieCredential]) -> str:
    """Serialise cookies into one `Cookie` header value.

    Values are emitted exactly as supplied. A signed or encrypted cookie is a
    single opaque string to the target, so re-encoding or re-quoting it here
    would corrupt it; validation already refused anything that could not be
    represented safely in a header.
    """
    return "; ".join(f"{cookie.name}={cookie.value}" for cookie in cookies)
