"""Cookie security analysis.

Pure functions over the `Set-Cookie` headers the scanner already received.

The cookie *value* is discarded during parsing and is never carried on
`CookieInfo`. That is deliberate and structural rather than a convention: a
session identifier is a live credential, so there must be no path by which one
can reach a finding, a log line or the database.

Detection is intentionally conservative. Naming a cookie "session-like" is a
heuristic, so those findings carry MEDIUM confidence, and a cookie that merely
looks functional is not treated as a credential.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingSeverity,
)

#: Whole cookie names used by common frameworks for session state.
_SESSION_COOKIE_NAMES = frozenset(
    {
        "sid",
        "sess",
        "session",
        "sessionid",
        "session_id",
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "aspsessionid",
        "connect.sid",
        "laravel_session",
        "_session_id",
        "csrftoken",
        "xsrf-token",
    }
)

#: Fragments that mark a cookie as session- or credential-bearing wherever they
#: appear in the name. Kept framework-agnostic on purpose.
_SESSION_NAME_FRAGMENTS = (
    "session",
    "sessid",
    "auth",
    "token",
    "jwt",
    "login",
    "credential",
    "remember",
    "identity",
)

#: Short fragments that are only meaningful as a whole word within a name, so
#: that "sidebar_state" is not mistaken for a session cookie.
_SESSION_NAME_TOKENS = frozenset({"sid", "sess", "jwt", "auth", "token"})

_NAME_SPLIT_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class CookieInfo:
    """The security-relevant attributes of one Set-Cookie header.

    There is deliberately no `value` field — see the module docstring.
    """

    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None


def parse_set_cookie(header: str) -> CookieInfo | None:
    """Parse one `Set-Cookie` header value, discarding the cookie's value.

    Returns None for anything without a usable name rather than raising, so a
    malformed header from a hostile or broken target cannot fail a scan.
    """
    if not header or not header.strip():
        return None

    segments = header.split(";")
    name_pair = segments[0].strip()
    if "=" not in name_pair:
        # A Set-Cookie with no name=value pair is not a cookie we can assess.
        return None

    name = name_pair.split("=", 1)[0].strip()
    if not name:
        return None

    secure = False
    http_only = False
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None

    for segment in segments[1:]:
        attribute = segment.strip()
        if not attribute:
            continue

        key, _, raw_value = attribute.partition("=")
        key = key.strip().lower()
        value = raw_value.strip() or None

        if key == "secure":
            secure = True
        elif key == "httponly":
            http_only = True
        elif key == "samesite" and value:
            same_site = value
        elif key == "domain" and value:
            domain = value
        elif key == "path" and value:
            path = value

    return CookieInfo(
        name=name,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        domain=domain,
        path=path,
    )


def parse_set_cookie_headers(headers: Iterable[str]) -> list[CookieInfo]:
    """Parse every Set-Cookie header, skipping ones that cannot be read."""
    cookies: list[CookieInfo] = []
    for header in headers:
        cookie = parse_set_cookie(header)
        if cookie is not None:
            cookies.append(cookie)
    return cookies


def is_session_cookie(name: str) -> bool:
    """Heuristic: does this name suggest a session or credential cookie?

    Findings derived from this carry MEDIUM confidence, never HIGH — the name is
    the only signal available without interpreting the cookie's contents, which
    this scanner does not do.
    """
    lowered = name.strip().lower()
    if not lowered:
        return False
    if lowered in _SESSION_COOKIE_NAMES:
        return True
    if any(fragment in lowered for fragment in _SESSION_NAME_FRAGMENTS):
        return True
    tokens = {token for token in _NAME_SPLIT_RE.split(lowered) if token}
    return bool(tokens & _SESSION_NAME_TOKENS)


def analyze_cookies(cookies: Sequence[CookieInfo], *, is_https: bool) -> list[FindingData]:
    """Return every cookie observation for one response."""
    findings: list[FindingData] = []
    for cookie in cookies:
        findings.extend(_analyze_cookie(cookie, is_https=is_https))
    return findings


def _analyze_cookie(cookie: CookieInfo, *, is_https: bool) -> list[FindingData]:
    findings: list[FindingData] = []
    session_like = is_session_cookie(cookie.name)
    # The name alone is safe to echo; the value never leaves the parser.
    scope = f'Cookie "{cookie.name}"'

    # --- Secure ---------------------------------------------------------- #
    # Only assessed over HTTPS: on a plain-HTTP response the attribute would be
    # ignored by browsers anyway, so demanding it there would be a false positive.
    if is_https and not cookie.secure:
        findings.append(
            FindingData(
                code="cookie_missing_secure",
                title=(
                    "Session cookie is not marked Secure"
                    if session_like
                    else "Cookie is not marked Secure"
                ),
                category=FindingCategory.COOKIE,
                severity=FindingSeverity.MEDIUM if session_like else FindingSeverity.LOW,
                confidence=(
                    FindingConfidence.MEDIUM if session_like else FindingConfidence.HIGH
                ),
                description=(
                    f"{scope} was set over HTTPS without the Secure attribute. Without it, "
                    "the browser will also send this cookie over plain HTTP."
                    + (
                        " The cookie's name suggests it carries session or authentication "
                        "state, though this scan did not inspect its contents."
                        if session_like
                        else ""
                    )
                ),
                evidence=f"{scope} does not include the Secure attribute.",
                impact=(
                    "Any later request to this host over HTTP would transmit the cookie in "
                    "clear text, where a party on the network path could read it."
                ),
                remediation=f'Add the Secure attribute when setting "{cookie.name}".',
            )
        )

    # --- HttpOnly -------------------------------------------------------- #
    # Reported only for session-like cookies. Many cookies are read by scripts
    # by design (UI preferences, analytics), so flagging every one of them would
    # bury the cases that matter.
    if session_like and not cookie.http_only:
        findings.append(
            FindingData(
                code="session_cookie_missing_httponly",
                title="Session cookie is missing HttpOnly",
                category=FindingCategory.COOKIE,
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.MEDIUM,
                description=(
                    f"{scope} appears — from its name — to hold session or authentication "
                    "state, and does not set HttpOnly. Client-side JavaScript can therefore "
                    "read it. The cookie's purpose was inferred from its name only."
                ),
                evidence=f"{scope} does not include the HttpOnly attribute.",
                impact=(
                    "Should a cross-site scripting flaw exist anywhere on this origin, an "
                    "attacker's script could read the cookie and reuse the session. No "
                    "injection testing was performed in this scan, so this describes the "
                    "consequence if such a flaw exists — not evidence that one does."
                ),
                remediation=(
                    f'Add the HttpOnly attribute when setting "{cookie.name}", unless it is '
                    "genuinely required by client-side code."
                ),
            )
        )

    # --- SameSite -------------------------------------------------------- #
    if cookie.same_site is None:
        findings.append(
            FindingData(
                code="cookie_missing_samesite",
                title=(
                    "Session cookie has no SameSite attribute"
                    if session_like
                    else "Cookie has no SameSite attribute"
                ),
                category=FindingCategory.COOKIE,
                severity=FindingSeverity.LOW if session_like else FindingSeverity.INFO,
                confidence=FindingConfidence.HIGH,
                description=(
                    f"{scope} does not declare SameSite. Current browsers default to "
                    "SameSite=Lax, so this is largely a portability and clarity concern "
                    "rather than an immediate weakness."
                ),
                evidence=f"{scope} does not include the SameSite attribute.",
                impact=(
                    "On clients that do not apply the Lax default, the cookie is sent with "
                    "cross-site requests, which is the precondition for cross-site request "
                    "forgery against state-changing endpoints."
                ),
                remediation=(
                    f'Set SameSite explicitly on "{cookie.name}" — Lax is a sensible '
                    "default, Strict for cookies that never need to survive a cross-site "
                    "navigation."
                ),
            )
        )
    elif cookie.same_site.lower() == "none" and not cookie.secure:
        # SameSite=None without Secure is rejected outright by browsers, so the
        # cookie silently fails to be set. That is a concrete defect, not advice.
        findings.append(
            FindingData(
                code="cookie_samesite_none_without_secure",
                title="Cookie uses SameSite=None without Secure",
                category=FindingCategory.COOKIE,
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                description=(
                    f"{scope} sets SameSite=None but not Secure. Browsers reject this "
                    "combination, so the cookie is likely not being stored at all."
                ),
                evidence=f"{scope} sets SameSite=None and does not include Secure.",
                impact=(
                    "The cookie is dropped by current browsers, which usually breaks the "
                    "feature relying on it. If a client did accept it, the cookie would be "
                    "sent cross-site over insecure connections."
                ),
                remediation=(
                    "Add the Secure attribute alongside SameSite=None, or use SameSite=Lax "
                    "if the cookie does not need to be sent cross-site."
                ),
            )
        )

    return findings
