"""Deciding what a cookie is for, and how sure we are.

Phase 3 already parses `Set-Cookie` into a `CookieInfo` with no value in it, and
already reports missing `Secure`, `HttpOnly` and `SameSite`. **None of that is
repeated here.** This module answers a different question — is this cookie
carrying session state? — so that later analysis can reason about the cookies
that matter and ignore the ones that do not.

The distinction earns its keep in the exclusions. An analytics cookie that
persists for two years is not a session cookie; a locale preference is not a
credential. Classifying them as session state would put security weight on every
site with a tracking tag, so they are recognised and ruled out by name before
anything else runs.

Pure: names and attributes in, a classification out. No network, no values.
"""

from __future__ import annotations

import re

from app.scanner.security.cookies import CookieInfo
from app.scanner.session_security.types import (
    CookieRole,
    SessionConfidence,
    SessionCookie,
)

# --------------------------------------------------------------------------- #
# Exclusions run first
# --------------------------------------------------------------------------- #

#: Analytics and tag-manager cookies. These persist, they are set on every page,
#: and they are not session state. Matched before anything else so a name like
#: `_gat_UA-1234` never reaches the session rules.
_ANALYTICS_EXACT = frozenset(
    {
        "_ga",
        "_gid",
        "_gat",
        "_gcl_au",
        "_fbp",
        "_fbc",
        "_hjid",
        "_hjsessionuser",
        "_clck",
        "_clsk",
        "ajs_anonymous_id",
        "ajs_user_id",
        "amplitude_id",
        "mp_mixpanel",
        "optimizelyenduserid",
        "intercom-id",
        "__utma",
        "__utmb",
        "__utmc",
        "__utmz",
    }
)

_ANALYTICS_PREFIXES = ("_ga", "_gat", "_hj", "_utm", "__utm", "ajs_", "amplitude_", "mp_")

#: Presentation and consent state. Not credentials, however long they last.
_PREFERENCE_EXACT = frozenset(
    {
        "locale",
        "lang",
        "language",
        "theme",
        "timezone",
        "tz",
        "currency",
        "country",
        "consent",
        "cookie_consent",
        "cookieconsent_status",
        "gdpr",
        "sidebar_state",
        "font_size",
        "color_scheme",
        "view_mode",
    }
)

_PREFERENCE_FRAGMENTS = ("consent", "preference", "locale", "theme", "timezone")

# --------------------------------------------------------------------------- #
# Session and authentication naming
# --------------------------------------------------------------------------- #

#: Framework session cookies. Unambiguous: these names exist for one purpose.
_FRAMEWORK_SESSION = frozenset(
    {
        "jsessionid",
        "phpsessid",
        "asp.net_sessionid",
        "aspsessionid",
        "connect.sid",
        "laravel_session",
        "ci_session",
        "symfony",
        "express.sid",
        "_rails_session",
        "sessionid",
        "session_id",
        "_session_id",
        "sid",
    }
)

#: Authentication material rather than a session handle. The distinction is
#: worth keeping: an access token and a session id fail differently.
_AUTHENTICATION_EXACT = frozenset(
    {
        "auth",
        "auth_token",
        "authtoken",
        "access_token",
        "refresh_token",
        "id_token",
        "bearer",
        "jwt",
        "token",
        "remember_token",
        "remember_me",
        "identity",
        "credential",
        "login",
    }
)

#: Words that mark a session cookie wherever they appear, as whole segments.
_SESSION_FRAGMENTS = ("session", "sess", "sessid")

#: Whole segments that only mean something on their own — so `sidebar_state`
#: does not match `sid`, and `tokenizer` does not match `token`.
_SESSION_TOKENS = frozenset({"sid", "sess", "session"})
_AUTH_TOKENS = frozenset({"auth", "token", "jwt", "bearer", "identity", "login"})

#: CSRF tokens are session-adjacent but are not session state. They are meant to
#: be readable by the page, so reporting a missing HttpOnly on one would be
#: wrong — Phase 3 owns that judgement, and this classifier keeps them separate.
_CSRF_NAMES = frozenset(
    {"csrftoken", "csrf_token", "xsrf-token", "xsrf_token", "_csrf", "csrf"}
)

_SPLIT = re.compile(r"[^a-z0-9]+")


def _segments(name: str) -> set[str]:
    return {segment for segment in _SPLIT.split(name.lower()) if segment}


def classify_name(name: str) -> tuple[CookieRole, SessionConfidence, tuple[str, ...]]:
    """Classify a cookie by name alone. Pure and fully testable.

    Returns the role, the confidence, and the signals that produced them so a
    reader can see why rather than being told.
    """
    lowered = name.strip().lower()
    if not lowered:
        return (CookieRole.UNKNOWN, SessionConfidence.UNKNOWN, ())

    segments = _segments(lowered)

    # --- exclusions, before anything else ------------------------------- #
    if lowered in _ANALYTICS_EXACT or lowered.startswith(_ANALYTICS_PREFIXES):
        return (CookieRole.ANALYTICS, SessionConfidence.UNKNOWN, ("name:analytics",))

    if lowered in _PREFERENCE_EXACT or any(
        fragment in lowered for fragment in _PREFERENCE_FRAGMENTS
    ):
        return (CookieRole.PREFERENCE, SessionConfidence.UNKNOWN, ("name:preference",))

    if lowered in _CSRF_NAMES or "csrf" in lowered or "xsrf" in lowered:
        # Session-adjacent, but not session state and not a credential.
        return (CookieRole.UNKNOWN, SessionConfidence.UNKNOWN, ("name:csrf-token",))

    # --- unambiguous framework session cookies --------------------------- #
    if lowered in _FRAMEWORK_SESSION:
        return (
            CookieRole.SESSION,
            SessionConfidence.HIGH_CONFIDENCE_SESSION,
            ("name:framework-session",),
        )

    # --- authentication material ----------------------------------------- #
    if lowered in _AUTHENTICATION_EXACT:
        return (
            CookieRole.AUTHENTICATION,
            SessionConfidence.HIGH_CONFIDENCE_SESSION,
            ("name:authentication",),
        )

    # --- session words as whole segments ---------------------------------- #
    if segments & _SESSION_TOKENS or any(
        fragment in lowered for fragment in _SESSION_FRAGMENTS
    ):
        return (
            CookieRole.SESSION,
            SessionConfidence.LIKELY_SESSION,
            ("name:session-word",),
        )

    if segments & _AUTH_TOKENS:
        return (
            CookieRole.AUTHENTICATION,
            SessionConfidence.LIKELY_SESSION,
            ("name:auth-word",),
        )

    return (CookieRole.UNKNOWN, SessionConfidence.UNKNOWN, ())


def classify_cookie(
    cookie: CookieInfo,
    *,
    over_https: bool = True,
    set_on: str | None = None,
    authenticated_scan: bool = False,
) -> SessionCookie:
    """Classify one parsed cookie, using its attributes to corroborate the name.

    The name does most of the work, but attributes move a borderline case:
    `HttpOnly` with `SameSite` set is how a session cookie is configured and how
    an analytics cookie usually is not, so a suggestive name backed by both is
    promoted. Being set during an authenticated scan is corroboration too — the
    request carried a credential, and this came back with it.

    Attributes are read, never re-judged. Whether `Secure` is missing is a
    Phase 3 finding and stays one.
    """
    role, confidence, signals = classify_name(cookie.name)
    reasons = list(signals)

    if confidence is SessionConfidence.LIKELY_SESSION:
        hardened = cookie.http_only and bool(cookie.same_site)
        if hardened:
            reasons.append("attributes:hardened")
            confidence = SessionConfidence.HIGH_CONFIDENCE_SESSION
        elif authenticated_scan:
            reasons.append("context:authenticated-scan")

    return SessionCookie(
        name=cookie.name,
        role=role,
        confidence=confidence,
        secure=cookie.secure,
        http_only=cookie.http_only,
        same_site=cookie.same_site,
        max_age=cookie.max_age,
        has_expires=cookie.has_expires,
        over_https=over_https,
        set_on=set_on,
        signals=tuple(reasons),
    )


def weakest_same_site(cookies: tuple[SessionCookie, ...]) -> str | None:
    """The least protective SameSite across the session cookies.

    CSRF analysis needs the weakest, not the strictest: if any session cookie
    the browser will attach is `None`, the browser's own defence does not apply
    to a cross-site request, whatever the others say. A cookie with no SameSite
    at all is treated as `Lax`, which is what modern browsers default to.
    """
    session_cookies = [cookie for cookie in cookies if cookie.session_like]
    if not session_cookies:
        return None

    order = {"none": 0, "lax": 1, "strict": 2}
    weakest: str | None = None
    weakest_rank = 99
    for cookie in session_cookies:
        value = (cookie.same_site or "lax").strip().lower()
        rank = order.get(value, 1)
        if rank < weakest_rank:
            weakest_rank = rank
            weakest = value
    return weakest
