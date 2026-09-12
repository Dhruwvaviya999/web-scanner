"""Aggregating session cookies across a scan, and what they say about expiry.

Phase 3 assesses each `Set-Cookie` header on its own and reports missing
`Secure`, `HttpOnly` and `SameSite`. **Those findings are not repeated here.**
This module answers questions that only make sense across the whole scan:

* which cookies, out of everything the target set, carry session state;
* whether any of them reached the network without TLS protection;
* what — if anything — is known about when the session expires.

The last one is where restraint matters most. A session cookie with no
`Max-Age` and no `Expires` is a *browser-session* cookie: it lasts until the
browser closes. That says nothing whatsoever about whether the server expires
the session, which is the thing that actually matters and is invisible from
outside. So the verdict is `BROWSER_SESSION` or `UNKNOWN` — never "the session
never expires".
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from app.scanner.security.cookies import CookieInfo, parse_set_cookie_headers
from app.scanner.session_security.session_classifier import classify_cookie
from app.scanner.session_security.types import (
    JwtObservation,
    SessionCookie,
    TimeoutEvidence,
    TimeoutObservation,
)


def collect_cookies(
    responses: Iterable[tuple[str, bool, Sequence[str]]],
    *,
    authenticated_scan: bool = False,
    limit: int = 100,
) -> tuple[SessionCookie, ...]:
    """Classify every cookie the scan saw set, deduplicated by name.

    Takes `(url, is_https, set_cookie_headers)` triples rather than captured
    responses, so this stays a pure function over primitives and can be tested
    without constructing a crawl.

    Deduplication keeps the *worst* observation of each name. A cookie set with
    `Secure` on one endpoint and without it on another is exposed, and reporting
    the protected sighting would describe the target more kindly than it is.
    """
    best: dict[str, SessionCookie] = {}

    for url, is_https, headers in responses:
        for cookie in parse_set_cookie_headers(headers):
            classified = classify_cookie(
                cookie,
                over_https=is_https,
                set_on=url,
                authenticated_scan=authenticated_scan,
            )
            key = classified.name.lower()
            existing = best.get(key)
            if existing is None or _is_worse(classified, existing):
                best[key] = classified
            if len(best) >= limit:
                return tuple(best.values())

    return tuple(best.values())


def _is_worse(candidate: SessionCookie, existing: SessionCookie) -> bool:
    """Whether `candidate` is the more exposed sighting of the same cookie."""
    if candidate.transport_exposed and not existing.transport_exposed:
        return True
    if existing.transport_exposed and not candidate.transport_exposed:
        return False
    # Equally exposed: prefer the sighting the classifier is more sure about, so
    # the reported role is the best-supported one.
    ranking = {"HIGH_CONFIDENCE_SESSION": 2, "LIKELY_SESSION": 1, "UNKNOWN": 0}
    return ranking[candidate.confidence.value] > ranking[existing.confidence.value]


def session_cookies(cookies: Sequence[SessionCookie]) -> tuple[SessionCookie, ...]:
    """Only the ones carrying session state. Analytics and preferences drop out."""
    return tuple(cookie for cookie in cookies if cookie.session_like)


def transport_exposed(cookies: Sequence[SessionCookie]) -> tuple[SessionCookie, ...]:
    """Session cookies that can reach the network unprotected, for counting.

    Two distinct causes, same consequence: the response was plain HTTP, or it
    was HTTPS and the cookie had no `Secure` attribute, so a later plaintext
    request to the same host would carry it. Only the first becomes a finding —
    see `plaintext_exposed`.
    """
    return tuple(cookie for cookie in cookies if cookie.transport_exposed)


def plaintext_exposed(cookies: Sequence[SessionCookie]) -> tuple[SessionCookie, ...]:
    """Session cookies set by a plain-HTTP response.

    The only transport case this phase reports. The HTTPS-without-`Secure` case
    is Phase 3's `COOKIE_SECURE_MISSING`, and emitting it again here would put
    the same problem in the report twice under two different rules.
    """
    return tuple(cookie for cookie in cookies if cookie.plaintext)


def infer_timeout(
    cookies: Sequence[SessionCookie],
    jwts: Sequence[JwtObservation] = (),
) -> TimeoutObservation:
    """What can honestly be said about session expiry.

    Ordered by how much each source actually establishes:

    1. A `Max-Age` or `Expires` on a session cookie — the client-side lifetime
       is stated. Still not the server's, but it is a real declaration.
    2. A JWT with an `exp` claim — the token declares its own expiry.
    3. A session cookie with neither — a browser-session cookie. Reported as
       `BROWSER_SESSION`, which is a description, not a criticism.
    4. Nothing session-like at all — `UNKNOWN`.
    """
    relevant = session_cookies(cookies)

    for cookie in relevant:
        if cookie.max_age is not None or cookie.has_expires:
            return TimeoutObservation(
                evidence=TimeoutEvidence.COOKIE_LIFETIME,
                source=cookie.name,
                max_age=cookie.max_age,
                detail=(
                    "the session cookie declares a client-side lifetime; whether the "
                    "server expires the session independently is not observable"
                ),
            )

    for observation in jwts:
        if observation.metadata.has_expiry:
            return TimeoutObservation(
                evidence=TimeoutEvidence.TOKEN_EXPIRY,
                source=observation.name,
                detail=(
                    "a token carries an exp claim, so it declares its own expiry; the "
                    "claim value is not read"
                ),
            )

    if relevant:
        return TimeoutObservation(
            evidence=TimeoutEvidence.BROWSER_SESSION,
            source=relevant[0].name,
            detail=(
                "the session cookie declares no lifetime, so a browser keeps it until "
                "it closes; this says nothing about server-side expiry, which cannot "
                "be observed from outside"
            ),
        )

    return TimeoutObservation(
        evidence=TimeoutEvidence.UNKNOWN,
        detail="no session cookie or expiring token was observed",
    )


def cookie_names(cookies: Sequence[CookieInfo]) -> tuple[str, ...]:
    """Cookie names only. Convenience for callers that need no attributes."""
    return tuple(cookie.name for cookie in cookies)
