"""Session identifiers in places they should not be.

A session identifier in a URL leaks through browser history, the `Referer`
header, server access logs, proxy logs, bookmarks and anything a user pastes
into a chat window. OWASP treats exposed session variables as a session-
management risk in its own right, because a leaked identifier can be replayed.

This module finds them **by name**. It never reads the value: the crawler
already stores canonical URLs with query values stripped, and nothing here
recovers them. A finding says `sessionid` appeared as a query parameter on a
given endpoint, and stops there.

The hard part is restraint. `id` is the most common parameter name on the web
and means nothing; `token` might be a pagination cursor; `key` might be a sort
key. So the table below is narrow, whole-segment matched, and has an explicit
exclusion list — a scanner that flags every `id` is a scanner nobody reads.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlsplit

from app.scanner.session_security.types import (
    ExposureLocation,
    ParameterClass,
    UrlExposure,
)

#: Parameter names that are session identifiers. Narrow on purpose: each of
#: these exists to carry a session handle and nothing else.
_SESSION_PARAMETERS = frozenset(
    {
        "sessionid",
        "session_id",
        "session",
        "jsessionid",
        "phpsessid",
        "aspsessionid",
        "sid",
        "sessid",
        "session_key",
        "sessionkey",
        "connect_sid",
    }
)

#: Credential-adjacent names. Weaker than the above — a `token` in a URL is
#: worth reporting, but it may be a password-reset token rather than a session,
#: and the finding says so rather than guessing.
_SECURITY_PARAMETERS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "auth",
        "auth_token",
        "authorization",
        "apikey",
        "api_key",
        "jwt",
        "bearer",
        "password",
        "passwd",
        "secret",
        "signature",
        "sig",
        "reset_token",
        "activation_token",
        "invite_token",
    }
)

#: Names that look sensitive and are not. Checked first.
#:
#: `csrf_token` in a URL is a design smell rather than a session leak, and
#: `token_type` is the literal string "Bearer" — reporting either as an exposed
#: session identifier would be wrong.
_EXCLUDED = frozenset(
    {
        "id",
        "uid",
        "user_id",
        "userid",
        "item_id",
        "order_id",
        "product_id",
        "page",
        "page_token",
        "next_token",
        "cursor",
        "token_type",
        "csrf_token",
        "csrftoken",
        "xsrf_token",
        "authenticity_token",
        "captcha",
        "state",
        "nonce",
        "code_challenge",
    }
)

_SPLIT = re.compile(r"[^a-z0-9]+")

#: `/page;jsessionid=...` — the servlet convention for URL-rewritten sessions,
#: used when a client refuses cookies. Matched on the parameter name only.
_PATH_PARAMETER = re.compile(r";\s*([A-Za-z0-9_.-]+)\s*=", re.IGNORECASE)


def normalize(name: str) -> str:
    """Reduce a parameter name to a comparable form."""
    return _SPLIT.sub("_", (name or "").strip().lower()).strip("_")


def classify_parameter(name: str) -> ParameterClass:
    """What a parameter name suggests it carries. Pure, and never a value."""
    normalized = normalize(name)
    if not normalized:
        return ParameterClass.UNKNOWN
    if normalized in _EXCLUDED:
        return ParameterClass.ORDINARY
    if normalized in _SESSION_PARAMETERS:
        return ParameterClass.SESSION_LIKE
    if normalized in _SECURITY_PARAMETERS:
        return ParameterClass.SECURITY_SENSITIVE
    return ParameterClass.ORDINARY


def _exposure(
    *,
    url: str,
    name: str,
    location: ExposureLocation,
    classification: ParameterClass,
    authenticated: bool,
    over_https: bool,
) -> UrlExposure:
    if classification is ParameterClass.SESSION_LIKE:
        detail = (
            "a session identifier in a URL travels into browser history, the "
            "Referer header, and server and proxy logs"
        )
    else:
        detail = (
            "a credential-like parameter in a URL travels into browser history, "
            "the Referer header, and server and proxy logs"
        )
    return UrlExposure(
        url=url,
        name=name,
        location=location,
        classification=classification,
        authenticated=authenticated,
        over_https=over_https,
        detail=detail,
    )


def analyze_url(
    url: str,
    *,
    parameter_names: Iterable[str] = (),
    authenticated: bool = False,
) -> tuple[UrlExposure, ...]:
    """Session-like identifiers in one URL.

    Takes the parameter names the crawler recorded as well as parsing the URL,
    because a stored canonical URL keeps names and drops values — both paths
    lead to the same place, and neither yields a value.
    """
    try:
        parts = urlsplit(url)
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return ()

    over_https = parts.scheme.lower() == "https"
    found: dict[tuple[str, str], UrlExposure] = {}

    names = list(parameter_names)
    try:
        names.extend(name for name, _ in parse_qsl(parts.query, keep_blank_values=True))
    except ValueError:  # pragma: no cover
        pass

    for name in names:
        classification = classify_parameter(name)
        if classification in (ParameterClass.ORDINARY, ParameterClass.UNKNOWN):
            continue
        exposure = _exposure(
            url=url,
            name=name,
            location=ExposureLocation.QUERY_PARAMETER,
            classification=classification,
            authenticated=authenticated,
            over_https=over_https,
        )
        found[(name, exposure.location.value)] = exposure

    # `/page;jsessionid=...`, the servlet URL-rewriting convention.
    for match in _PATH_PARAMETER.finditer(parts.path or ""):
        name = match.group(1)
        classification = classify_parameter(name)
        if classification in (ParameterClass.ORDINARY, ParameterClass.UNKNOWN):
            continue
        exposure = _exposure(
            url=url,
            name=name,
            location=ExposureLocation.PATH_PARAMETER,
            classification=classification,
            authenticated=authenticated,
            over_https=over_https,
        )
        found[(name, exposure.location.value)] = exposure

    return tuple(found.values())


def analyze_location_header(
    url: str, location: str | None, *, authenticated: bool = False
) -> tuple[UrlExposure, ...]:
    """Session-like identifiers in a redirect target.

    A redirect that carries a session identifier is worse than a link that does:
    the browser follows it automatically, and the identifier lands in history
    without anybody choosing to go there.
    """
    if not location:
        return ()

    exposures = analyze_url(location, authenticated=authenticated)
    return tuple(
        UrlExposure(
            url=url,
            name=exposure.name,
            location=ExposureLocation.LOCATION_HEADER,
            classification=exposure.classification,
            authenticated=exposure.authenticated,
            over_https=exposure.over_https,
            detail=(
                "the redirect target carries the identifier, so a browser puts it "
                "in history without the user choosing to go there"
            ),
        )
        for exposure in exposures
    )


def analyze_json_fields(
    url: str, field_names: Iterable[str], *, authenticated: bool = False
) -> tuple[UrlExposure, ...]:
    """Session-like field names in a JSON response body.

    Names only — the Phase 13 summary never kept a value. A response containing
    a field called `session_id` is worth a reviewer's attention; what was in it
    is not something this scanner has.
    """
    found: dict[str, UrlExposure] = {}
    for name in field_names:
        classification = classify_parameter(name)
        if classification is not ParameterClass.SESSION_LIKE:
            # Credential-adjacent field names in a JSON body are Phase 14's
            # subject; duplicating them here would report one thing twice.
            continue
        found[name] = UrlExposure(
            url=url,
            name=name,
            location=ExposureLocation.JSON_FIELD,
            classification=classification,
            authenticated=authenticated,
            over_https=url.lower().startswith("https"),
            detail="a session identifier appears as a field in an API response",
        )
    return tuple(found.values())
