"""Configuration weaknesses readable from headers the scan already received.

Three analyzers, all pure, all working from response headers that
`CapturedResponse` already retains. No request is sent to test any of them —
in particular, **no `Origin` header is forged to probe CORS**, because that is
active testing and this phase is read-only.

The restraint is the design. It is easy to write a CORS checker that flags every
API without `Access-Control-Allow-Origin`; the result is a report full of
findings against server-to-server APIs that have no business supporting browsers
at all. Absence of CORS is not a weakness, and neither is a `Server` header that
names software without a version.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from app.scanner.api_security.types import (
    CorsObservation,
    CorsVerdict,
    DisclosureObservation,
    InventoryObservation,
)

# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #

_ALLOW_ORIGIN = "access-control-allow-origin"
_ALLOW_CREDENTIALS = "access-control-allow-credentials"
_VARY = "vary"


def _header(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive header lookup that tolerates any mapping shape."""
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def analyze_cors(url: str, headers: Mapping[str, str]) -> CorsObservation:
    """Judge one endpoint's CORS headers.

    The dangerous combination is a permissive origin *together with*
    credentials: that is what turns a cross-origin read into an authenticated
    one. A wildcard on its own is how public APIs are supposed to look, and
    saying otherwise would be wrong on most of the internet.
    """
    allow_origin = _header(headers, _ALLOW_ORIGIN)
    if allow_origin is None:
        return CorsObservation(
            url=url,
            verdict=CorsVerdict.ABSENT,
            detail="no CORS headers, which is not a weakness on its own",
        )

    origin = allow_origin.strip()
    credentials = (_header(headers, _ALLOW_CREDENTIALS) or "").strip().lower() == "true"
    vary = _header(headers, _VARY) or ""
    vary_origin = "origin" in vary.lower()

    if origin == "*" and credentials:
        return CorsObservation(
            url=url,
            verdict=CorsVerdict.WILDCARD_WITH_CREDENTIALS,
            allow_origin=origin,
            allow_credentials=True,
            vary_origin=vary_origin,
            detail=(
                "any origin is allowed and credentials are permitted; browsers "
                "refuse this combination, so shipping it means the policy was "
                "never exercised"
            ),
        )

    if origin.lower() == "null" and credentials:
        return CorsObservation(
            url=url,
            verdict=CorsVerdict.NULL_ORIGIN_ALLOWED,
            allow_origin=origin,
            allow_credentials=True,
            vary_origin=vary_origin,
            detail=(
                "the null origin is allowed with credentials, and a sandboxed "
                "document can present that origin"
            ),
        )

    if origin != "*" and credentials and not vary_origin:
        return CorsObservation(
            url=url,
            verdict=CorsVerdict.CREDENTIALED_WITHOUT_VARY,
            allow_origin=origin,
            allow_credentials=True,
            vary_origin=False,
            detail=(
                "a specific origin is allowed with credentials but the response "
                "does not vary on Origin, so a shared cache can serve one "
                "origin's credentialed response to another"
            ),
        )

    return CorsObservation(
        url=url,
        verdict=CorsVerdict.SAFE,
        allow_origin=origin,
        allow_credentials=credentials,
        vary_origin=vary_origin,
        detail="CORS is configured and nothing about it is unsafe on its face",
    )


# --------------------------------------------------------------------------- #
# Information disclosure in headers
# --------------------------------------------------------------------------- #

#: Headers whose value names the software running the service. A bare product
#: name is ordinary; a **version** is what tells an attacker which advisories
#: to read, so only versioned values are reported.
_BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

#: Headers that only exist when diagnostics were left on. Any value is notable.
_DEBUG_HEADERS = (
    "x-debug",
    "x-debug-token",
    "x-debug-token-link",
    "x-runtime",
    "x-drupal-cache",
    "x-generator",
    "x-symfony-profiler",
)

#: Never recorded, whatever else is true. These carry credentials, and a
#: disclosure finding must not become the disclosure.
_FORBIDDEN_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie", "www-authenticate"}
)

_VERSION = re.compile(r"\d+\.\d+")

#: Bounded, so a pathological header cannot put a kilobyte into a finding.
_MAX_VALUE = 120


def analyze_disclosure(
    url: str, headers: Mapping[str, str]
) -> tuple[DisclosureObservation, ...]:
    """Headers that name internal software or leave diagnostics switched on."""
    observations: list[DisclosureObservation] = []

    for key, value in headers.items():
        name = key.lower()
        if name in _FORBIDDEN_HEADERS:
            # Structurally impossible to report: these are credentials.
            continue

        text = (value or "").strip()[:_MAX_VALUE]
        if not text:
            continue

        if name in _BANNER_HEADERS:
            if not _VERSION.search(text):
                # `Server: nginx` tells an attacker nothing they could not
                # guess. `Server: nginx/1.18.0` tells them which CVEs to try.
                continue
            observations.append(
                DisclosureObservation(
                    url=url,
                    header=key,
                    value=text,
                    detail="the header names the software and its version",
                )
            )
        elif name in _DEBUG_HEADERS:
            observations.append(
                DisclosureObservation(
                    url=url,
                    header=key,
                    value=text,
                    detail="a diagnostic header is present on a client-facing response",
                )
            )

    return tuple(observations)


# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #

_VERSION_SEGMENT = re.compile(r"^v(\d+)(?:\.\d+)*$", re.IGNORECASE)


def version_of(path: str) -> str | None:
    """The API version segment of a path, if it has one. `/api/v2/x` -> `v2`."""
    for segment in path.split("/"):
        if segment and _VERSION_SEGMENT.match(segment):
            return segment.lower()
    return None


def analyze_inventory(
    *,
    observed: tuple[str, ...],
    documented_only: tuple[str, ...],
    undocumented: tuple[str, ...],
) -> tuple[InventoryObservation, ...]:
    """Notable facts about the API inventory itself.

    Deliberately informational. Two versions coexisting is what a migration
    looks like from the outside, and calling that a vulnerability would be
    guessing at a roadmap. It is recorded because knowing which versions are
    live is genuinely useful — OWASP treats inventory management as an API
    concern in its own right — and because a reviewer can tell in seconds what a
    scanner never could.
    """
    observations: list[InventoryObservation] = []

    versions = sorted({v for path in observed if (v := version_of(path))})
    if len(versions) > 1:
        observations.append(
            InventoryObservation(
                kind="MULTIPLE_VERSIONS",
                detail=(
                    f"{len(versions)} API versions are live at the same time. That is "
                    "normal during a migration; confirm the older one is still "
                    "intended to be reachable."
                ),
                paths=tuple(
                    sorted(path for path in observed if version_of(path) in versions)
                )[:20],
                versions=tuple(versions),
            )
        )

    if documented_only:
        observations.append(
            InventoryObservation(
                kind="DOCUMENTED_NOT_OBSERVED",
                detail=(
                    "operations appear in a published specification but were not "
                    "reached by the scan. They may be retired, restricted, or "
                    "simply not linked — the documentation and the service "
                    "disagree either way."
                ),
                paths=tuple(sorted(documented_only))[:20],
            )
        )

    if undocumented:
        observations.append(
            InventoryObservation(
                kind="OBSERVED_NOT_DOCUMENTED",
                detail=(
                    "operations answered requests but appear in no published "
                    "specification, so they are outside whatever review the "
                    "documented surface receives."
                ),
                paths=tuple(sorted(undocumented))[:20],
            )
        )

    return tuple(observations)
