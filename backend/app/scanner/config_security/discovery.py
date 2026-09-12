"""Bounded candidate paths, and how to read what comes back.

**These lists are constants, and that is the security property.** There is no
wordlist, no generator, no permutation and no recursion anywhere in this module.
A scanner that walks a dictionary against somebody's server is a brute-forcer
wearing a different name — it is loud, it fills their logs, and it is the exact
behaviour that gets scanning traffic blocked. Every path below is here because
it is a conventional location that a misconfigured deployment actually serves,
and the whole set is smaller than a hundred entries.

Backup variants are the one derived case, and they derive from files the scan
*already found*, three suffixes each, capped for the whole scan. `/config.json`
becoming `/config.json.bak` is a check; `/a.bak`, `/b.bak`, `/c.bak` … is
enumeration, and the difference is that the first starts from evidence.

Reading the response is the other half. A target that answers every unknown path
with a 200 and a friendly HTML page — a single-page application's catch-all
route, most commonly — will otherwise "expose" every candidate in the list.
`classify` exists to refuse that: a candidate counts as exposed only when the
response looks like the thing that was asked for.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence

from app.scanner.config_security.types import (
    AccessVisibility,
    CandidateKind,
    CandidateObservation,
    CandidateOutcome,
)

# --------------------------------------------------------------------------- #
# The lists. Fixed, small, and never generated.
# --------------------------------------------------------------------------- #

#: Administrative interfaces. Reaching one is not a finding on its own — see
#: `visibility`. Plenty of applications serve a login page at /admin, which is
#: exactly what should happen.
ADMIN_CANDIDATES: tuple[str, ...] = (
    "/admin",
    "/admin/",
    "/administrator",
    "/wp-admin/",
    "/admin/login",
    "/manage",
)

#: Management and operations surfaces. Spring Boot Actuator dominates this list
#: because it is the one that most often ships open by accident.
MANAGEMENT_CANDIDATES: tuple[str, ...] = (
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/management",
    "/management/health",
)

#: Health and metrics. Recorded for inventory; almost never a finding. A
#: {"status":"UP"} response is a correctly built health check.
HEALTH_CANDIDATES: tuple[str, ...] = (
    "/health",
    "/healthz",
    "/readyz",
    "/livez",
    "/metrics",
    "/status",
)

#: Debug and diagnostic surfaces.
DEBUG_CANDIDATES: tuple[str, ...] = (
    "/debug",
    "/debug/",
    "/debug/vars",
    "/__debug__/",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/trace",
)

#: Deployment files that should never be under a web root. `.env` and
#: `.git/HEAD` are the two that matter most and the two checked first.
SENSITIVE_FILE_CANDIDATES: tuple[str, ...] = (
    "/.env",
    "/.env.local",
    "/.env.production",
    # /.git/HEAD is deliberately absent: REPOSITORY_CANDIDATES owns it, and
    # listing it twice would spend two requests from the budget on one path.
    "/.htaccess",
    "/web.config",
    "/config.json",
    "/appsettings.json",
    "/docker-compose.yml",
    "/Dockerfile",
    "/composer.json",
    "/package.json",
    "/.npmrc",
    "/.dockerignore",
    "/robots.txt",
)

#: Repository metadata. Exactly one path, deliberately.
#:
#: `/.git/HEAD` is a 20-byte file that proves the directory is served. That is
#: the entire finding. Fetching `/.git/config`, an object, a ref or an index
#: would start reconstructing the repository — which is the attack this check
#: exists to warn about, not something to perform in order to warn about it.
REPOSITORY_CANDIDATES: tuple[str, ...] = ("/.git/HEAD",)

#: Default and sample content shipped by servers and frameworks.
SAMPLE_CANDIDATES: tuple[str, ...] = (
    "/test.html",
    "/example.html",
    "/sample.html",
    "/index.html.bak",
    "/welcome.html",
)

#: Suffixes appended to a file the scan already found. Three, and no more.
BACKUP_SUFFIXES: tuple[str, ...] = (".bak", ".old", "~", ".backup", ".save")

#: File extensions worth deriving a backup candidate for. A backup of an image
#: is not interesting; a backup of a config file is the point.
_BACKUP_WORTHY = (".json", ".yml", ".yaml", ".xml", ".config", ".ini", ".conf", ".php")


def candidates_for(kind: CandidateKind) -> tuple[str, ...]:
    """The fixed list for one kind."""
    return {
        CandidateKind.ADMIN: ADMIN_CANDIDATES,
        CandidateKind.MANAGEMENT: MANAGEMENT_CANDIDATES,
        CandidateKind.HEALTH: HEALTH_CANDIDATES,
        CandidateKind.DEBUG: DEBUG_CANDIDATES,
        CandidateKind.SENSITIVE_FILE: SENSITIVE_FILE_CANDIDATES,
        CandidateKind.REPOSITORY: REPOSITORY_CANDIDATES,
        CandidateKind.SAMPLE: SAMPLE_CANDIDATES,
    }.get(kind, ())


def backup_variants(path: str, *, limit: int = 3) -> tuple[str, ...]:
    """Backup spellings of a path the scan already discovered.

    Derived, never invented: the input must be a real path from this scan. Only
    configuration-shaped files qualify, and only `limit` suffixes are produced,
    so this cannot become a wordlist by increments.
    """
    lowered = path.lower()
    if not any(lowered.endswith(ext) for ext in _BACKUP_WORTHY):
        return ()
    return tuple(f"{path}{suffix}" for suffix in BACKUP_SUFFIXES[:limit])


# --------------------------------------------------------------------------- #
# Reading the response
# --------------------------------------------------------------------------- #

#: Media types that mean "the server handed back a page", which for a candidate
#: like `/.env` means a catch-all route answered rather than the file existing.
_HTML_TYPES = ("text/html", "application/xhtml+xml")

#: A `.env` file is `KEY=value` lines. This confirms the *shape* without keeping
#: anything: the match object is discarded and only a boolean leaves the module.
_ENV_SHAPE = re.compile(rb"^\s*(?:#[^\n]*\n)*\s*[A-Z_][A-Z0-9_]*\s*=", re.MULTILINE)

#: `/.git/HEAD` is one line: a ref pointer or a bare commit hash.
_GIT_HEAD_SHAPE = re.compile(rb"^\s*(?:ref:\s*refs/|[0-9a-f]{40}\b)")

#: A JSON or YAML document, by first non-space character.
_STRUCTURED_START = (b"{", b"[", b"---")


def _media_type(content_type: str | None) -> str | None:
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower() or None


def _looks_like_page(media_type: str | None) -> bool:
    return bool(media_type) and media_type in _HTML_TYPES


def body_matches_candidate(path: str, body: bytes) -> bool:
    """Whether the body is plausibly the file that was requested.

    The guard against a catch-all route. A single-page application answers
    `/.env` with its shell HTML and a 200; without this, every candidate in the
    list would be reported as exposed on every SPA in existence.

    The body is examined and dropped. Nothing read here is returned, stored or
    reported — the result is one boolean.
    """
    if not body:
        return False
    head = body[:2048]
    lowered = path.lower()

    if lowered.endswith((".env", ".env.local", ".env.production")):
        return bool(_ENV_SHAPE.search(head))
    if lowered.endswith("/.git/head"):
        return bool(_GIT_HEAD_SHAPE.match(head.lstrip()))
    if lowered.endswith((".json", ".yml", ".yaml")):
        return head.lstrip().startswith(_STRUCTURED_START)
    if lowered.endswith((".config", ".xml")):
        return head.lstrip().startswith(b"<")
    if lowered.endswith("/.htaccess"):
        return b"<" not in head[:64]
    if lowered.endswith("robots.txt"):
        return b"user-agent" in head.lower() or b"disallow" in head.lower()
    return True


def classify(
    *,
    path: str,
    kind: CandidateKind,
    status_code: int | None,
    headers: Mapping[str, str] | None = None,
    body: bytes = b"",
    authenticated: bool = False,
) -> CandidateObservation:
    """Turn one candidate response into an observation.

    Conservative in both directions. A 404 is `NOT_FOUND`; a 401 or 403 is
    `PROTECTED`, which is the *correct* configuration and never a finding; a 200
    is `EXPOSED` only when the body looks like what was asked for.
    """
    headers = headers or {}
    media_type = _media_type(
        next((v for k, v in headers.items() if k.lower() == "content-type"), None)
    )
    length = _content_length(headers, body)
    signals: list[str] = []

    if status_code is None:
        return CandidateObservation(
            path=path,
            kind=kind,
            outcome=CandidateOutcome.ERROR,
            authenticated=authenticated,
            signals=("request:failed",),
            detail="the request did not complete, which says nothing about the target",
        )

    if status_code in (401, 403):
        return CandidateObservation(
            path=path,
            kind=kind,
            outcome=CandidateOutcome.PROTECTED,
            status_code=status_code,
            media_type=media_type,
            size=length,
            visibility=AccessVisibility.AUTHENTICATED_ONLY,
            authenticated=authenticated,
            signals=(f"status:{status_code}",),
            detail="the target refused the request, which is the correct answer here",
        )

    if status_code == 404 or status_code == 410:
        return CandidateObservation(
            path=path,
            kind=kind,
            outcome=CandidateOutcome.NOT_FOUND,
            status_code=status_code,
            authenticated=authenticated,
            visibility=AccessVisibility.NOT_FOUND,
            signals=(f"status:{status_code}",),
            detail="the target does not serve this path",
        )

    if status_code >= 500 or status_code in (405, 429):
        return CandidateObservation(
            path=path,
            kind=kind,
            outcome=CandidateOutcome.UNKNOWN,
            status_code=status_code,
            authenticated=authenticated,
            signals=(f"status:{status_code}",),
            detail="the response does not establish whether the path is served",
        )

    if not (200 <= status_code < 300):
        return CandidateObservation(
            path=path,
            kind=kind,
            outcome=CandidateOutcome.UNKNOWN,
            status_code=status_code,
            authenticated=authenticated,
            signals=(f"status:{status_code}",),
            detail="an unexpected status; treated as inconclusive",
        )

    signals.append(f"status:{status_code}")

    # A file candidate answered with an HTML page is a routing catch-all, not
    # the file. This is the single most important false-positive guard here.
    file_like = kind in (
        CandidateKind.SENSITIVE_FILE,
        CandidateKind.REPOSITORY,
        CandidateKind.BACKUP,
    )
    if file_like and _looks_like_page(media_type):
        signals.append("body:html-catch-all")
        return CandidateObservation(
            path=path,
            kind=kind,
            outcome=CandidateOutcome.NOT_FOUND,
            status_code=status_code,
            media_type=media_type,
            size=length,
            authenticated=authenticated,
            signals=tuple(signals),
            detail=(
                "an HTML page answered a request for a file, so a catch-all route "
                "replied rather than the file being served"
            ),
        )

    if file_like and body and not body_matches_candidate(path, body):
        signals.append("body:shape-mismatch")
        return CandidateObservation(
            path=path,
            kind=kind,
            outcome=CandidateOutcome.UNKNOWN,
            status_code=status_code,
            media_type=media_type,
            size=length,
            authenticated=authenticated,
            signals=tuple(signals),
            detail="the response did not have the shape of the file requested",
        )

    if file_like and body:
        signals.append("body:shape-match")

    return CandidateObservation(
        path=path,
        kind=kind,
        outcome=CandidateOutcome.EXPOSED,
        status_code=status_code,
        media_type=media_type,
        size=length,
        visibility=(
            AccessVisibility.PUBLICLY_REACHABLE
            if not authenticated
            else AccessVisibility.UNKNOWN
        ),
        authenticated=authenticated,
        signals=tuple(signals),
        detail="the target served this path",
    )


def _content_length(headers: Mapping[str, str], body: bytes) -> int | None:
    for key, value in headers.items():
        if key.lower() == "content-length":
            try:
                return int(value.strip())
            except ValueError:
                break
    return len(body) or None


def visibility(
    anonymous: CandidateObservation | None,
    authenticated: CandidateObservation | None,
) -> AccessVisibility:
    """Who could reach a path, from the identities actually exercised.

    Only what was observed. With no anonymous observation there is nothing to
    conclude, and an admin panel this scan never tried anonymously is `UNKNOWN`
    rather than assumed either way.
    """
    if anonymous is None:
        return AccessVisibility.UNKNOWN
    if anonymous.outcome is CandidateOutcome.NOT_FOUND:
        return AccessVisibility.NOT_FOUND
    if anonymous.outcome is CandidateOutcome.EXPOSED:
        return AccessVisibility.PUBLICLY_REACHABLE
    if anonymous.outcome is CandidateOutcome.PROTECTED:
        if authenticated is not None and authenticated.outcome is CandidateOutcome.EXPOSED:
            return AccessVisibility.AUTHENTICATED_ONLY
        return AccessVisibility.AUTHENTICATED_ONLY
    return AccessVisibility.UNKNOWN


def not_tested(paths: Iterable[str], kind: CandidateKind) -> tuple[CandidateObservation, ...]:
    """Record candidates the budget never reached.

    Coverage honesty: these appear in the report as unchecked, so a scan that
    ran out of budget cannot be read as one that found nothing.
    """
    return tuple(
        CandidateObservation(
            path=path,
            kind=kind,
            outcome=CandidateOutcome.NOT_TESTED,
            detail="not requested: the stage's request budget was reached first",
        )
        for path in paths
    )


def discovered_file_paths(urls: Sequence[str], *, limit: int = 10) -> tuple[str, ...]:
    """Paths from the crawl that are worth deriving a backup candidate for."""
    from urllib.parse import urlsplit

    found: dict[str, None] = {}
    for url in urls:
        try:
            path = urlsplit(url).path
        except ValueError:  # pragma: no cover - urlsplit is lenient
            continue
        if path and any(path.lower().endswith(ext) for ext in _BACKUP_WORTHY):
            found.setdefault(path, None)
        if len(found) >= limit:
            break
    return tuple(found)
