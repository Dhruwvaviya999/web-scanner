"""GraphQL presence detection.

**Detection only.** This module answers one question — is there a GraphQL
endpoint here? — and stops. It does not run introspection, does not send a
query, does not send a mutation, and does not guess field names. Those are
exploitation techniques and they are out of scope for this phase; a report that
says `introspection_tested: false` is telling the truth about what was done.

Everything below therefore works from evidence the scan already has: the path a
crawler reached, the media type a response declared, and what a specification
said. No request is issued by this module at all.
"""

from __future__ import annotations

from typing import Any

from app.scanner.api.classifier import looks_like_graphql_path, media_kind, path_of
from app.scanner.api.types import ApiMediaKind, GraphQlDetection

#: Phrases a GraphQL server returns when it is asked for something it cannot
#: serve — a GET on a POST-only endpoint, or a request with no query. Matched
#: only in a body the scan already had; nothing is sent to provoke one.
_RESPONSE_MARKERS = (
    "must provide query string",
    "must provide a query string",
    "graphql",
    "query is required",
    "getting started with graphql",
)


def detect_from_path(url: str) -> tuple[bool, tuple[str, ...]]:
    """Whether a URL is at the conventional GraphQL location."""
    if looks_like_graphql_path(path_of(url)):
        return True, ("path:graphql",)
    return False, ()


def detect_from_content_type(content_type: str | None) -> tuple[bool, tuple[str, ...]]:
    """Whether a response declared a GraphQL media type.

    `application/graphql-response+json` is only ever sent by a GraphQL server,
    so this is conclusive on its own.
    """
    if media_kind(content_type) is ApiMediaKind.GRAPHQL:
        return True, ("response:graphql-media-type",)
    return False, ()


def detect_from_body(body: str | bytes | None) -> tuple[bool, tuple[str, ...]]:
    """Whether a body the scan already had reads like a GraphQL server.

    Bounded and case-insensitive, over a prefix only. Nothing from the body is
    retained — the return value is a boolean and a fixed marker name.
    """
    if not body:
        return False, ()
    if isinstance(body, bytes):
        text = body[:4096].decode("utf-8", "replace")
    else:
        text = body[:4096]
    lowered = text.lower()

    for marker in _RESPONSE_MARKERS:
        if marker in lowered:
            return True, ("body:graphql-marker",)
    # A GraphQL error envelope: a top-level `errors` array alongside `data`.
    if '"errors"' in lowered and ('"data"' in lowered or '"locations"' in lowered):
        return True, ("body:graphql-error-envelope",)
    return False, ()


def detect_from_specification(document: Any) -> tuple[bool, tuple[str, ...]]:
    """Whether a parsed specification points at a GraphQL endpoint."""
    if not isinstance(document, dict):
        return False, ()
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return False, ()
    for raw_path in paths:
        if isinstance(raw_path, str) and looks_like_graphql_path(raw_path):
            return True, ("spec:graphql-path",)
    return False, ()


def detect(
    *,
    url: str,
    content_type: str | None = None,
    body: str | bytes | None = None,
    status_code: int | None = None,
) -> GraphQlDetection:
    """Combine every available signal for one endpoint.

    A path convention alone is enough to record a detection — `/graphql` is not
    a name that happens by accident — but the indicators are listed so a
    reviewer can see whether the server itself confirmed it or only the URL did.
    """
    indicators: list[str] = []

    for detected, found in (
        detect_from_path(url),
        detect_from_content_type(content_type),
        detect_from_body(body),
    ):
        if detected:
            indicators.extend(found)

    if not indicators:
        return GraphQlDetection()

    return GraphQlDetection(
        detected=True,
        url=url,
        path=path_of(url),
        indicators=tuple(dict.fromkeys(indicators)),
        # Always false, and stated explicitly. This phase never runs
        # introspection, so a reader is never left to assume it did.
        introspection_tested=False,
    )
