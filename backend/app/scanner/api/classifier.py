"""Deciding whether something behaves like an API.

Evidence-based, and in a deliberate order of trust:

1. **What the response was.** `application/json` is the endpoint telling us what
   it is. Nothing outranks that.
2. **What a specification said.** Corroboration from a document the target
   published, which is strong but describes intent rather than behaviour.
3. **What the URL looks like.** `/api/` in a path is a naming convention, and
   naming conventions are wrong all the time.

The third alone is never enough. `/api/about` returning HTML is a web page with
an unfortunate URL; classifying it as an API would put noise into every count
downstream and would make "12 API endpoints" mean nothing. So a path signal
contradicted by an HTML response produces LOW confidence, and LOW is not an API.

Pure functions throughout: content type and path in, classification out. That is
what makes every rule here testable without a network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.scanner.api.types import ApiConfidence, ApiMediaKind

#: Media types that are an API answering. `+json` and `+xml` suffixes are
#: matched structurally, so `application/vnd.example.v2+json` and
#: `application/problem+json` are recognised without listing every vendor type.
_JSON_TYPES = frozenset(
    {"application/json", "application/ld+json", "text/json"}
)
_XML_TYPES = frozenset({"application/xml", "text/xml"})
_FORM_TYPES = frozenset({"application/x-www-form-urlencoded"})
_MULTIPART_TYPES = frozenset({"multipart/form-data"})
_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_GRAPHQL_TYPES = frozenset(
    {"application/graphql", "application/graphql+json", "application/graphql-response+json"}
)

#: Path segments that conventionally introduce an API. Matched as whole
#: segments: `/api/v1/x` matches, `/rapid/x` does not, and `/apiary` does not.
_API_SEGMENTS = frozenset({"api", "apis", "rest", "graphql", "gql", "rpc", "jsonrpc"})

#: A version segment such as `v1` or `v2.1`.
_VERSION_SEGMENT = re.compile(r"^v\d+(\.\d+)*$")


def media_type_of(content_type: str | None) -> str | None:
    """`application/json` out of `application/json; charset=utf-8`."""
    if not content_type:
        return None
    media = content_type.split(";", 1)[0].strip().lower()
    return media or None


def media_kind(content_type: str | None) -> ApiMediaKind:
    """Which family a content type belongs to."""
    media = media_type_of(content_type)
    if media is None:
        return ApiMediaKind.UNKNOWN
    if media in _GRAPHQL_TYPES:
        return ApiMediaKind.GRAPHQL
    if media in _JSON_TYPES or media.endswith("+json"):
        return ApiMediaKind.JSON
    if media in _XML_TYPES or media.endswith("+xml"):
        # `application/xhtml+xml` is a document, not an API payload, and it
        # matches the +xml suffix — so it has to be excluded explicitly.
        return ApiMediaKind.HTML if media in _HTML_TYPES else ApiMediaKind.XML
    if media in _HTML_TYPES:
        return ApiMediaKind.HTML
    if media in _FORM_TYPES:
        return ApiMediaKind.FORM
    if media in _MULTIPART_TYPES:
        return ApiMediaKind.MULTIPART
    return ApiMediaKind.OTHER


#: Media kinds that are an API payload by themselves.
_API_RESPONSE_KINDS = frozenset(
    {ApiMediaKind.JSON, ApiMediaKind.XML, ApiMediaKind.GRAPHQL}
)


def is_api_media_type(content_type: str | None) -> bool:
    """Whether a response media type is, on its own, evidence of an API."""
    return media_kind(content_type) in _API_RESPONSE_KINDS


def path_of(url: str) -> str:
    """The path of a URL, or the value itself when it is already a path."""
    if "://" not in url and url.startswith("/"):
        return url
    try:
        return urlsplit(url).path or "/"
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return "/"


def path_segments(path: str) -> list[str]:
    return [segment for segment in path.split("/") if segment]


def path_looks_like_api(path: str) -> bool:
    """Whether the path uses a conventional API naming pattern.

    A weak signal on its own, and treated as one. Matched on whole segments so
    that `/apiary/blog` — a word that merely starts with "api" — does not count.
    """
    segments = [segment.lower() for segment in path_segments(path)]
    if any(segment in _API_SEGMENTS for segment in segments):
        return True
    # A version segment counts only near the front, where it introduces an API
    # surface: `/v1/orders`. Deeper down it is usually a document or an asset.
    return any(_VERSION_SEGMENT.match(segment) for segment in segments[:2])


def looks_like_graphql_path(path: str) -> bool:
    """Whether a path is the conventional GraphQL location."""
    segments = [segment.lower() for segment in path_segments(path)]
    return bool(segments) and segments[-1] in {"graphql", "gql"}


@dataclass(frozen=True, slots=True)
class ApiClassification:
    """The verdict, with the reasons that produced it.

    `signals` exists so a low-confidence result can be explained rather than
    merely asserted — a reviewer who disagrees can see exactly which evidence
    the scanner weighed.
    """

    confidence: ApiConfidence
    signals: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_api(self) -> bool:
        """Whether this counts as an API endpoint.

        LOW is excluded on purpose. A weak signal is worth recording and worth
        explaining, but it is not worth putting into an inventory a reviewer is
        going to act on.
        """
        return self.confidence in (ApiConfidence.HIGH, ApiConfidence.MEDIUM)


def classify(
    *,
    path: str,
    response_content_type: str | None = None,
    status_code: int | None = None,
    documented: bool = False,
    json_parsed: bool = False,
) -> ApiClassification:
    """Weigh the available evidence for one endpoint.

    `json_parsed` means the body actually parsed as JSON, which upgrades a
    missing or wrong Content-Type — an API that forgets its header is still an
    API, and this is the only signal that can see past a mislabelled response.
    """
    signals: list[str] = []
    kind = media_kind(response_content_type)

    if looks_like_graphql_path(path):
        signals.append("path:graphql")
    if path_looks_like_api(path):
        signals.append("path:api-convention")

    # --- 1. what the response actually was --------------------------------- #
    if kind is ApiMediaKind.JSON:
        signals.append("response:json")
        return ApiClassification(ApiConfidence.HIGH, tuple(signals))
    if kind is ApiMediaKind.GRAPHQL:
        signals.append("response:graphql")
        return ApiClassification(ApiConfidence.HIGH, tuple(signals))
    if kind is ApiMediaKind.XML:
        signals.append("response:xml")
        return ApiClassification(ApiConfidence.HIGH, tuple(signals))

    if json_parsed:
        # The header said something else, or nothing; the body settled it.
        signals.append("body:json")
        return ApiClassification(ApiConfidence.HIGH, tuple(signals))

    # --- 2. what a specification said -------------------------------------- #
    if documented:
        signals.append("spec:documented")
        # Documentation is real evidence, but it describes intent. An HTML
        # response contradicting it keeps the result at MEDIUM rather than HIGH.
        return ApiClassification(ApiConfidence.MEDIUM, tuple(signals))

    # --- 3. what the URL looks like ---------------------------------------- #
    if kind is ApiMediaKind.HTML:
        # A path convention flatly contradicted by an HTML document. This is the
        # `/api/about` case: recorded, explained, and not counted as an API.
        if signals:
            signals.append("response:html")
            return ApiClassification(ApiConfidence.LOW, tuple(signals))
        return ApiClassification(ApiConfidence.LOW, ("response:html",))

    if "path:graphql" in signals:
        return ApiClassification(ApiConfidence.MEDIUM, tuple(signals))

    if "path:api-convention" in signals:
        # A conventional path with a non-HTML, non-JSON response — an empty
        # body, a redirect, an error. Suggestive, and no more than that.
        if status_code is not None and 200 <= status_code < 300 and kind in (
            ApiMediaKind.UNKNOWN,
            ApiMediaKind.OTHER,
        ):
            return ApiClassification(ApiConfidence.MEDIUM, tuple(signals))
        return ApiClassification(ApiConfidence.LOW, tuple(signals))

    return ApiClassification(ApiConfidence.LOW, tuple(signals))
