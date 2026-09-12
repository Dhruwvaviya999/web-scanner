"""Deciding whether a parameter controls a file or a path.

Pure functions: names, an endpoint path and an observed content type in, a
classification out. No request is sent here, and nothing is concluded — the
output only decides which parameters are *worth* a careful probe, because
probing every parameter would be both noisy and a reliable source of false
positives.

Conservatism is the whole design. `id` is the most common parameter name on the
web and never a file; `page` is usually pagination, occasionally a template;
`file` is almost always a file. So names are graded, an explicit exclusion list
runs first, and corroborating signals — an endpoint that looks like a download,
a response that came back as a document rather than JSON — can lift a borderline
name but never a clearly-excluded one.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from app.scanner.path_security.types import ParameterAssessment, ParameterClass

_SPLIT = re.compile(r"[^a-z0-9]+")

#: Names that exist to carry a file or a path. A traversal probe here is
#: well-targeted. LFI-style names (`template`, `include`, `view`, `page`) live
#: here too, but `page` is deliberately *not* — see the possible/excluded lists.
_LIKELY_NAMES = frozenset(
    {
        "file",
        "filename",
        "file_name",
        "filepath",
        "file_path",
        "path",
        "document",
        "doc",
        "template",
        "include",
        "download",
        "attachment",
        "resource",
        "folder",
        "directory",
        "dir",
        "pathname",
        "filedir",
    }
)

#: Names that are sometimes a file and sometimes not. Probed, but graded lower
#: and requiring the payload/canary evidence to be unambiguous before anything
#: is concluded.
_POSSIBLE_NAMES = frozenset(
    {
        "page",
        "view",
        "src",
        "image",
        "img",
        "url",
        "content",
        "item",
        "load",
        "read",
        "name",
        "lang",
        "locale",
        "theme",
        "skin",
        "module",
    }
)

#: Names that clearly do not carry a file. Checked first, and never probed —
#: this is what keeps the detector off `id`, search boxes and pagination.
_EXCLUDED_NAMES = frozenset(
    {
        "id",
        "uid",
        "user_id",
        "userid",
        "pid",
        "order_id",
        "product_id",
        "q",
        "query",
        "search",
        "term",
        "keyword",
        "page_size",
        "pagesize",
        "limit",
        "offset",
        "count",
        "sort",
        "order",
        "filter",
        "token",
        "csrf_token",
        "csrf",
        "session",
        "sessionid",
        "email",
        "password",
        "lat",
        "lng",
        "lon",
        "latitude",
        "longitude",
        "start",
        "end",
        "from",
        "to",
        "date",
        "year",
        "month",
        "day",
        "format",
        "type",
        "category",
        "tag",
        "status",
        "state",
    }
)

#: Endpoint path fragments that suggest the endpoint serves files. A file-ish
#: name on one of these is corroborated; a borderline name can be lifted by it.
_FILE_ENDPOINT_FRAGMENTS = (
    "download",
    "file",
    "files",
    "document",
    "documents",
    "doc",
    "attachment",
    "media",
    "asset",
    "assets",
    "static",
    "content",
    "template",
    "include",
    "view",
    "render",
    "image",
    "images",
    "export",
    "report",
)

#: Response media types that mean "a document was served", which corroborates a
#: file parameter. JSON/HTML application pages do not.
_FILE_MEDIA_PREFIXES = (
    "application/pdf",
    "application/octet-stream",
    "application/zip",
    "application/msword",
    "application/vnd.",
    "image/",
    "text/plain",
    "text/csv",
    "audio/",
    "video/",
)


def normalize(name: str) -> str:
    """Reduce a parameter name to a comparable token."""
    return _SPLIT.sub("_", (name or "").strip().lower()).strip("_")


def _endpoint_looks_file_serving(endpoint: str) -> bool:
    lowered = (endpoint or "").lower()
    return any(f"/{fragment}" in lowered for fragment in _FILE_ENDPOINT_FRAGMENTS)


def _media_is_file(content_type: str | None) -> bool:
    if not content_type:
        return False
    media = content_type.split(";", 1)[0].strip().lower()
    return any(media.startswith(prefix) for prefix in _FILE_MEDIA_PREFIXES)


def classify_name(name: str) -> tuple[ParameterClass, tuple[str, ...]]:
    """Classify a parameter by name alone. Pure and fully testable."""
    normalized = normalize(name)
    if not normalized:
        return (ParameterClass.UNKNOWN, ())

    # Exclusions first: a clearly non-file name is never lifted by context.
    if normalized in _EXCLUDED_NAMES:
        return (ParameterClass.NOT_FILE_PARAMETER, ("name:excluded",))

    if normalized in _LIKELY_NAMES:
        return (ParameterClass.LIKELY_FILE_PARAMETER, ("name:file-like",))

    if normalized in _POSSIBLE_NAMES:
        return (ParameterClass.POSSIBLE_FILE_PARAMETER, ("name:possible-file",))

    # A name ending in a file-ish word run — `report_file`, `doc_path`.
    segments = [s for s in normalized.split("_") if s]
    if segments and segments[-1] in ("file", "path", "name", "doc", "dir"):
        if segments[-1] in ("file", "path", "doc", "dir"):
            return (ParameterClass.LIKELY_FILE_PARAMETER, ("name:file-suffix",))
        return (ParameterClass.POSSIBLE_FILE_PARAMETER, ("name:possible-suffix",))

    return (ParameterClass.UNKNOWN, ())


def classify(
    parameter: str,
    *,
    endpoint: str = "",
    content_type: str | None = None,
) -> ParameterAssessment:
    """Classify one parameter using its name and what surrounds it.

    Context corroborates a name; it never overrides an exclusion. A borderline
    `POSSIBLE` name on a download-shaped endpoint, or one whose endpoint already
    served a document, is lifted to `LIKELY`. A clearly non-file name stays
    excluded whatever the endpoint looks like.
    """
    classification, signals = classify_name(parameter)
    reasons = list(signals)

    if classification is ParameterClass.NOT_FILE_PARAMETER:
        return ParameterAssessment(
            endpoint=endpoint,
            parameter=parameter,
            classification=classification,
            signals=tuple(reasons),
        )

    endpoint_file = _endpoint_looks_file_serving(endpoint)
    media_file = _media_is_file(content_type)

    if endpoint_file:
        reasons.append("endpoint:file-serving")
    if media_file:
        reasons.append("response:document-media-type")

    # A possible-file name gains confidence from a corroborating context.
    if classification is ParameterClass.POSSIBLE_FILE_PARAMETER and (
        endpoint_file or media_file
    ):
        classification = ParameterClass.LIKELY_FILE_PARAMETER
        reasons.append("promoted:context")

    # An unknown name on a plainly file-serving endpoint that returned a
    # document is worth a cautious probe — but only with both signals, never on
    # the endpoint path alone.
    if classification is ParameterClass.UNKNOWN and endpoint_file and media_file:
        classification = ParameterClass.POSSIBLE_FILE_PARAMETER
        reasons.append("promoted:file-context")

    return ParameterAssessment(
        endpoint=endpoint,
        parameter=parameter,
        classification=classification,
        signals=tuple(reasons),
    )


def classify_all(
    parameters: Iterable[str],
    *,
    endpoint: str = "",
    content_type: str | None = None,
) -> tuple[ParameterAssessment, ...]:
    """Classify every parameter on one endpoint, deduplicated by name."""
    seen: dict[str, ParameterAssessment] = {}
    for parameter in parameters:
        if parameter in seen:
            continue
        seen[parameter] = classify(
            parameter, endpoint=endpoint, content_type=content_type
        )
    return tuple(seen.values())
