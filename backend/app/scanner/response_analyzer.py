"""Interpretation of an HTTP response.

`http_scanner` speaks to the network; this module decides what the reply means.
It is pure — no sockets, no I/O — so every rule here can be tested by handing it
a `RawHttpResponse`.

Phase 2 answers only descriptive questions (what type of content is this, what
is the page called, is it served over TLS). Security judgements — missing
headers, weak cookies, TLS posture — belong to later phases and are deliberately
absent: nothing here decides whether a target is safe.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from app.scanner.types import HttpProbeResult, RawHttpResponse

MAX_HEADER_VALUE_LENGTH = 255
MAX_TITLE_LENGTH = 512

#: Media types whose body is worth decoding to look for a <title>.
HTML_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})

_CHARSET_RE = re.compile(r"charset\s*=\s*\"?([\w.:+-]+)\"?", re.IGNORECASE)


def analyze_response(raw: RawHttpResponse) -> HttpProbeResult:
    """Turn transport facts into the result the application stores."""
    content_type = clean_header_value(raw.headers.get("content-type"))
    return HttpProbeResult(
        http_status_code=raw.status_code,
        response_time_ms=raw.elapsed_ms,
        final_url=raw.final_url,
        is_https=raw.is_https,
        redirect_count=raw.redirect_count,
        content_type=content_type,
        server_header=clean_header_value(raw.headers.get("server")),
        page_title=extract_page_title(raw.body, content_type) if raw.body else None,
        content_length=_content_length(raw),
    )


def clean_header_value(value: str | None) -> str | None:
    """Collapse whitespace and bound the length of a header before storing it.

    Header values are attacker-controlled, so they are normalised here rather
    than trusted anywhere downstream.
    """
    if not value:
        return None
    collapsed = " ".join(value.split())
    if not collapsed:
        return None
    return collapsed[:MAX_HEADER_VALUE_LENGTH]


def media_type_of(content_type: str | None) -> str | None:
    """`text/html` out of `text/html; charset=utf-8`."""
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower() or None


#: Media types whose body is text worth reading for analysis. Broader than HTML
#: because SQL-injection error signatures surface in JSON, XML and plain text
#: too. Still bounded by `max_response_bytes`; binary types are never read.
_TEXTUAL_MEDIA_TYPES = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "application/json",
        "application/ld+json",
        "application/xml",
        "text/xml",
        "application/javascript",
        "text/javascript",
    }
)


def is_textual_response(content_type: str | None) -> bool:
    """True when the body is text the scanner can usefully read.

    Covers `text/*` plus the common structured-text application types. A missing
    Content-Type is treated as readable, so a misconfigured endpoint is not
    silently skipped.
    """
    if not content_type:
        return True
    media = content_type.split(";", 1)[0].strip().lower()
    if not media:
        return True
    if media in _TEXTUAL_MEDIA_TYPES:
        return True
    return media.startswith("text/")


def is_html_response(content_type: str | None) -> bool:
    return media_type_of(content_type) in HTML_MEDIA_TYPES


def charset_of(content_type: str | None) -> str | None:
    if not content_type:
        return None
    match = _CHARSET_RE.search(content_type)
    return match.group(1).strip().lower() if match else None


def _content_length(raw: RawHttpResponse) -> int | None:
    """Body size in bytes.

    Prefers the target's own `Content-Length`; falls back to what was actually
    read, but only when the body was read in full — a truncated read would
    otherwise report the scanner's own limit as the page size.
    """
    header = raw.headers.get("content-length")
    if header:
        try:
            declared = int(header.strip())
        except ValueError:
            declared = -1
        if declared >= 0:
            return declared

    if raw.body and not raw.body_truncated:
        return len(raw.body)
    return None


def decode_html(body: bytes, content_type: str | None) -> str:
    """Decode a body to text, preferring the charset the target declared.

    Never raises: an undecodable byte becomes a replacement character, because a
    mis-encoded page should still yield a usable title.
    """
    for encoding in (charset_of(content_type), "utf-8"):
        if not encoding:
            continue
        try:
            return body.decode(encoding, errors="replace")
        except LookupError:
            # The target named an encoding Python does not know.
            continue
    return body.decode("utf-8", errors="replace")


class _TitleParser(HTMLParser):
    """Pulls the first `<title>` out of a document and then stops.

    Parsing halts at `</head>` or `<body>` so that a `<title>` inside inline SVG
    further down the page cannot be mistaken for the document title.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self.finished = False
        self._capturing = False
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.finished:
            return
        if tag == "title" and self.title is None:
            self._capturing = True
        elif tag == "body":
            self.finished = True

    def handle_endtag(self, tag: str) -> None:
        if self.finished:
            return
        if tag == "title" and self._capturing:
            self._capturing = False
            self.title = "".join(self._parts)
            self.finished = True
        elif tag == "head":
            self.finished = True

    def handle_data(self, data: str) -> None:
        if self._capturing:
            self._parts.append(data)

    @property
    def best_effort_title(self) -> str | None:
        """The closed `<title>`, or whatever was captured before parsing ended."""
        if self.title is not None:
            return self.title
        return "".join(self._parts) if self._parts else None


def extract_page_title(body: bytes, content_type: str | None) -> str | None:
    """Return the document title, or None when there isn't a usable one.

    Only HTML responses are parsed. Malformed markup is tolerated rather than
    treated as a scan failure — a broken page is a finding for a later phase, not
    a reason to lose the rest of the result.
    """
    if not body or not is_html_response(content_type):
        return None

    parser = _TitleParser()
    try:
        parser.feed(decode_html(body, content_type))
        parser.close()
    except (AssertionError, ValueError):
        # html.parser is lenient, but never let a hostile page break a scan;
        # anything captured before it gave up is still usable.
        pass

    raw_title = parser.best_effort_title
    if raw_title is None:
        return None

    normalized = " ".join(raw_title.split())
    return normalized[:MAX_TITLE_LENGTH] if normalized else None
