"""Generic response comparison.

Pure observations about how two responses differ. Nothing here draws a
vulnerability conclusion — `status_changed` belongs in the framework,
`is_sql_injection` belongs to a detector. Keeping the line there is what lets
several detectors share these without inheriting each other's judgement.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from app.scanner.response_analyzer import decode_html
from app.scanner.types import RawHttpResponse

#: Bodies longer than this are compared on a prefix. Similarity on a large page
#: is dominated by its first screenful, and the cost is bounded.
_SIMILARITY_SAMPLE_BYTES = 20_000


def response_text(response: RawHttpResponse) -> str:
    """Decode a response body using the charset it declared.

    Reuses the phase-2 decoder so every part of the scanner reads a body the
    same way. Never raises: an undecodable byte becomes a replacement character.
    """
    if not response.body:
        return ""
    return decode_html(response.body, response.headers.get("content-type"))


def media_type(response: RawHttpResponse) -> str | None:
    """`text/html` out of `text/html; charset=utf-8`."""
    value = response.headers.get("content-type")
    if not value:
        return None
    return value.split(";", 1)[0].strip().lower() or None


def status_changed(a: RawHttpResponse, b: RawHttpResponse) -> bool:
    return a.status_code != b.status_code


def content_type_changed(a: RawHttpResponse, b: RawHttpResponse) -> bool:
    return media_type(a) != media_type(b)


def final_url_changed(a: RawHttpResponse, b: RawHttpResponse) -> bool:
    return a.final_url != b.final_url


def size_delta(a: RawHttpResponse, b: RawHttpResponse) -> int:
    """Signed byte difference, `b` relative to `a`."""
    return len(b.body) - len(a.body)


def timing_delta_ms(a: RawHttpResponse, b: RawHttpResponse) -> int:
    """Signed millisecond difference, `b` relative to `a`.

    A single pair of timings is weak evidence on its own — network variance
    routinely exceeds application variance — so this reports the number and
    leaves any conclusion to a detector that gathers more samples.
    """
    return b.elapsed_ms - a.elapsed_ms


def body_similarity(a: RawHttpResponse, b: RawHttpResponse) -> float:
    """Rough similarity of two bodies, 0.0 to 1.0.

    Both empty counts as identical. Intended for "did this page change
    materially", not for precise diffing.
    """
    left = response_text(a)[:_SIMILARITY_SAMPLE_BYTES]
    right = response_text(b)[:_SIMILARITY_SAMPLE_BYTES]
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def contains_marker(response: RawHttpResponse, marker: str) -> bool:
    """Whether `marker` appears verbatim in the decoded body.

    Case-sensitive on purpose: an application that changes the case of a value
    has transformed it, and that is a different observation from echoing it.
    """
    if not marker:
        return False
    return marker in response_text(response)


@dataclass(frozen=True, slots=True)
class ResponseDelta:
    """Every generic difference between a baseline and a probe response."""

    status_changed: bool
    content_type_changed: bool
    final_url_changed: bool
    size_delta: int
    timing_delta_ms: int
    body_similarity: float


def compare(baseline: RawHttpResponse, probe: RawHttpResponse) -> ResponseDelta:
    """Summarise how `probe` differs from `baseline`."""
    return ResponseDelta(
        status_changed=status_changed(baseline, probe),
        content_type_changed=content_type_changed(baseline, probe),
        final_url_changed=final_url_changed(baseline, probe),
        size_delta=size_delta(baseline, probe),
        timing_delta_ms=timing_delta_ms(baseline, probe),
        body_similarity=body_similarity(baseline, probe),
    )
