"""Eligibility rules and per-endpoint security analysis.

Pure functions over a response the crawler already captured. The Phase 3
detectors are reused unchanged — this module decides *what* to analyse and hands
each response to them; it does not restate any rule.
"""

from __future__ import annotations

from app.scanner.analysis.types import (
    AnalysisSkipReason,
    EndpointAnalysis,
    EndpointAnalysisStatus,
)
from app.scanner.crawler.types import CapturedResponse
from app.scanner.response_analyzer import is_html_response
from app.scanner.security.cookies import analyze_cookies, parse_set_cookie_headers
from app.scanner.security.headers import analyze_security_headers

#: Static assets whose security headers the current detectors have nothing
#: useful to say about. Analysing them would inflate coverage without adding
#: signal, so they are skipped explicitly rather than silently.
_EXCLUDED_MEDIA_PREFIXES = ("image/", "font/", "video/", "audio/")
_EXCLUDED_MEDIA_TYPES = frozenset(
    {"text/css", "text/javascript", "application/javascript", "application/x-javascript"}
)


def _media_type(content_type: str | None) -> str | None:
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower() or None


def is_excluded_resource(content_type: str | None) -> bool:
    """True for stylesheets, scripts and media."""
    media = _media_type(content_type)
    if media is None:
        return False
    if media in _EXCLUDED_MEDIA_TYPES:
        return True
    return media.startswith(_EXCLUDED_MEDIA_PREFIXES)


def eligibility(response: CapturedResponse) -> AnalysisSkipReason | None:
    """Return the reason this response should be skipped, or None to analyse it.

    Phase 3's own guards still apply *inside* the detectors: header rules that
    are document-scoped stay document-scoped, and HSTS is still only assessed
    over HTTPS. This function decides only whether to invoke them at all.
    """
    if is_excluded_resource(response.content_type):
        return AnalysisSkipReason.EXCLUDED_RESOURCE

    # Non-document responses (JSON, XML, plain text) still get the checks that
    # apply to any response — the detectors themselves narrow it from there.
    # Only genuinely non-analysable resources are excluded above.
    return None


def analyze_endpoint(response: CapturedResponse) -> EndpointAnalysis:
    """Run the security detectors against one captured response."""
    skip_reason = eligibility(response)
    if skip_reason is not None:
        return EndpointAnalysis(
            url=response.url,
            status=EndpointAnalysisStatus.SKIPPED,
            skip_reason=skip_reason,
        )

    cookies = parse_set_cookie_headers(response.set_cookie)
    findings = [
        *analyze_security_headers(
            response.headers,
            is_https=response.is_https,
            content_type=response.content_type,
        ),
        *analyze_cookies(cookies, is_https=response.is_https),
    ]

    return EndpointAnalysis(
        url=response.url,
        status=EndpointAnalysisStatus.ANALYZED,
        findings=tuple(findings),
    )


def skipped_endpoint(url: str, reason: AnalysisSkipReason) -> EndpointAnalysis:
    return EndpointAnalysis(
        url=url, status=EndpointAnalysisStatus.SKIPPED, skip_reason=reason
    )


def failed_endpoint(url: str, error: str) -> EndpointAnalysis:
    """An endpoint that could not be assessed.

    Produces no findings on purpose: reporting a missing header for a page that
    was never successfully read would be a fabricated result.
    """
    return EndpointAnalysis(
        url=url,
        status=EndpointAnalysisStatus.FAILED,
        skip_reason=AnalysisSkipReason.REQUEST_FAILED,
        error=error,
    )


def is_html_endpoint(content_type: str | None) -> bool:
    """Exposed for callers that need the document test the crawler uses."""
    return is_html_response(content_type)
