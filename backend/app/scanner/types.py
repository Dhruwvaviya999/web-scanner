"""Value objects exchanged inside the scanner package.

These are plain dataclasses on purpose: the scanner must not know about ORM
models, HTTP routing or the database. `scan_service` is the only translation
layer between this package and the rest of the application.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from app.scanner.analysis.types import AnalysisResult
from app.scanner.crawler.types import CrawlResult
from app.scanner.security.types import FindingData


class ScanErrorCode(str, Enum):
    """Why a scan could not be completed. Maps to a user-facing message."""

    INVALID_URL = "invalid_url"
    BLOCKED_TARGET = "blocked_target"
    DNS_FAILURE = "dns_failure"
    CONNECTION_FAILED = "connection_failed"
    TLS_ERROR = "tls_error"
    TIMEOUT = "timeout"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    EXTERNAL_REDIRECT = "external_redirect"
    UNEXPECTED = "unexpected"


class ScannerError(Exception):
    """Raised inside the scanner for any condition that fails a scan."""

    def __init__(self, code: ScanErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """A URL that has passed validation and is safe to request."""

    raw_url: str
    normalized_url: str
    scheme: str
    host: str
    port: int
    is_https: bool


@dataclass(frozen=True, slots=True)
class RawHttpResponse:
    """Transport-level facts about the final response, before interpretation.

    `http_scanner` produces this; `response_analyzer` turns it into an
    `HttpProbeResult`. Keeping the two apart means fetching and interpreting can
    change independently, and the analyzer is testable without a network.
    """

    status_code: int
    headers: Mapping[str, str]
    final_url: str
    is_https: bool
    redirect_count: int
    elapsed_ms: int
    #: Bounded prefix of the body. Empty when the body was not worth reading.
    body: bytes = b""
    #: True when the body was longer than the scanner's read limit.
    body_truncated: bool = False
    #: Every Set-Cookie header, kept separate because a response may send many
    #: and a plain mapping would collapse them into one joined string.
    set_cookie: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HttpProbeResult:
    """The analysed result of a single HTTP request to the target."""

    http_status_code: int
    response_time_ms: int
    final_url: str
    is_https: bool
    redirect_count: int
    content_type: str | None = None
    server_header: str | None = None
    #: <title> of the page, when the response was HTML and carried one.
    page_title: str | None = None
    #: Size of the response body in bytes, when the target reported or we read it.
    content_length: int | None = None


@dataclass(slots=True)
class ScanReport:
    """Aggregate output of a scan run.

    Later phases attach discovered endpoints and findings here; the service layer
    persists whichever parts it knows about.
    """

    target: ScanTarget | None
    probe: HttpProbeResult | None = None
    #: The unanalysed response, kept so later modules can inspect headers and
    #: cookies without issuing another request.
    raw: "RawHttpResponse | None" = None
    #: Security observations produced by the detector modules.
    findings: list["FindingData"] = field(default_factory=list)
    #: Attack surface discovered by the crawler, when it ran.
    crawl: "CrawlResult | None" = None
    #: Per-endpoint analysis and the aggregated findings it produced.
    analysis: "AnalysisResult | None" = None
    error_code: ScanErrorCode | None = None
    error_message: str | None = None
    # Reserved for later phases: discovered endpoints, risk score.
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.error_code is None and self.probe is not None


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    """Runtime limits for a scan run.

    Passed in by the caller rather than read from `app.core.config`, so the
    scanner package stays independent of the web application.
    """

    timeout_seconds: float = 10.0
    total_timeout_seconds: float = 30.0
    max_redirects: int = 5
    #: Hard cap on body bytes read from a target. Only HTML bodies are read at
    #: all, and only to recover the page title.
    max_response_bytes: int = 262_144
    user_agent: str = "WebScanner/0.1"
    allow_private_networks: bool = False


class ScanModule(Protocol):
    """Contract every future scanner module implements.

    Phase 1 ships exactly one module (`HttpProbeModule`). Crawling, header
    analysis, XSS and SQLi checks become additional modules behind this same
    interface, which is why the orchestrator iterates over a list.
    """

    name: str

    async def run(self, target: ScanTarget, report: ScanReport) -> None: ...
