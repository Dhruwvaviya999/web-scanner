"""Value objects exchanged inside the scanner package.

These are plain dataclasses on purpose: the scanner must not know about ORM
models, HTTP routing or the database. `scan_service` is the only translation
layer between this package and the rest of the application.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol


class ScanErrorCode(str, Enum):
    """Why a scan could not be completed. Maps to a user-facing message."""

    INVALID_URL = "invalid_url"
    BLOCKED_TARGET = "blocked_target"
    DNS_FAILURE = "dns_failure"
    CONNECTION_FAILED = "connection_failed"
    TLS_ERROR = "tls_error"
    TIMEOUT = "timeout"
    TOO_MANY_REDIRECTS = "too_many_redirects"
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
class HttpProbeResult:
    """What a single HTTP request to the target revealed."""

    http_status_code: int
    response_time_ms: int
    final_url: str
    is_https: bool
    redirect_count: int
    content_type: str | None = None
    server_header: str | None = None


@dataclass(slots=True)
class ScanReport:
    """Aggregate output of a scan run.

    Later phases attach discovered endpoints and findings here; the service layer
    persists whichever parts it knows about.
    """

    target: ScanTarget | None
    probe: HttpProbeResult | None = None
    error_code: ScanErrorCode | None = None
    error_message: str | None = None
    # Reserved for phase 2+: discovered endpoints, findings, risk score.
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
    max_response_bytes: int = 2_000_000
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
