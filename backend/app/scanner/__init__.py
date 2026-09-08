"""Isolated scanning engine.

Nothing in this package imports from `app.models`, `app.routers` or
`app.core.database`. It takes a URL and returns a plain `ScanReport`, which is
what allows it to grow into a full crawling/analysis pipeline independently of
the web application around it.
"""

from app.scanner.scanner import WebScanner
from app.scanner.types import (
    HttpProbeResult,
    ScanErrorCode,
    ScannerConfig,
    ScannerError,
    ScanReport,
    ScanTarget,
)
from app.scanner.url_validator import parse_target_url

__all__ = [
    "HttpProbeResult",
    "ScanErrorCode",
    "ScanReport",
    "ScanTarget",
    "ScannerConfig",
    "ScannerError",
    "WebScanner",
    "parse_target_url",
]
