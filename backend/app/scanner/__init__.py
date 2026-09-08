"""Isolated scanning engine.

Nothing in this package imports from `app.models`, `app.routers` or
`app.core.database`. It takes a URL and returns a plain `ScanReport`, which is
what allows it to grow into a full crawling/analysis pipeline independently of
the web application around it.
"""

from app.scanner.crawler.types import (
    CrawlConfig,
    CrawlResult,
    DiscoveredEndpoint,
    DiscoveredForm,
    DiscoveredFormField,
    FormFieldKind,
    ParameterLocation,
)
from app.scanner.response_analyzer import analyze_response, extract_page_title
from app.scanner.vulnerabilities.xss.detector import XssConfig
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingSeverity,
)
from app.scanner.scanner import WebScanner
from app.scanner.types import (
    HttpProbeResult,
    RawHttpResponse,
    ScanErrorCode,
    ScannerConfig,
    ScannerError,
    ScanReport,
    ScanTarget,
)
from app.scanner.url_validator import parse_target_url

__all__ = [
    "CrawlConfig",
    "XssConfig",
    "CrawlResult",
    "DiscoveredEndpoint",
    "DiscoveredForm",
    "DiscoveredFormField",
    "FindingCategory",
    "FindingConfidence",
    "FindingData",
    "FindingSeverity",
    "FormFieldKind",
    "HttpProbeResult",
    "ParameterLocation",
    "RawHttpResponse",
    "ScanErrorCode",
    "ScanReport",
    "ScanTarget",
    "ScannerConfig",
    "ScannerError",
    "WebScanner",
    "analyze_response",
    "extract_page_title",
    "parse_target_url",
]
