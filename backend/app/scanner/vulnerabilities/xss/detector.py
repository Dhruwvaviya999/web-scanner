"""Reflected-XSS probing across discovered query parameters.

Orchestration only — the response analysis lives in `analyzer.py` and the
grading in `findings.py`, both pure. The fetcher is injected, so the whole probe
strategy is testable against canned responses with no network involved.

Request budget, per parameter:

* **1 request** when the parameter is not reflected — a baseline carrying an
  inert alphanumeric token. If that token does not come back, there is nothing
  to test and the probe is never sent.
* **2 requests** when it is reflected — baseline, then the encoding probe.

Nothing is escalated beyond that: no payload lists, no mutation, no retries.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.scanner.security.types import FindingData
from app.scanner.vulnerabilities.xss.analyzer import analyze_reflection, is_html_document
from app.scanner.vulnerabilities.xss.findings import build_finding
from app.scanner.vulnerabilities.xss.payloads import new_baseline_token, new_probe
from app.scanner.vulnerabilities.xss.types import XssScanStats

logger = logging.getLogger(__name__)

#: Benign filler for the parameters not under test, so the application still
#: receives plausible input. Alphanumeric and inert.
FILLER_VALUE = "1"


@dataclass(frozen=True, slots=True)
class XssConfig:
    """Bounds on active probing. Every limit is configurable."""

    enabled: bool = True
    #: Parameters probed on any one endpoint.
    max_parameters_per_endpoint: int = 8
    #: Hard cap on probe requests for the whole scan.
    max_requests_per_scan: int = 80
    #: Endpoints considered. Keeps a large crawl from becoming a large probe run.
    max_endpoints: int = 25


@dataclass(frozen=True, slots=True)
class XssResponse:
    """A probe response, reduced to what the analyser needs."""

    url: str
    status_code: int
    content_type: str | None
    body: str


@dataclass(slots=True)
class EndpointTarget:
    """One endpoint worth probing."""

    url: str
    parameters: tuple[str, ...]
    content_type: str | None = None


@dataclass(slots=True)
class XssScanResult:
    #: `(endpoint_url, finding)` pairs, ready for the phase-5 aggregator.
    observations: list[tuple[str, FindingData]] = field(default_factory=list)
    stats: XssScanStats = field(default_factory=XssScanStats)


#: Fetches one probe URL. Returns None when the request could not be completed —
#: a failed probe is skipped, never fatal, and never produces a finding.
XssFetcher = Callable[[str], Awaitable[XssResponse | None]]


def build_probe_url(endpoint_url: str, parameter: str, value: str) -> str:
    """The endpoint URL with `parameter` set to `value`.

    Other parameters get an inert filler so the application still sees a
    complete query. The scheme, host and path are taken from the endpoint and
    never altered, so a probe cannot be redirected to a different target by
    construction.
    """
    parts = urlsplit(endpoint_url)
    existing = parse_qsl(parts.query, keep_blank_values=True)

    names = [name for name, _ in existing] or [parameter]
    if parameter not in names:
        names.append(parameter)

    query = [(name, value if name == parameter else FILLER_VALUE) for name in names]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


class ReflectedXssDetector:
    """Probes discovered query parameters for reflected XSS."""

    def __init__(self, config: XssConfig, fetch: XssFetcher) -> None:
        self._config = config
        self._fetch = fetch

    async def scan(self, targets: Sequence[EndpointTarget]) -> XssScanResult:
        result = XssScanResult()

        for target in targets[: self._config.max_endpoints]:
            if result.stats.requests_sent >= self._config.max_requests_per_scan:
                result.stats.limit_reached = True
                break
            await self._scan_endpoint(target, result)

        return result

    async def _scan_endpoint(self, target: EndpointTarget, result: XssScanResult) -> None:
        if not target.parameters:
            return

        # Only documents are candidates: HTML-context analysis of a JSON or
        # binary response would be meaningless.
        if not is_html_document(target.content_type):
            result.stats.parameters_skipped += len(target.parameters)
            result.stats.note("non_html_endpoint")
            return

        result.stats.endpoints_tested += 1

        for parameter in target.parameters[: self._config.max_parameters_per_endpoint]:
            if result.stats.requests_sent >= self._config.max_requests_per_scan:
                result.stats.limit_reached = True
                return
            await self._scan_parameter(target, parameter, result)

    async def _scan_parameter(
        self, target: EndpointTarget, parameter: str, result: XssScanResult
    ) -> None:
        stats = result.stats

        # --- baseline: is this parameter reflected at all? ----------------- #
        baseline_token = new_baseline_token()
        baseline = await self._request(build_probe_url(target.url, parameter, baseline_token), stats)
        if baseline is None:
            stats.request_failures += 1
            stats.note("baseline_request_failed")
            return

        if not is_html_document(baseline.content_type):
            stats.parameters_skipped += 1
            stats.note("non_html_response")
            return

        if baseline_token not in baseline.body:
            # Not reflected. No probe is sent, and no finding is possible.
            stats.parameters_tested += 1
            stats.note("not_reflected")
            return

        # --- probe: which metacharacters survive encoding? ----------------- #
        probe = new_probe()
        response = await self._request(build_probe_url(target.url, parameter, probe.value), stats)
        stats.parameters_tested += 1

        if response is None:
            stats.request_failures += 1
            stats.note("probe_request_failed")
            return

        if not is_html_document(response.content_type):
            stats.note("non_html_response")
            return

        analysis = analyze_reflection(
            response.body, probe.open_marker, probe.close_marker, probe.canary
        )
        finding = build_finding(parameter, analysis)

        if finding is None:
            # Reflected but safely encoded, or not reflected on the probe.
            stats.note(analysis.outcome.value.lower())
            return

        result.observations.append((target.url, finding))

    async def _request(self, url: str, stats: XssScanStats) -> XssResponse | None:
        stats.requests_sent += 1
        try:
            return await self._fetch(url)
        except Exception:  # noqa: BLE001 - one bad probe must not end the scan
            logger.debug("XSS probe request failed", exc_info=True)
            return None
