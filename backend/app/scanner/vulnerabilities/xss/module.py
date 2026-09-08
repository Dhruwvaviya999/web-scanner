"""The scan module that runs reflected-XSS probing.

Glue only. It builds probe targets from the endpoints the crawler already
discovered, hands the detector a fetcher built from the shared `HttpFetcher`,
and merges what comes back into the phase-5 aggregation.

Every existing protection stays in force, because the probes go through the same
transport as everything else:

* `parse_target_url` validation on each probe URL,
* the SSRF guard on every connection,
* the same-origin lock — taken from the probe's final URL, and enforced again on
  redirects, so a probe cannot be walked onto another host,
* the configured request timeout and redirect limit.

Nothing here constructs a URL from user-supplied data: the scheme, host and path
come from an already-validated endpoint, and only a known parameter's value is
substituted.
"""

from __future__ import annotations

import logging

from app.scanner.analysis.aggregator import aggregate_findings
from app.scanner.crawler.url_normalizer import Origin, is_same_origin, origin_of
from app.scanner.http_scanner import HttpFetcher, build_client
from app.scanner.response_analyzer import decode_html
from app.scanner.types import ScannerConfig, ScannerError, ScanReport, ScanTarget
from app.scanner.url_validator import parse_target_url
from app.scanner.vulnerabilities.xss.analyzer import is_html_document
from app.scanner.vulnerabilities.xss.detector import (
    EndpointTarget,
    ReflectedXssDetector,
    XssConfig,
    XssResponse,
)

logger = logging.getLogger(__name__)


class ReflectedXssModule:
    """Actively probes discovered query parameters for reflected XSS."""

    name = "xss_reflected"

    def __init__(self, config: ScannerConfig, xss_config: XssConfig) -> None:
        self._config = config
        self._xss_config = xss_config

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        if not self._xss_config.enabled:
            return
        if report.crawl is None or report.raw is None:
            # Nothing was discovered, so there is no input surface to probe.
            return

        origin = origin_of(report.raw.final_url)
        if origin is None:
            return

        targets = _targets_from(report)
        if not targets:
            return

        async with build_client(self._config) as client:
            fetcher = HttpFetcher(
                self._config,
                client,
                # A redirect leaving the origin is refused, not followed.
                allow_url=lambda url: is_same_origin(url, origin),
                max_redirects=self._config.max_redirects,
            )
            detector = ReflectedXssDetector(self._xss_config, _network_fetcher(fetcher, origin))
            result = await detector.scan(targets)

        report.metadata["xss_requests_sent"] = result.stats.requests_sent
        report.metadata["xss_parameters_tested"] = result.stats.parameters_tested
        if result.stats.limit_reached:
            report.metadata["xss_limit_reached"] = True

        if not result.observations:
            return

        # Merge into the phase-5 aggregation so XSS findings participate in
        # deduplication, endpoint association and the scan summary like any
        # other finding — there is no separate XSS result path.
        if report.analysis is None:
            return
        report.analysis.observations.extend(result.observations)
        report.analysis.findings = aggregate_findings(report.analysis.observations)


def _targets_from(report: ScanReport) -> list[EndpointTarget]:
    """Endpoints with query parameters, ordered shallowest first.

    Only endpoints that actually carry parameters are probed — an endpoint with
    no discovered input surface has nothing for this detector to test.
    """
    assert report.crawl is not None
    targets = [
        EndpointTarget(
            url=endpoint.url,
            parameters=endpoint.parameters,
            content_type=endpoint.content_type,
        )
        for endpoint in report.crawl.endpoints
        if endpoint.parameters and is_html_document(endpoint.content_type)
    ]
    targets.sort(key=lambda t: (len(t.parameters) * -1, t.url))
    return targets


def _network_fetcher(fetcher: HttpFetcher, origin: Origin):
    """Adapt `HttpFetcher` to the detector's contract.

    Any failure — validation, DNS, TLS, timeout, an off-origin redirect —
    returns None, so one bad probe is skipped rather than ending the scan.
    """

    async def fetch(url: str) -> XssResponse | None:
        try:
            probe_target = parse_target_url(url)
        except ScannerError:
            return None

        # Belt and braces: the URL was built from an already-validated endpoint,
        # but it is re-checked before any connection is made.
        if not is_same_origin(probe_target.normalized_url, origin):
            return None

        try:
            raw = await fetcher.fetch(probe_target)
        except ScannerError as exc:
            logger.debug("XSS probe skipped %s: %s", url, exc.code.value)
            return None

        if not is_same_origin(raw.final_url, origin):
            return None

        content_type = raw.headers.get("content-type")
        return XssResponse(
            url=raw.final_url,
            status_code=raw.status_code,
            content_type=content_type,
            # The body is decoded for analysis and never persisted.
            body=decode_html(raw.body, content_type) if raw.body else "",
        )

    return fetch
