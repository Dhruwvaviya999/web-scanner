"""The scan module that analyses discovered endpoints.

Runs after the crawler and replaces the phase-3 seed-only analysis. Glue only:
eligibility, per-endpoint analysis and aggregation each live in their own module.

**No requests are issued here.** The crawler already fetched every endpoint, so
its captured responses are reused. That is strictly better than re-fetching:
identical data, half the traffic against the target, and no second code path
that could drift from the crawler's SSRF and redirect handling.

When the crawler did not run — disabled, or the probe never connected — the seed
response from `HttpProbeModule` is analysed on its own, so a scan always assesses
what it managed to reach.
"""

from __future__ import annotations

import logging

from app.scanner.analysis.aggregator import aggregate_findings
from app.scanner.analysis.endpoint_analyzer import analyze_endpoint
from app.scanner.analysis.types import AnalysisResult, EndpointAnalysisStatus
from app.scanner.crawler.types import CapturedResponse
from app.scanner.crawler.url_normalizer import canonical_url
from app.scanner.security.types import FindingData
from app.scanner.types import ScanReport, ScanTarget

logger = logging.getLogger(__name__)


class EndpointAnalysisModule:
    """Assesses every eligible endpoint and aggregates the findings."""

    name = "endpoint_analysis"

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        result = AnalysisResult()
        observations: list[tuple[str | None, FindingData]] = []

        for url, response in self._responses(report):
            analysis = _safe_analyze(url, response)
            result.endpoint_analyses.append(analysis)

            if analysis.status is EndpointAnalysisStatus.ANALYZED:
                observations.extend((url, finding) for finding in analysis.findings)

        result.findings = aggregate_findings(observations)

        report.analysis = result
        # The report's flat finding list stays the aggregated representatives, so
        # anything reading `report.findings` keeps working.
        report.findings = [group.data for group in result.findings]
        report.metadata["endpoints_analyzed"] = result.analyzed
        report.metadata["endpoints_skipped"] = result.skipped
        report.metadata["endpoints_failed"] = result.failed

    def _responses(self, report: ScanReport) -> list[tuple[str, CapturedResponse]]:
        """Every response to assess, keyed by the endpoint URL it belongs to.

        The seed is already among the crawl's endpoints — the crawl starts
        there — so it is not analysed twice. Both paths key on the canonical
        URL, which is what makes "seed" and "crawler-discovered seed" the same
        endpoint.
        """
        if report.crawl is not None and report.crawl.responses:
            return sorted(report.crawl.responses.items())

        if report.raw is None:
            return []

        # Crawling disabled or unavailable: assess the seed response alone.
        seed_url = canonical_url(report.raw.final_url)
        return [
            (
                seed_url,
                CapturedResponse(
                    url=seed_url,
                    status_code=report.raw.status_code,
                    content_type=report.raw.headers.get("content-type"),
                    is_https=report.raw.is_https,
                    headers=dict(report.raw.headers),
                    set_cookie=report.raw.set_cookie,
                ),
            )
        ]


def _safe_analyze(url: str, response: CapturedResponse):
    """Analyse one endpoint, never letting a single bad page end the scan."""
    try:
        analysis = analyze_endpoint(response)
    except Exception:  # noqa: BLE001 - one endpoint must not fail the whole scan
        logger.exception("Endpoint analysis failed for %s", url)
        from app.scanner.analysis.endpoint_analyzer import failed_endpoint

        return failed_endpoint(url, "The response could not be analysed.")

    # analyze_endpoint keys on the response's own URL; the endpoint is stored
    # under its canonical URL, so use the canonical one for the association.
    return type(analysis)(
        url=url,
        status=analysis.status,
        skip_reason=analysis.skip_reason,
        error=analysis.error,
        findings=analysis.findings,
    )
