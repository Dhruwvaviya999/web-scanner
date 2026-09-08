"""Endpoint analysis: eligibility, coverage and failure isolation.

Runs the real pipeline module against canned responses — no network.
"""

from __future__ import annotations

import asyncio

from app.scanner.analysis.endpoint_analyzer import (
    analyze_endpoint,
    eligibility,
    failed_endpoint,
    is_excluded_resource,
)
from app.scanner.analysis.module import EndpointAnalysisModule
from app.scanner.analysis.types import AnalysisSkipReason, EndpointAnalysisStatus
from app.scanner.crawler.types import CapturedResponse, CrawlResult, DiscoveredEndpoint
from app.scanner.security.types import FindingRule
from app.scanner.types import RawHttpResponse, ScanReport, ScanTarget

TARGET = ScanTarget(
    raw_url="https://x.test",
    normalized_url="https://x.test/",
    scheme="https",
    host="x.test",
    port=443,
    is_https=True,
)


def response(url: str, content_type: str | None = "text/html", **headers) -> CapturedResponse:
    merged = {"content-type": content_type} if content_type else {}
    merged.update(headers)
    return CapturedResponse(
        url=url,
        status_code=200,
        content_type=content_type,
        is_https=True,
        headers=merged,
        set_cookie=headers.pop("set_cookie", ()) if "set_cookie" in headers else (),
    )


def run_module(report: ScanReport) -> ScanReport:
    asyncio.run(EndpointAnalysisModule().run(TARGET, report))
    return report


def crawl_with(responses: dict[str, CapturedResponse]) -> CrawlResult:
    result = CrawlResult()
    result.responses = responses
    result.endpoints = [
        DiscoveredEndpoint(url=url, path="/", method="GET", depth=0) for url in responses
    ]
    return result


# --- 1. Seed endpoint is analysed ------------------------------------------ #


def test_seed_is_analysed_when_no_crawl_ran():
    report = ScanReport(target=TARGET)
    report.raw = RawHttpResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        final_url="https://x.test/",
        is_https=True,
        redirect_count=0,
        elapsed_ms=10,
    )
    run_module(report)

    assert report.analysis is not None
    assert report.analysis.analyzed == 1
    assert report.analysis.endpoint_analyses[0].url == "https://x.test/"
    assert any(
        g.data.rule is FindingRule.SECURITY_HEADER_CSP_MISSING for g in report.analysis.findings
    )


def test_seed_is_not_analysed_twice_when_the_crawl_covered_it():
    """The crawl starts at the seed, so it is already among the endpoints."""
    report = ScanReport(target=TARGET)
    report.raw = RawHttpResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        final_url="https://x.test/",
        is_https=True,
        redirect_count=0,
        elapsed_ms=10,
    )
    report.crawl = crawl_with({"https://x.test/": response("https://x.test/")})
    run_module(report)

    urls = [a.url for a in report.analysis.endpoint_analyses]
    assert urls == ["https://x.test/"]
    assert len(urls) == len(set(urls))


# --- 2. Multiple discovered endpoints -------------------------------------- #


def test_every_crawled_endpoint_is_analysed():
    report = ScanReport(target=TARGET)
    report.crawl = crawl_with(
        {
            "https://x.test/": response("https://x.test/"),
            "https://x.test/a": response("https://x.test/a"),
            "https://x.test/b": response("https://x.test/b"),
        }
    )
    run_module(report)

    assert report.analysis.analyzed == 3
    # Same rule on three pages -> one finding, three occurrences.
    csp = next(
        g for g in report.analysis.findings
        if g.data.rule is FindingRule.SECURITY_HEADER_CSP_MISSING
    )
    assert csp.occurrence_count == 3


# --- 3. Non-analysable responses are skipped ------------------------------- #


def test_static_assets_are_skipped_with_a_reason():
    for content_type in ("image/png", "text/css", "application/javascript", "font/woff2"):
        assert is_excluded_resource(content_type), content_type
        assert eligibility(response("u", content_type)) is AnalysisSkipReason.EXCLUDED_RESOURCE


def test_json_endpoints_are_still_analysed_but_document_rules_do_not_fire():
    """Phase 3's document guard still applies inside the detectors."""
    report = ScanReport(target=TARGET)
    report.crawl = crawl_with(
        {"https://x.test/api": response("https://x.test/api", "application/json")}
    )
    run_module(report)

    assert report.analysis.analyzed == 1
    rules = {g.data.rule for g in report.analysis.findings}
    assert FindingRule.SECURITY_HEADER_CSP_MISSING not in rules
    assert FindingRule.SECURITY_HEADER_HSTS_MISSING in rules


def test_skipped_endpoints_produce_no_findings():
    report = ScanReport(target=TARGET)
    report.crawl = crawl_with(
        {"https://x.test/style.css": response("https://x.test/style.css", "text/css")}
    )
    run_module(report)

    assert report.analysis.skipped == 1
    assert report.analysis.analyzed == 0
    assert report.analysis.findings == []


# --- 4. A failed endpoint does not fail the scan --------------------------- #


def test_failed_endpoint_is_recorded_and_yields_no_findings():
    analysis = failed_endpoint("https://x.test/broken", "timed out")

    assert analysis.status is EndpointAnalysisStatus.FAILED
    assert analysis.skip_reason is AnalysisSkipReason.REQUEST_FAILED
    # Never invent a finding for a page that was never read.
    assert analysis.findings == ()


def test_one_bad_endpoint_leaves_the_rest_analysed():
    class Exploding(dict):
        def items(self):  # noqa: D102 - forced failure inside the detector
            raise RuntimeError("boom")

    bad = CapturedResponse(
        url="https://x.test/bad",
        status_code=200,
        content_type="text/html",
        is_https=True,
        headers=Exploding(),
    )
    report = ScanReport(target=TARGET)
    report.crawl = crawl_with(
        {
            "https://x.test/": response("https://x.test/"),
            "https://x.test/bad": bad,
            "https://x.test/c": response("https://x.test/c"),
        }
    )
    run_module(report)

    assert report.analysis.analyzed == 2
    assert report.analysis.failed == 1
    # The scan still produced results from the endpoints that worked.
    assert report.analysis.findings


# --- 5 & 6. Coverage accounting -------------------------------------------- #


def test_coverage_counts_are_consistent():
    report = ScanReport(target=TARGET)
    report.crawl = crawl_with(
        {
            "https://x.test/": response("https://x.test/"),
            "https://x.test/a": response("https://x.test/a"),
            "https://x.test/logo.png": response("https://x.test/logo.png", "image/png"),
        }
    )
    run_module(report)

    a = report.analysis
    assert a.analyzed == 2
    assert a.skipped == 1
    assert a.failed == 0
    assert len(a.endpoint_analyses) == 3


def test_no_responses_yields_empty_analysis():
    report = ScanReport(target=TARGET)
    run_module(report)

    assert report.analysis.endpoint_analyses == []
    assert report.analysis.findings == []


# --- Cookies across endpoints ---------------------------------------------- #


def test_cookie_findings_carry_their_subject_across_endpoints():
    report = ScanReport(target=TARGET)
    login = CapturedResponse(
        url="https://x.test/login",
        status_code=200,
        content_type="text/html",
        is_https=True,
        headers={"content-type": "text/html"},
        set_cookie=("session=abc; Path=/",),
    )
    home = CapturedResponse(
        url="https://x.test/",
        status_code=200,
        content_type="text/html",
        is_https=True,
        headers={"content-type": "text/html"},
        set_cookie=("session=abc; Path=/",),
    )
    report.crawl = crawl_with({"https://x.test/": home, "https://x.test/login": login})
    run_module(report)

    secure = next(
        g for g in report.analysis.findings if g.data.rule is FindingRule.COOKIE_SECURE_MISSING
    )
    assert secure.data.subject == "session"
    assert secure.occurrence_count == 2


def test_analysis_never_records_a_cookie_value():
    report = ScanReport(target=TARGET)
    report.crawl = crawl_with(
        {
            "https://x.test/": CapturedResponse(
                url="https://x.test/",
                status_code=200,
                content_type="text/html",
                is_https=True,
                headers={"content-type": "text/html"},
                set_cookie=("session=SUPER-SECRET-VALUE; Path=/",),
            )
        }
    )
    run_module(report)

    dumped = repr(report.analysis)
    assert "SUPER-SECRET-VALUE" not in dumped
