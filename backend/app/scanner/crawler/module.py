"""The scan module that runs the crawler.

Supplies the crawler with a network fetcher built from the shared `HttpFetcher`,
so crawled pages get exactly the same SSRF revalidation, timeout and body-size
handling as the initial probe. One HTTP client is reused for the whole crawl
rather than one per page.

The crawl starts from the probe's *final* URL, so a target that redirects
`http://example.com` to `https://example.com` is crawled on the origin it
actually landed on — and the origin lock is taken from there, so no redirect can
widen the scope afterwards.
"""

from __future__ import annotations

import logging

from app.scanner.crawler.crawler import Crawler
from app.scanner.crawler.types import CrawlConfig, FetchedPage
from app.scanner.crawler.url_normalizer import Origin, is_same_origin, origin_of
from app.scanner.http_scanner import HttpFetcher, build_client
from app.scanner.response_analyzer import is_html_response
from app.scanner.types import ScannerConfig, ScannerError, ScanReport, ScanTarget
from app.scanner.url_validator import parse_target_url

logger = logging.getLogger(__name__)


class CrawlModule:
    """Discovers the target's attack surface after the initial probe."""

    name = "crawler"

    def __init__(self, config: ScannerConfig, crawl_config: CrawlConfig) -> None:
        self._config = config
        self._crawl_config = crawl_config

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        if not self._crawl_config.enabled:
            return
        if report.raw is None:
            # The probe never reached the target, so there is nothing to crawl.
            return

        seed_url = report.raw.final_url
        origin = origin_of(seed_url)
        if origin is None:
            return

        async with build_client(self._config) as client:
            fetcher = HttpFetcher(
                self._config,
                client,
                # A redirect that leaves the origin is refused rather than
                # followed, so the crawl cannot be walked onto another host.
                allow_url=lambda url: is_same_origin(url, origin),
                max_redirects=self._crawl_config.max_redirects_per_page,
            )
            crawler = Crawler(self._crawl_config, _network_fetcher(fetcher, origin))
            result = await crawler.crawl(seed_url)

        report.crawl = result
        report.metadata["pages_crawled"] = result.pages_crawled
        report.metadata["endpoints_discovered"] = len(result.endpoints)
        report.metadata["forms_discovered"] = len(result.forms)


def _network_fetcher(fetcher: HttpFetcher, origin: Origin):
    """Adapt `HttpFetcher` to the crawler's simpler page-fetch contract.

    Any failure on a single page — DNS, TLS, timeout, an off-origin redirect —
    returns None. One unreachable page must not end the crawl.
    """

    async def fetch(url: str) -> FetchedPage | None:
        try:
            target = parse_target_url(url)
        except ScannerError:
            return None

        if not is_same_origin(target.normalized_url, origin):
            return None

        try:
            raw = await fetcher.fetch(target)
        except ScannerError as exc:
            logger.debug("Crawl skipped %s: %s", url, exc.code.value)
            return None

        # A redirect chain may have ended somewhere else on the same origin;
        # record where the response actually came from.
        if not is_same_origin(raw.final_url, origin):
            return None

        content_type = raw.headers.get("content-type")
        return FetchedPage(
            url=raw.final_url,
            status_code=raw.status_code,
            content_type=content_type,
            body=raw.body,
            is_html=is_html_response(content_type),
            is_https=raw.is_https,
            headers=dict(raw.headers),
            set_cookie=raw.set_cookie,
        )

    return fetch
