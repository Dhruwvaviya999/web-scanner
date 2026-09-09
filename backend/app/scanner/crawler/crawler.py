"""Bounded breadth-first crawler.

Discovers the attack surface of one origin: reachable URLs, their query
parameter names, and the forms on each page. It never submits a form, never
sends a payload and never leaves the origin it was given.

Termination is guaranteed three ways — a page cap, a depth cap and a wall-clock
budget — and the visited set is keyed on the canonical URL, so circular links
cannot loop. Reaching a limit is normal completion, not an error.

The fetcher is injected, so the whole algorithm is testable against canned pages
with no network involved.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable

from app.scanner.api.parser import summarize_body
from app.scanner.api.types import JsonShape
from app.scanner.cancellation import CancellationToken, ScanCancelled
from app.scanner.crawler.html_parser import decode_html, extract_forms, extract_links
from app.scanner.crawler.types import (
    CrawlConfig,
    CrawlResult,
    DiscoveredEndpoint,
    FetchedPage,
    SkipReason,
)
from app.scanner.crawler.url_normalizer import (
    Origin,
    canonical_url,
    is_same_origin,
    normalize_url,
    origin_of,
    path_of,
    query_parameter_names,
)

logger = logging.getLogger(__name__)

#: Fetches one URL. Returns None when the page could not be retrieved — a
#: failed page is skipped, never fatal to the crawl.
PageFetcher = Callable[[str], Awaitable[FetchedPage | None]]

_TITLE_LIMIT = 512


class Crawler:
    """Walks one origin breadth-first within the configured bounds."""

    def __init__(
        self,
        config: CrawlConfig,
        fetch: PageFetcher,
        cancellation: CancellationToken | None = None,
    ) -> None:
        self._config = config
        self._fetch = fetch
        self._cancellation = cancellation or CancellationToken.none()

    async def crawl(self, seed_url: str) -> CrawlResult:
        result = CrawlResult()

        origin = origin_of(seed_url)
        seed = normalize_url(seed_url)
        if origin is None or seed is None:
            logger.info("Crawl skipped: %r is not a crawlable URL", seed_url)
            return result

        started = time.perf_counter()
        visited: set[str] = set()
        # BFS: shallow pages are discovered before deep ones, so a page cap
        # yields a broad view of the site rather than one deep branch.
        queue: deque[tuple[str, int]] = deque([(seed, 0)])
        visited.add(canonical_url(seed))

        try:
            await self._walk(queue, visited, origin, result, started)
        except ScanCancelled:
            # Stopping is not failing. Everything crawled so far is returned;
            # what was still queued is recorded as skipped, so the coverage
            # numbers show plainly that the crawl did not finish.
            result.cancelled = True
            self._drain(queue, result, SkipReason.CANCELLED)
            logger.info("Crawl stopped: the scan was cancelled")

        return result

    async def _walk(
        self,
        queue: "deque[tuple[str, int]]",
        visited: set[str],
        origin: Origin,
        result: CrawlResult,
        started: float,
    ) -> None:
        """The crawl loop itself. Raises `ScanCancelled` when told to stop."""
        while queue:
            if result.pages_crawled >= self._config.max_pages:
                result.limit_reached = True
                self._drain(queue, result, SkipReason.PAGE_LIMIT)
                break

            if time.perf_counter() - started >= self._config.time_budget_seconds:
                result.limit_reached = True
                logger.info("Crawl stopped: time budget of %.0fs reached", self._config.time_budget_seconds)
                self._drain(queue, result, SkipReason.TIME_BUDGET)
                break

            # Before issuing another request: the strongest boundary in the
            # crawl, since it guarantees no new traffic reaches the target once
            # cancellation is observed.
            self._cancellation.raise_if_cancelled("CRAWLING")

            url, depth = queue.popleft()
            page = await self._fetch(url)

            if page is None:
                result.record_skip(SkipReason.FETCH_FAILED)
                continue

            result.pages_crawled += 1
            result.max_depth_reached = max(result.max_depth_reached, depth)
            endpoint = self._endpoint_for(page, depth)
            result.endpoints.append(endpoint)
            # Keyed by the canonical URL so the analysis stage can look the
            # response up from the stored endpoint without another request.
            #
            # The JSON summary is computed here, at the one moment the body is
            # still in hand and about to be discarded. It costs nothing extra —
            # no second request — and keeps only structure: a non-JSON body is
            # rejected on its first character.
            result.responses[endpoint.url] = page.captured(
                json_shape=_safe_summary(page.body)
            )

            # Only documents carry links and forms; a JSON or image response is
            # recorded as an endpoint and otherwise left alone.
            if not page.is_html or not page.body:
                continue

            html = decode_html(page.body, page.content_type)
            result.forms.extend(extract_forms(html, page.url))

            if depth >= self._config.max_depth:
                # Links here would exceed the depth limit; count them once as
                # skipped rather than queueing work that will be discarded.
                self._skip_links(html, page.url, origin, visited, result)
                continue

            self._enqueue_links(html, page.url, origin, visited, queue, depth, result)

    # ------------------------------------------------------------------ #

    def _endpoint_for(self, page: FetchedPage, depth: int) -> DiscoveredEndpoint:
        """Record a fetched page, with query values stripped from the stored URL."""
        return DiscoveredEndpoint(
            # canonical_url drops query values, so a token in a URL is not stored.
            url=canonical_url(page.url),
            path=path_of(page.url),
            method="GET",
            depth=depth,
            status_code=page.status_code,
            content_type=page.content_type,
            page_title=_page_title(page),
            parameters=query_parameter_names(page.url),
        )

    def _enqueue_links(
        self,
        html: str,
        base_url: str,
        origin: Origin,
        visited: set[str],
        queue: deque[tuple[str, int]],
        depth: int,
        result: CrawlResult,
    ) -> None:
        for link in extract_links(html, base_url):
            if not is_same_origin(link, origin):
                # External origins are never fetched, at any depth.
                result.record_skip(SkipReason.EXTERNAL_ORIGIN)
                continue

            key = canonical_url(link)
            if key in visited:
                result.record_skip(SkipReason.ALREADY_VISITED)
                continue

            visited.add(key)
            queue.append((link, depth + 1))

    def _skip_links(
        self,
        html: str,
        base_url: str,
        origin: Origin,
        visited: set[str],
        result: CrawlResult,
    ) -> None:
        """Account for links found at the depth limit without queueing them."""
        for link in extract_links(html, base_url):
            if not is_same_origin(link, origin):
                result.record_skip(SkipReason.EXTERNAL_ORIGIN)
            elif canonical_url(link) not in visited:
                result.record_skip(SkipReason.DEPTH_LIMIT)

    @staticmethod
    def _drain(queue: deque[tuple[str, int]], result: CrawlResult, reason: SkipReason) -> None:
        """Count everything still queued when a limit stopped the crawl."""
        while queue:
            queue.popleft()
            result.record_skip(reason)


def _safe_summary(body: bytes) -> "JsonShape | None":
    """Summarise a body's JSON structure, or return None. Never raises.

    Wrapped because `_walk` has no guard of its own: an exception here would
    unwind the whole crawl and discard every page already gathered. One
    unparseable body is not worth that, and the summary is a convenience rather
    than something the scan depends on.
    """
    if not body:
        return None
    try:
        return summarize_body(body)
    except Exception:  # noqa: BLE001 - one bad body must not end the crawl
        logger.debug("Could not summarise a response body", exc_info=True)
        return None


def _page_title(page: FetchedPage) -> str | None:
    """Reuse the phase-2 title extractor so both paths agree on the answer."""
    from app.scanner.response_analyzer import extract_page_title

    if not page.is_html or not page.body:
        return None
    title = extract_page_title(page.body, page.content_type)
    return title[:_TITLE_LIMIT] if title else None
