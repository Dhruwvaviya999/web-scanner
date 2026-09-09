"""The scan module that builds an API attack surface.

Reconnaissance only. This stage classifies what earlier stages already fetched,
reads any specification the target publishes at a conventional location, and
notes whether GraphQL is present. It exploits nothing, submits nothing, and
executes nothing a specification describes.

Its traffic is deliberately tiny and deliberately boring: a handful of GET
requests to well-known documentation paths on the origin already being scanned.
There is no path brute-forcer here, no identifier sweep and no method matrix —
requesting eight conventional paths is not enumeration, and growing that list
into one is exactly what this phase must not do.

Every request goes through the same `HttpFetcher` as the rest of the scanner, so
URL validation, the SSRF guard, the exact-origin lock, per-hop redirect
re-validation, redirect limits, timeouts, the response cap and the phase-11
authentication context all apply unchanged. There is no API transport.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from app.scanner.api.classifier import path_of
from app.scanner.api.discovery import (
    ApiSurfaceBuilder,
    endpoint_from_form,
    endpoint_from_observation,
)
from app.scanner.api.graphql import detect as detect_graphql
from app.scanner.api.graphql import detect_from_specification
from app.scanner.api.openapi import parse_specification
from app.scanner.api.parser import parse_json_body
from app.scanner.api.types import (
    ApiDiscoveryConfig,
    ApiSurface,
    GraphQlDetection,
)
from app.scanner.auth.types import AuthenticationContext
from app.scanner.cancellation import CancellationToken, ScanCancelled
from app.scanner.crawler.url_normalizer import Origin, is_same_origin, origin_of
from app.scanner.http_scanner import HttpFetcher, build_client
from app.scanner.types import RawHttpResponse, ScannerConfig, ScannerError, ScanReport, ScanTarget
from app.scanner.url_validator import parse_target_url

logger = logging.getLogger(__name__)


class ApiDiscoveryModule:
    """Classifies the discovered surface and looks for API documentation."""

    name = "api_discovery"

    def __init__(
        self,
        config: ScannerConfig,
        api_config: ApiDiscoveryConfig | None = None,
        cancellation: CancellationToken | None = None,
        authentication: AuthenticationContext | None = None,
    ) -> None:
        self._config = config
        self._api_config = api_config or ApiDiscoveryConfig()
        self._cancellation = cancellation or CancellationToken.none()
        self._authentication = authentication

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        if not self._api_config.enabled:
            report.api = ApiSurface()
            return

        builder = ApiSurfaceBuilder(self._api_config.limits)
        cancelled = False

        # Everything from the crawl first: it is already paid for, so a
        # cancelled or budget-limited scan still gets the classification it can
        # derive for free. It also establishes which paths were *seen* not to be
        # APIs, which a specification cannot override.
        refuted = self._classify_crawl(report, builder)
        self._classify_forms(report, builder)

        origin = origin_of(report.raw.final_url) if report.raw is not None else None
        if origin is not None and self._api_config.fetch_documents:
            try:
                await self._discover_documents(origin, builder, refuted)
            except ScanCancelled:
                cancelled = True

        report.api = builder.build()
        _record_metadata(report)

        if cancelled:
            # The partial surface is attached above before the pipeline unwinds,
            # so a cancelled scan keeps what it did classify.
            raise ScanCancelled(self.name)

    # ------------------------------------------------------------------ #
    # From what the scan already fetched
    # ------------------------------------------------------------------ #

    def _classify_crawl(
        self, report: ScanReport, builder: ApiSurfaceBuilder
    ) -> set[tuple[str, str]]:
        """Classify every endpoint the crawler reached. Sends nothing.

        Returns the identities the crawl saw and rejected — an HTML page at an
        API-shaped URL, typically. A specification entry for one of those does
        not resurrect it: the scanner watched the endpoint serve a web page, and
        a document claiming otherwise describes intent while the response
        describes behaviour.
        """
        refuted: set[tuple[str, str]] = set()
        if report.crawl is None:
            return refuted

        authenticated = bool(
            self._authentication is not None and self._authentication.configured
        )

        for discovered in report.crawl.endpoints:
            captured = report.crawl.responses.get(discovered.url)
            endpoint, classification = endpoint_from_observation(
                url=discovered.url,
                method=discovered.method,
                status_code=discovered.status_code,
                content_type=discovered.content_type,
                parameters=discovered.parameters,
                json_shape=captured.json_shape if captured is not None else None,
                authenticated_scan=authenticated,
                limits=self._api_config.limits,
            )
            if endpoint is None:
                # A weak signal seen and dismissed. Counted so the report can
                # distinguish "nothing looked like an API" from "something did
                # and was rejected".
                if classification.signals:
                    builder.stats.note("rejected:low_confidence")
                if "response:html" in classification.signals:
                    refuted.add((discovered.method.upper(), path_of(discovered.url)))
                continue

            builder.add(endpoint)

            detection = detect_graphql(
                url=discovered.url, content_type=discovered.content_type
            )
            builder.set_graphql(detection)

        return refuted

    def _classify_forms(self, report: ScanReport, builder: ApiSurfaceBuilder) -> None:
        """Form actions that point at an API. No form is ever submitted."""
        if report.crawl is None:
            return

        for form in report.crawl.forms:
            endpoint = endpoint_from_form(
                action=form.action,
                method=form.method,
                field_names=[field.name for field in form.fields],
                limits=self._api_config.limits,
            )
            if endpoint is not None:
                builder.add(endpoint)

    # ------------------------------------------------------------------ #
    # The only traffic this stage generates
    # ------------------------------------------------------------------ #

    async def _discover_documents(
        self,
        origin: Origin,
        builder: ApiSurfaceBuilder,
        refuted: set[tuple[str, str]] | None = None,
    ) -> None:
        """Request a small fixed set of conventional documentation paths.

        Bounded by `max_document_candidates` and by the list itself, which is a
        constant. A candidate that 404s, times out or returns HTML is simply not
        documentation: it is recorded as tried and the scan moves on.
        """
        limits = self._api_config.limits
        candidates = list(self._api_config.document_candidates)[
            : limits.max_document_candidates
        ]
        graphql_candidates = list(self._api_config.graphql_candidates)

        async with build_client(self._config) as client:
            fetcher = HttpFetcher(
                self._config,
                client,
                # Locked to the origin already being scanned. A redirect leaving
                # it is refused rather than followed, so neither the request nor
                # the phase-11 credential can travel off-origin.
                allow_url=lambda url: is_same_origin(url, origin),
                max_redirects=self._config.max_redirects,
                authentication=self._authentication,
            )

            for path in candidates:
                self._cancellation.raise_if_cancelled(self.name)
                builder.stats.document_candidates_tried += 1
                response = await self._fetch(fetcher, f"{origin.base_url}{path}", builder)
                if response is None:
                    continue
                self._read_document(
                    response, f"{origin.base_url}{path}", builder, refuted or set()
                )

            # GraphQL: only when the crawl has not already established it, and
            # only a plain GET. A GraphQL server answers one with an error that
            # identifies it, which is all this phase needs — no query and no
            # introspection is ever sent.
            if not builder.graphql_detected:
                for path in graphql_candidates:
                    self._cancellation.raise_if_cancelled(self.name)
                    url = f"{origin.base_url}{path}"
                    response = await self._fetch(fetcher, url, builder)
                    if response is None:
                        continue
                    detection = detect_graphql(
                        url=url,
                        content_type=response.headers.get("content-type"),
                        body=response.body,
                        status_code=response.status_code,
                    )
                    if detection.detected:
                        builder.set_graphql(detection)
                        break

    async def _fetch(
        self, fetcher: HttpFetcher, url: str, builder: ApiSurfaceBuilder
    ) -> RawHttpResponse | None:
        """One GET. Never raises: a failed candidate is not a failed scan."""
        try:
            probe_target = parse_target_url(url)
        except ScannerError:
            builder.stats.note("invalid_candidate_url")
            return None

        try:
            builder.stats.requests_sent += 1
            return await fetcher.fetch(probe_target)
        except ScannerError as exc:
            builder.stats.note(f"candidate_unavailable:{exc.code.value}")
            return None
        except ScanCancelled:
            raise
        except Exception:  # noqa: BLE001 - one candidate must not end the scan
            logger.exception("Unexpected failure fetching an API documentation candidate")
            builder.stats.note("candidate_unavailable:unexpected")
            return None

    def _read_document(
        self,
        response: RawHttpResponse,
        url: str,
        builder: ApiSurfaceBuilder,
        refuted: set[tuple[str, str]],
    ) -> None:
        """Parse a candidate response as a specification, if that is what it is."""
        if response.status_code < 200 or response.status_code >= 300:
            builder.stats.note(f"candidate_status:{response.status_code}")
            return

        document = parse_json_body(response.body)
        if document is None:
            builder.stats.note("candidate_not_json")
            return

        parsed = parse_specification(document, url=url, limits=self._api_config.limits)
        if parsed is None:
            builder.stats.note("candidate_not_a_specification")
            return

        summary, endpoints = parsed
        builder.add_document(summary)
        for endpoint in endpoints:
            if endpoint.identity in refuted:
                # The crawl watched this path serve a web page. A document
                # listing it does not make it an API.
                builder.stats.note("spec:contradicted_by_observation")
                continue
            builder.add(endpoint)

        detected, indicators = detect_from_specification(document)
        if detected:
            builder.set_graphql(
                GraphQlDetection(
                    detected=True, url=None, path=None, indicators=indicators
                )
            )

        logger.info(
            "API specification parsed: %s version=%s paths=%d operations=%d",
            _safe_path(url),
            summary.version,
            summary.path_count,
            summary.operation_count,
        )


def _record_metadata(report: ScanReport) -> None:
    if report.api is None:  # pragma: no cover - always set by run()
        return
    stats = report.api.stats
    report.metadata["api_endpoints_discovered"] = stats.endpoints_discovered
    report.metadata["api_documents_found"] = stats.documents_found
    report.metadata["api_requests_sent"] = stats.requests_sent
    if stats.graphql_endpoints:
        report.metadata["api_graphql_detected"] = True


def _safe_path(url: str) -> str:
    """The path of a URL, for logs. Never a query string."""
    try:
        return urlsplit(url).path or "/"
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return "?"
