"""Assembling one API surface from several sources.

Pure. Crawl results and parsed specifications in, a deduplicated `ApiSurface`
out. No transport, no budget of its own, no cancellation — those belong to the
module, which is what makes every merge rule here testable with plain objects.

The rule that shapes the whole file: **a second discovery adds to the first, it
does not replace it.** An endpoint found by the crawler and also described by
OpenAPI carries both sources, the stronger confidence, the observed URL and the
documented parameter list. Overwriting would silently discard the very evidence
that makes the record trustworthy.

Identity is `(method, path)` with query values excluded, which is the only
representation that stays finite: `/api/products?id=1` and `?id=2` are one
endpoint with a parameter called `id`, not two endpoints.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from app.scanner.api.classifier import (
    ApiClassification,
    classify,
    looks_like_graphql_path,
    media_type_of,
    path_looks_like_api,
    path_of,
)
from app.scanner.api.types import (
    ApiAuthStatus,
    ApiConfidence,
    ApiDiscoveryLimits,
    ApiEndpoint,
    ApiParameter,
    ApiParameterLocation,
    ApiSource,
    ApiStats,
    ApiSurface,
    GraphQlDetection,
    JsonShape,
    OpenApiDocument,
    merge_parameters,
    strongest,
)


def auth_status_for(
    status_code: int | None, *, authenticated_scan: bool
) -> ApiAuthStatus:
    """What one response says about needing credentials.

    Deliberately narrow. A 401 is unambiguous — the status exists to say
    "authenticate first" — so it is taken at face value. A **403 is not**: it is
    returned for authorization failures, CSRF checks, IP restrictions, blocked
    user agents and unsupported methods just as often as for a missing
    credential, so it yields UNKNOWN rather than a confident claim.

    A 2xx says which identity got in, and nothing about whether another one
    could: an authenticated scan reaching an endpoint does not establish that an
    anonymous request would have been refused. Phase 12's authorization testing
    is what answers that, by actually comparing identities.
    """
    if status_code is None:
        return ApiAuthStatus.UNKNOWN
    if status_code == 401:
        return ApiAuthStatus.AUTH_REQUIRED
    if 200 <= status_code < 300:
        return (
            ApiAuthStatus.AUTHENTICATED_ACCESSIBLE
            if authenticated_scan
            else ApiAuthStatus.ANONYMOUS_ACCESSIBLE
        )
    return ApiAuthStatus.UNKNOWN


def merge_endpoints(
    existing: ApiEndpoint, incoming: ApiEndpoint, limits: ApiDiscoveryLimits
) -> ApiEndpoint:
    """Combine two records of the same `(method, path)`.

    Sources union. Confidence takes the stronger. Every optional field takes
    whichever record actually has one, with the observed record winning where
    both do — what the endpoint really returned outranks what a document says it
    returns.
    """
    return ApiEndpoint(
        path=existing.path,
        method=existing.method,
        url=existing.url or incoming.url,
        confidence=strongest(existing.confidence, incoming.confidence),
        sources=existing.sources | incoming.sources,
        auth_status=(
            existing.auth_status
            if existing.auth_status is not ApiAuthStatus.UNKNOWN
            else incoming.auth_status
        ),
        request_media_type=existing.request_media_type or incoming.request_media_type,
        response_media_type=existing.response_media_type or incoming.response_media_type,
        status_code=existing.status_code if existing.status_code is not None else incoming.status_code,
        operation_id=existing.operation_id or incoming.operation_id,
        parameters=merge_parameters(
            existing.parameters, incoming.parameters, limits.max_parameters_per_endpoint
        ),
        security=existing.security or incoming.security,
        json_shape=existing.json_shape or incoming.json_shape,
    )


class ApiSurfaceBuilder:
    """Accumulates endpoints from every source, deduplicating as it goes."""

    def __init__(self, limits: ApiDiscoveryLimits | None = None) -> None:
        self._limits = limits or ApiDiscoveryLimits()
        self._endpoints: dict[tuple[str, str], ApiEndpoint] = {}
        self._documents: list[OpenApiDocument] = []
        self._graphql = GraphQlDetection()
        self.stats = ApiStats()

    @property
    def limits(self) -> ApiDiscoveryLimits:
        return self._limits

    def add(self, endpoint: ApiEndpoint) -> None:
        """Record one endpoint, merging it with any earlier record of the same."""
        key = endpoint.identity
        existing = self._endpoints.get(key)
        if existing is not None:
            self._endpoints[key] = merge_endpoints(existing, endpoint, self._limits)
            return

        if len(self._endpoints) >= self._limits.max_endpoints:
            # Fails closed: the surface stops growing and says that it did,
            # rather than silently reporting a partial inventory as complete.
            self.stats.truncated = True
            self.stats.note("endpoint_limit")
            return

        self._endpoints[key] = endpoint

    def add_all(self, endpoints: Iterable[ApiEndpoint]) -> None:
        for endpoint in endpoints:
            self.add(endpoint)

    @property
    def graphql_detected(self) -> bool:
        """Whether GraphQL has already been established.

        A property rather than a peek at `build()`, which has side effects: it
        recomputes the counters, so calling it mid-flight would corrupt them.
        """
        return self._graphql.detected

    def add_document(self, document: OpenApiDocument) -> None:
        self._documents.append(document)

    def set_graphql(self, detection: GraphQlDetection) -> None:
        """Keep the first positive detection; later ones only add indicators."""
        if not detection.detected:
            return
        if not self._graphql.detected:
            self._graphql = detection
            return
        self._graphql = GraphQlDetection(
            detected=True,
            url=self._graphql.url,
            path=self._graphql.path,
            indicators=tuple(
                dict.fromkeys(self._graphql.indicators + detection.indicators)
            ),
            introspection_tested=False,
        )

    def build(self) -> ApiSurface:
        endpoints = tuple(
            sorted(self._endpoints.values(), key=lambda e: (e.path, e.method))
        )

        self.stats.endpoints_discovered = len(endpoints)
        self.stats.endpoints_observed = sum(1 for e in endpoints if e.observed)
        self.stats.endpoints_documented_only = sum(
            1 for e in endpoints if e.documented_only
        )
        self.stats.parameters_discovered = len(
            {(e.identity, p.identity) for e in endpoints for p in e.parameters}
        )
        self.stats.documents_found = len(self._documents)
        self.stats.authenticated_endpoints = sum(
            1
            for e in endpoints
            if e.auth_status
            in (ApiAuthStatus.AUTHENTICATED_ACCESSIBLE, ApiAuthStatus.AUTH_REQUIRED)
        )
        self.stats.unknown_auth_endpoints = sum(
            1 for e in endpoints if e.auth_status is ApiAuthStatus.UNKNOWN
        )
        self.stats.graphql_endpoints = 1 if self._graphql.detected else 0

        return ApiSurface(
            endpoints=endpoints,
            documents=tuple(self._documents),
            graphql=self._graphql,
            stats=self.stats,
        )


def endpoint_from_observation(
    *,
    url: str,
    method: str,
    status_code: int | None,
    content_type: str | None,
    parameters: Sequence[str],
    json_shape: JsonShape | None,
    authenticated_scan: bool,
    documented_paths: frozenset[str] = frozenset(),
    limits: ApiDiscoveryLimits | None = None,
) -> tuple[ApiEndpoint | None, ApiClassification]:
    """Classify one crawled endpoint.

    Returns the endpoint and the classification that produced it. A LOW-
    confidence result yields `None` for the endpoint but keeps its classification
    so the caller can count and explain what it rejected — a signal seen and
    dismissed is a different thing from a signal never noticed.
    """
    bounds = limits or ApiDiscoveryLimits()
    path = path_of(url)

    classification = classify(
        path=path,
        response_content_type=content_type,
        status_code=status_code,
        documented=path in documented_paths,
        json_parsed=json_shape is not None,
    )
    if not classification.is_api:
        return None, classification

    sources = {ApiSource.CRAWLER, ApiSource.RESPONSE_ANALYSIS}
    if looks_like_graphql_path(path):
        sources.add(ApiSource.GRAPHQL)

    endpoint = ApiEndpoint(
        path=path,
        method=method.upper(),
        url=url,
        confidence=classification.confidence,
        sources=frozenset(sources),
        auth_status=auth_status_for(status_code, authenticated_scan=authenticated_scan),
        response_media_type=media_type_of(content_type),
        status_code=status_code,
        parameters=tuple(
            ApiParameter(name=name, location=ApiParameterLocation.QUERY)
            for name in list(parameters)[: bounds.max_parameters_per_endpoint]
        ),
        json_shape=json_shape,
    )
    return endpoint, classification


def endpoint_from_form(
    *,
    action: str,
    method: str,
    field_names: Sequence[str],
    limits: ApiDiscoveryLimits | None = None,
) -> ApiEndpoint | None:
    """An API endpoint implied by a form action.

    Only when the action itself looks like an API. A form posting to `/contact`
    is a web form, and recording it as an API operation would inflate the count
    with pages that merely accept input.

    The form is never submitted. Its field names describe the interface and
    nothing else — no value from a form control is read, let alone stored.
    """
    bounds = limits or ApiDiscoveryLimits()
    path = path_of(action)
    # A form action has no response to weigh, so the path convention is the only
    # evidence there is. `classify` would rightly grade that LOW; here it is the
    # whole question, and a form posting to an API path is worth recording.
    if not path_looks_like_api(path):
        return None

    return ApiEndpoint(
        path=path,
        method=(method or "GET").upper(),
        url=action if "://" in action else None,
        confidence=ApiConfidence.MEDIUM,
        sources=frozenset({ApiSource.FORM}),
        parameters=tuple(
            # A form's controls become the request body, so BODY is where they
            # would be carried. Names only, and nothing is ever submitted.
            ApiParameter(name=name, location=ApiParameterLocation.BODY)
            for name in list(field_names)[: bounds.max_parameters_per_endpoint]
        ),
    )
