"""API discovery: classification, specifications, GraphQL, safety, privacy.

Phase 13 is reconnaissance. These tests are therefore as concerned with what the
scanner does **not** do — invoke a documented operation, run introspection, send
a body, enumerate paths, keep a response value — as with what it finds.

The pure tests need nothing but strings and dictionaries. The rest run against a
loopback application started inside this process, which serves a mixture of real
APIs, an HTML page at an API-looking path, a protected API, an OpenAPI document,
a Swagger document and a GraphQL endpoint. The HTML-at-`/api/` route matters
most: a classifier that cannot ignore it turns every inventory into noise.
"""

from __future__ import annotations

import json
import secrets
import socket
import threading
import time
import uuid

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.main import app as api_app
from app.models.api_surface import ApiDocument, ApiEndpointRow, split_list
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner import ScannerConfig, WebScanner
from app.scanner.api.classifier import (
    classify,
    is_api_media_type,
    media_kind,
    path_looks_like_api,
)
from app.scanner.api.discovery import (
    ApiSurfaceBuilder,
    auth_status_for,
    endpoint_from_form,
    endpoint_from_observation,
    merge_endpoints,
)
from app.scanner.api.graphql import detect as detect_graphql
from app.scanner.api.openapi import looks_like_specification, parse_specification
from app.scanner.api.parser import parse_json_body, summarize_body, summarize_json
from app.scanner.api.types import (
    ApiAuthStatus,
    ApiConfidence,
    ApiDiscoveryConfig,
    ApiDiscoveryLimits,
    ApiEndpoint,
    ApiMediaKind,
    ApiParameter,
    ApiParameterLocation,
    ApiSource,
)
from app.scanner.auth import AuthMode
from app.scanner.auth.context import build_context
from app.scanner.cancellation import CancellationToken
from app.scanner.crawler.types import CrawlConfig
from app.services import api_surface_service, scan_service

PASSWORD = "Sup3rSecret!pass"
API_TOKEN = "phase13-api-token"

#: A value that must never appear anywhere the scanner persists or returns.
SECRET_VALUE = "SUPER-SECRET-RECORD-VALUE-9x7"


# --------------------------------------------------------------------------- #
# A target with real APIs, a decoy, a spec and a GraphQL endpoint
# --------------------------------------------------------------------------- #


OPENAPI_DOCUMENT = {
    "openapi": "3.0.3",
    "info": {"title": "Shop API", "version": "2.1"},
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
            "apiKey": {"type": "apiKey", "in": "header", "name": "X-Api-Key"},
        }
    },
    "paths": {
        "/api/products": {
            "get": {
                "operationId": "listProducts",
                "parameters": [
                    {"name": "limit", "in": "query", "required": False},
                    {"name": "X-Trace", "in": "header"},
                ],
                "responses": {"200": {"content": {"application/json": {}}}},
            },
            "post": {
                "operationId": "createProduct",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "required": ["name"],
                                "properties": {"name": {}, "price": {}},
                            }
                        }
                    }
                },
                "responses": {"201": {"content": {"application/json": {}}}},
                "security": [{"bearerAuth": []}],
            },
        },
        # Documented and never reachable: nothing serves this path.
        "/api/legacy/{id}": {
            "delete": {
                "operationId": "deleteLegacy",
                "parameters": [{"name": "id", "in": "path", "required": True}],
            }
        },
    },
}

SWAGGER_DOCUMENT = {
    "swagger": "2.0",
    "info": {"title": "Legacy", "version": "1.0"},
    "securityDefinitions": {"legacyKey": {"type": "apiKey", "in": "query", "name": "key"}},
    "paths": {
        "/v1/orders": {
            "get": {
                "operationId": "listOrders",
                "produces": ["application/json"],
                "parameters": [{"name": "page", "in": "query"}],
            }
        }
    },
}


def build_target_app() -> FastAPI:
    """A target with APIs, a decoy HTML page at an API path, and documentation."""
    # `openapi_url=None` matters: without it the framework serves its own
    # generated schema at /openapi.json, which documents every route including
    # the HTML ones, and the fixture would be testing the framework rather than
    # the scanner.
    target = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    received: list[dict[str, str | None]] = []
    target.state.received = received

    @target.middleware("http")
    async def record(request: Request, call_next):
        received.append(
            {
                "method": request.method,
                "path": request.url.path,
                "authorization": request.headers.get("authorization"),
            }
        )
        return await call_next(request)

    def page(title: str, body: str) -> str:
        return (
            f"<!doctype html><html><head><title>{title}</title></head>"
            f"<body><p>{body}</p></body></html>"
        )

    @target.get("/")
    def index() -> HTMLResponse:
        return HTMLResponse(
            page(
                "Home",
                '<a href="/api/products?limit=10">products</a> '
                '<a href="/api/about">about</a> '
                '<a href="/api/search?q=hello">search</a> '
                '<a href="/private/api/orders">orders</a> '
                '<a href="/graphql">graphql</a> '
                '<a href="/docs-page">docs</a>',
            )
        )

    @target.get("/api/products")
    def products(limit: int = 10) -> JSONResponse:
        return JSONResponse(
            {
                "items": [{"id": 1, "name": "Anvil", "price": 10}],
                "total": 1,
                "secret_note": SECRET_VALUE,
            }
        )

    @target.get("/api/search")
    def search(q: str = "") -> JSONResponse:
        return JSONResponse({"query": q, "results": [], "count": 0})

    @target.get("/api/about")
    def about() -> HTMLResponse:
        """The decoy: an API-looking path that is an ordinary web page."""
        return HTMLResponse(page("About our API", "We have an API. This is not it."))

    @target.get("/docs-page")
    def docs_page() -> HTMLResponse:
        return HTMLResponse(page("Docs", "Human documentation."))

    @target.get("/private/api/orders")
    def orders(request: Request):
        if request.headers.get("authorization") != f"Bearer {API_TOKEN}":
            return Response(status_code=401)
        return JSONResponse({"orders": [{"id": 101, "total": 25}], "owner": "alice"})

    @target.get("/openapi.json")
    def openapi_document() -> JSONResponse:
        return JSONResponse(OPENAPI_DOCUMENT)

    @target.get("/swagger.json")
    def swagger_document() -> JSONResponse:
        return JSONResponse(SWAGGER_DOCUMENT)

    @target.get("/graphql")
    def graphql() -> JSONResponse:
        """A GraphQL server's answer to a GET with no query. Deterministic."""
        return JSONResponse(
            {"errors": [{"message": "Must provide query string."}]}, status_code=400
        )

    return target


class _Server:
    def __init__(self, app: FastAPI) -> None:
        self.app = app
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error")
        )
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def received(self) -> list[dict[str, str | None]]:
        return self.app.state.received

    def start(self) -> None:
        self._thread.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("the target fixture did not start")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


@pytest.fixture(scope="module")
def target():
    server = _Server(build_target_app())
    server.start()
    try:
        yield server
    finally:
        server.stop()


def scanner_config() -> ScannerConfig:
    return ScannerConfig(
        timeout_seconds=5.0, total_timeout_seconds=90.0, allow_private_networks=True
    )


def run_scan(base_url: str, *, authenticated: bool = False, **overrides):
    authentication = (
        build_context(AuthMode.BEARER_TOKEN, base_url, token=API_TOKEN)
        if authenticated
        else None
    )
    return WebScanner(
        scanner_config(),
        crawl_config=CrawlConfig(max_pages=20, max_depth=3, time_budget_seconds=30),
        detectors=[],
        authentication=authentication,
        api_config=ApiDiscoveryConfig(**overrides),
    ).scan_sync(base_url)


def by_identity(surface) -> dict[tuple[str, str], ApiEndpoint]:
    return {endpoint.identity: endpoint for endpoint in surface.endpoints}


# --------------------------------------------------------------------------- #
# 1. Classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("content_type", "expected"),
    [
        ("application/json", ApiMediaKind.JSON),
        ("application/json; charset=utf-8", ApiMediaKind.JSON),
        ("application/problem+json", ApiMediaKind.JSON),
        ("application/vnd.example.v2+json", ApiMediaKind.JSON),
        ("application/ld+json", ApiMediaKind.JSON),
        ("application/xml", ApiMediaKind.XML),
        ("text/xml", ApiMediaKind.XML),
        ("application/graphql-response+json", ApiMediaKind.GRAPHQL),
        ("text/html", ApiMediaKind.HTML),
        # A +xml suffix that is a document, not an API payload.
        ("application/xhtml+xml", ApiMediaKind.HTML),
        ("application/x-www-form-urlencoded", ApiMediaKind.FORM),
        ("multipart/form-data", ApiMediaKind.MULTIPART),
        ("image/png", ApiMediaKind.OTHER),
        (None, ApiMediaKind.UNKNOWN),
    ],
)
def test_media_kinds(content_type, expected):
    assert media_kind(content_type) is expected


def test_only_payload_media_types_are_api_evidence():
    assert is_api_media_type("application/json") is True
    assert is_api_media_type("application/problem+json") is True
    assert is_api_media_type("text/html") is False
    assert is_api_media_type("application/xhtml+xml") is False


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/api/products", True),
        ("/rest/orders", True),
        ("/v1/users", True),
        ("/v2.1/users", True),
        ("/graphql", True),
        # Words that merely begin with "api" are not API paths.
        ("/apiary/blog", False),
        ("/rapid/thing", False),
        ("/about", False),
        # A version segment deep in a path is a document, not a surface.
        ("/blog/2024/v1/post", False),
    ],
)
def test_path_conventions(path, expected):
    assert path_looks_like_api(path) is expected


def test_a_json_response_is_high_confidence():
    result = classify(path="/products/search", response_content_type="application/json")
    assert result.confidence is ApiConfidence.HIGH
    assert result.is_api is True


def test_an_api_path_returning_html_is_not_an_api():
    """The decoy case. Naming alone must never make something an API."""
    result = classify(path="/api/about", response_content_type="text/html; charset=utf-8")
    assert result.confidence is ApiConfidence.LOW
    assert result.is_api is False
    assert "path:api-convention" in result.signals
    assert "response:html" in result.signals


def test_a_mislabelled_json_body_is_still_an_api():
    """An API that forgets its Content-Type is still an API."""
    result = classify(path="/data", response_content_type="text/plain", json_parsed=True)
    assert result.confidence is ApiConfidence.HIGH


def test_documentation_alone_is_medium_confidence():
    """A specification describes intent. It does not prove behaviour."""
    result = classify(path="/api/legacy", documented=True)
    assert result.confidence is ApiConfidence.MEDIUM
    assert result.is_api is True


def test_an_ordinary_page_is_not_an_api():
    assert classify(path="/about", response_content_type="text/html").is_api is False


# --------------------------------------------------------------------------- #
# 2. JSON summarising keeps structure and discards content
# --------------------------------------------------------------------------- #


def test_a_json_summary_keeps_names_and_no_values():
    body = json.dumps(
        {
            "id": 123,
            "name": "Alice",
            "email": "alice@example.com",
            "access_token": SECRET_VALUE,
            "role": "user",
        }
    )
    shape = summarize_body(body)

    assert shape is not None
    assert shape.top_level == "object"
    assert set(shape.field_names) == {"id", "name", "email", "access_token", "role"}
    # The names describe the interface; not one value survives.
    rendered = str(shape)
    assert SECRET_VALUE not in rendered
    assert "Alice" not in rendered
    assert "alice@example.com" not in rendered


def test_a_nested_summary_is_bounded_in_depth():
    document = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}}
    shape = summarize_json(document, ApiDiscoveryLimits(max_json_depth=3))

    assert shape.truncated is True
    assert shape.depth <= 4


def test_a_wide_summary_is_bounded_in_breadth():
    document = {f"field{i}": i for i in range(500)}
    shape = summarize_json(document, ApiDiscoveryLimits(max_json_fields=10))

    assert len(shape.field_names) == 10
    assert shape.truncated is True
    # The count still reports the real width, so a truncated list is never
    # mistaken for the whole interface.
    assert shape.field_count == 500


def test_an_array_response_is_summarised():
    shape = summarize_body(json.dumps([{"id": 1, "name": "x"}, {"id": 2, "name": "y"}]))
    assert shape is not None
    assert shape.top_level == "array"
    assert set(shape.field_names) == {"id", "name"}


@pytest.mark.parametrize(
    "body", ["", "<html><body>hi</body></html>", "not json at all", b"\x00\x01\x02"]
)
def test_a_non_json_body_yields_nothing(body):
    assert summarize_body(body) is None
    assert parse_json_body(body) is None


# --------------------------------------------------------------------------- #
# 3. OpenAPI and Swagger
# --------------------------------------------------------------------------- #


def test_openapi_3_is_parsed():
    parsed = parse_specification(OPENAPI_DOCUMENT, url="https://x/openapi.json")
    assert parsed is not None
    document, endpoints = parsed

    assert document.version == "3.0.3"
    assert document.title == "Shop API"
    assert document.document_version == "2.1"
    assert document.path_count == 2
    assert {scheme.name for scheme in document.security_schemes} == {"bearerAuth", "apiKey"}
    assert document.source is ApiSource.OPENAPI

    operations = {(e.method, e.path) for e in endpoints}
    assert ("GET", "/api/products") in operations
    assert ("POST", "/api/products") in operations
    assert ("DELETE", "/api/legacy/{id}") in operations


def test_openapi_parameters_carry_location_and_requiredness():
    _, endpoints = parse_specification(OPENAPI_DOCUMENT, url="https://x/openapi.json")
    get_products = next(e for e in endpoints if e.method == "GET")

    by_name = {p.name: p for p in get_products.parameters}
    assert by_name["limit"].location is ApiParameterLocation.QUERY
    assert by_name["limit"].required is False
    assert by_name["X-Trace"].location is ApiParameterLocation.HEADER
    # Nobody said, and that is different from saying no.
    assert by_name["X-Trace"].required is None


def test_a_documented_request_body_yields_field_names_only():
    _, endpoints = parse_specification(OPENAPI_DOCUMENT, url="https://x/openapi.json")
    post = next(e for e in endpoints if e.method == "POST")

    body_fields = {p.name: p for p in post.parameters if p.location is ApiParameterLocation.BODY}
    assert set(body_fields) == {"name", "price"}
    assert body_fields["name"].required is True
    assert post.security == ("bearerAuth",)
    assert post.request_media_type == "application/json"


def test_swagger_2_is_parsed():
    parsed = parse_specification(SWAGGER_DOCUMENT, url="https://x/swagger.json")
    assert parsed is not None
    document, endpoints = parsed

    assert document.version == "2.0"
    assert document.source is ApiSource.SWAGGER
    assert {scheme.name for scheme in document.security_schemes} == {"legacyKey"}

    orders = endpoints[0]
    assert orders.method == "GET"
    assert orders.path == "/v1/orders"
    assert orders.operation_id == "listOrders"
    assert orders.response_media_type == "application/json"
    assert orders.parameters[0].name == "page"


def test_every_specification_operation_is_documented_not_observed():
    """A document is a claim. Nothing here has been shown to exist."""
    _, endpoints = parse_specification(OPENAPI_DOCUMENT, url="https://x/openapi.json")
    assert all(e.documented and not e.observed for e in endpoints)
    assert all(e.documented_only for e in endpoints)
    assert all(e.url is None for e in endpoints)


@pytest.mark.parametrize(
    "document",
    [
        None,
        "a string",
        123,
        {},
        {"openapi": "3.0.0"},  # a version with no paths describes no surface
        {"paths": {}},  # paths with no version is not a specification
        {"openapi": "3.0.0", "paths": "not an object"},
    ],
)
def test_a_non_specification_is_refused(document):
    assert looks_like_specification(document) is False
    assert parse_specification(document, url="https://x/x.json") is None


def test_a_malformed_specification_does_not_raise():
    """A target's broken JSON is not a reason to fail a scan."""
    document = {
        "openapi": "3.0.0",
        "paths": {
            "/ok": {"get": {"operationId": "fine"}},
            "/broken": {"get": "not an object"},
            "not-a-path": {"get": {}},
            "/params": {"get": {"parameters": ["nonsense", {"no_name": 1}]}},
        },
    }
    parsed = parse_specification(document, url="https://x/x.json")
    assert parsed is not None
    _, endpoints = parsed
    assert ("GET", "/ok") in {(e.method, e.path) for e in endpoints}


def test_path_parsing_is_bounded():
    document = {
        "openapi": "3.0.0",
        "paths": {f"/p{i}": {"get": {}} for i in range(100)},
    }
    parsed = parse_specification(
        document, url="https://x/x.json", limits=ApiDiscoveryLimits(max_parsed_paths=10)
    )
    assert parsed is not None
    summary, endpoints = parsed
    assert summary.truncated is True
    assert summary.path_count == 10
    assert len(endpoints) == 10


def test_parameters_are_bounded_per_operation():
    document = {
        "openapi": "3.0.0",
        "paths": {
            "/wide": {
                "get": {
                    "parameters": [
                        {"name": f"p{i}", "in": "query"} for i in range(100)
                    ]
                }
            }
        },
    }
    _, endpoints = parse_specification(
        document,
        url="https://x/x.json",
        limits=ApiDiscoveryLimits(max_parameters_per_endpoint=5),
    )
    assert len(endpoints[0].parameters) == 5


# --------------------------------------------------------------------------- #
# 4. GraphQL: presence only
# --------------------------------------------------------------------------- #


def test_the_conventional_path_is_detected():
    detection = detect_graphql(url="https://x/graphql")
    assert detection.detected is True
    assert detection.path == "/graphql"
    assert detection.introspection_tested is False


def test_a_graphql_media_type_is_conclusive():
    detection = detect_graphql(
        url="https://x/q", content_type="application/graphql-response+json"
    )
    assert detection.detected is True
    assert "response:graphql-media-type" in detection.indicators


def test_a_graphql_error_envelope_is_recognised():
    body = '{"errors":[{"message":"Must provide query string."}]}'
    detection = detect_graphql(url="https://x/q", content_type="application/json", body=body)
    assert detection.detected is True


def test_an_ordinary_page_is_not_graphql():
    assert detect_graphql(url="https://x/about", content_type="text/html").detected is False


def test_introspection_is_never_recorded_as_tested():
    """Phase 13 detects GraphQL. It never queries it, and says so."""
    for detection in (
        detect_graphql(url="https://x/graphql"),
        detect_graphql(url="https://x/q", content_type="application/graphql+json"),
    ):
        assert detection.introspection_tested is False


# --------------------------------------------------------------------------- #
# 5. Discovery, merging and identity
# --------------------------------------------------------------------------- #


def test_query_values_never_create_separate_endpoints():
    """The rule that keeps an inventory finite."""
    builder = ApiSurfaceBuilder()
    for url in (
        "https://x.test/api/products?id",
        "https://x.test/api/products?id",
    ):
        endpoint, _ = endpoint_from_observation(
            url=url,
            method="GET",
            status_code=200,
            content_type="application/json",
            parameters=("id",),
            json_shape=None,
            authenticated_scan=False,
        )
        builder.add(endpoint)

    surface = builder.build()
    assert surface.stats.endpoints_discovered == 1
    assert surface.endpoints[0].path == "/api/products"


def test_a_second_source_adds_rather_than_replaces():
    observed = ApiEndpoint(
        path="/api/products",
        method="GET",
        url="https://x.test/api/products",
        confidence=ApiConfidence.HIGH,
        sources=frozenset({ApiSource.CRAWLER}),
        auth_status=ApiAuthStatus.ANONYMOUS_ACCESSIBLE,
        status_code=200,
        response_media_type="application/json",
    )
    documented = ApiEndpoint(
        path="/api/products",
        method="GET",
        confidence=ApiConfidence.MEDIUM,
        sources=frozenset({ApiSource.OPENAPI}),
        operation_id="listProducts",
        parameters=(ApiParameter(name="limit", required=False),),
    )

    merged = merge_endpoints(observed, documented, ApiDiscoveryLimits())

    assert merged.sources == {ApiSource.CRAWLER, ApiSource.OPENAPI}
    assert merged.confidence is ApiConfidence.HIGH
    assert merged.url == "https://x.test/api/products"
    assert merged.operation_id == "listProducts"
    assert merged.observed is True
    assert merged.documented is True
    assert merged.documented_only is False


def test_a_documented_parameter_supersedes_an_observed_one():
    """Only a specification knows whether a parameter is required."""
    observed = ApiEndpoint(
        path="/a", parameters=(ApiParameter(name="id"),), sources=frozenset({ApiSource.CRAWLER})
    )
    documented = ApiEndpoint(
        path="/a",
        parameters=(ApiParameter(name="id", required=True),),
        sources=frozenset({ApiSource.OPENAPI}),
    )
    merged = merge_endpoints(observed, documented, ApiDiscoveryLimits())
    assert merged.parameters[0].required is True


def test_the_endpoint_budget_fails_closed():
    builder = ApiSurfaceBuilder(ApiDiscoveryLimits(max_endpoints=3))
    for i in range(10):
        builder.add(ApiEndpoint(path=f"/api/{i}", sources=frozenset({ApiSource.CRAWLER})))

    surface = builder.build()
    assert surface.stats.endpoints_discovered == 3
    assert surface.stats.truncated is True


def test_a_low_confidence_observation_is_rejected_but_explained():
    endpoint, classification = endpoint_from_observation(
        url="https://x.test/api/about",
        method="GET",
        status_code=200,
        content_type="text/html",
        parameters=(),
        json_shape=None,
        authenticated_scan=False,
    )
    assert endpoint is None
    assert classification.signals  # seen and dismissed, not unnoticed


@pytest.mark.parametrize(
    ("status", "authenticated", "expected"),
    [
        (200, False, ApiAuthStatus.ANONYMOUS_ACCESSIBLE),
        (200, True, ApiAuthStatus.AUTHENTICATED_ACCESSIBLE),
        (401, False, ApiAuthStatus.AUTH_REQUIRED),
        # 403 is returned for authorization, CSRF, IP rules and bad methods just
        # as often as for a missing credential.
        (403, False, ApiAuthStatus.UNKNOWN),
        (500, False, ApiAuthStatus.UNKNOWN),
        (None, False, ApiAuthStatus.UNKNOWN),
    ],
)
def test_auth_status_is_conservative(status, authenticated, expected):
    assert auth_status_for(status, authenticated_scan=authenticated) is expected


def test_only_api_shaped_form_actions_become_endpoints():
    assert (
        endpoint_from_form(action="/contact", method="POST", field_names=["email"]) is None
    )
    endpoint = endpoint_from_form(
        action="/api/subscribe", method="POST", field_names=["email"]
    )
    assert endpoint is not None
    assert endpoint.sources == {ApiSource.FORM}
    assert endpoint.parameters[0].location is ApiParameterLocation.BODY


# --------------------------------------------------------------------------- #
# 6. End to end against the fixture
# --------------------------------------------------------------------------- #


def test_a_scan_discovers_the_json_apis(target):
    report = run_scan(target.base_url)

    assert report.api is not None
    endpoints = by_identity(report.api)

    assert ("GET", "/api/products") in endpoints
    assert ("GET", "/api/search") in endpoints
    assert endpoints[("GET", "/api/products")].confidence is ApiConfidence.HIGH
    assert endpoints[("GET", "/api/products")].observed is True


def test_the_html_decoy_is_not_classified_as_an_api(target):
    """`/api/about` returns HTML. Naming is not evidence."""
    report = run_scan(target.base_url)
    endpoints = by_identity(report.api)

    assert ("GET", "/api/about") not in endpoints
    assert ("GET", "/docs-page") not in endpoints


def test_json_field_names_are_captured_without_values(target):
    report = run_scan(target.base_url)
    products = by_identity(report.api)[("GET", "/api/products")]

    assert products.json_shape is not None
    assert "items" in products.json_shape.field_names
    assert "secret_note" in products.json_shape.field_names
    # The name of the field is interface; the value in it is not.
    assert SECRET_VALUE not in str(products.json_shape)


def test_query_parameters_are_recorded_by_name(target):
    report = run_scan(target.base_url)
    search = by_identity(report.api)[("GET", "/api/search")]

    assert [p.name for p in search.parameters] == ["q"]
    assert search.parameters[0].location is ApiParameterLocation.QUERY


def test_the_openapi_document_is_found_and_parsed(target):
    report = run_scan(target.base_url)

    versions = {document.version for document in report.api.documents}
    assert "3.0.3" in versions
    assert "2.0" in versions
    assert report.api.stats.documents_found >= 2


def test_a_documented_but_unreachable_operation_is_marked_as_such(target):
    """Nothing serves `/api/legacy/{id}`. It is documented and nothing more."""
    report = run_scan(target.base_url)
    legacy = by_identity(report.api)[("DELETE", "/api/legacy/{id}")]

    assert legacy.documented is True
    assert legacy.observed is False
    assert legacy.documented_only is True
    assert legacy.url is None


def test_an_endpoint_found_twice_carries_both_sources(target):
    """`/api/products` is crawled and documented. Both should survive."""
    report = run_scan(target.base_url)
    products = by_identity(report.api)[("GET", "/api/products")]

    assert ApiSource.CRAWLER in products.sources
    assert ApiSource.OPENAPI in products.sources
    assert products.operation_id == "listProducts"
    assert products.observed is True
    assert products.documented is True


def test_graphql_is_detected_without_being_queried(target):
    before = len(target.received)
    report = run_scan(target.base_url)

    assert report.api.graphql.detected is True
    assert report.api.graphql.introspection_tested is False

    # Not one request to the GraphQL endpoint used anything but GET, and no
    # request carried a body.
    graphql_requests = [
        entry for entry in target.received[before:] if entry["path"] == "/graphql"
    ]
    assert graphql_requests
    assert {entry["method"] for entry in graphql_requests} == {"GET"}


def test_no_documented_operation_is_ever_invoked(target):
    """A DELETE appears in the specification. It must never be sent."""
    before = len(target.received)
    run_scan(target.base_url)

    methods = {entry["method"] for entry in target.received[before:]}
    assert methods == {"GET"}
    assert not any(
        entry["path"].startswith("/api/legacy") for entry in target.received[before:]
    )


def test_documentation_candidates_stay_on_the_scanned_origin(target):
    before = len(target.received)
    run_scan(target.base_url)

    paths = [entry["path"] for entry in target.received[before:]]
    # Every documentation candidate is a path on this origin, and the set tried
    # is the small fixed list — not an enumeration.
    tried = [p for p in paths if p.endswith(("openapi.json", "swagger.json", "api-docs"))]
    assert tried
    assert len(tried) <= 8


def test_the_candidate_budget_is_respected(target):
    before = len(target.received)
    run_scan(target.base_url, limits=ApiDiscoveryLimits(max_document_candidates=2))

    paths = [entry["path"] for entry in target.received[before:]]
    assert "/openapi.json" in paths
    assert "/api/openapi.json" not in paths


def test_document_discovery_can_be_turned_off(target):
    before = len(target.received)
    report = run_scan(target.base_url, fetch_documents=False)

    paths = [entry["path"] for entry in target.received[before:]]
    assert "/openapi.json" not in paths
    assert "/swagger.json" not in paths
    # Classification of what the crawl already fetched still works.
    assert ("GET", "/api/products") in by_identity(report.api)


def test_the_stage_can_be_disabled_entirely(target):
    report = run_scan(target.base_url, enabled=False)
    assert report.api is not None
    assert report.api.stats.endpoints_discovered == 0


def test_cancellation_stops_document_discovery(target):
    report = WebScanner(
        scanner_config(),
        crawl_config=CrawlConfig(),
        detectors=[],
        api_config=ApiDiscoveryConfig(),
        cancellation=CancellationToken(lambda: True),
    ).scan_sync(target.base_url)

    assert report.cancelled is True


def test_an_authenticated_scan_reaches_the_protected_api(target):
    anonymous = run_scan(target.base_url)
    authenticated = run_scan(target.base_url, authenticated=True)

    anon_orders = by_identity(anonymous.api).get(("GET", "/private/api/orders"))
    auth_orders = by_identity(authenticated.api).get(("GET", "/private/api/orders"))

    # Anonymous gets a 401, which is a refusal rather than an API payload, so it
    # is recorded as needing authentication rather than as accessible.
    if anon_orders is not None:
        assert anon_orders.auth_status is ApiAuthStatus.AUTH_REQUIRED

    assert auth_orders is not None
    assert auth_orders.auth_status is ApiAuthStatus.AUTHENTICATED_ACCESSIBLE
    assert auth_orders.confidence is ApiConfidence.HIGH


def test_the_authentication_credential_never_leaves_the_origin(target):
    """Phase 11's guarantee, unchanged by API discovery."""
    context = build_context(AuthMode.BEARER_TOKEN, target.base_url, token=API_TOKEN)
    assert context.applies_to(f"{target.base_url}/openapi.json") is True
    assert context.applies_to("http://127.0.0.2:9/openapi.json") is False
    assert dict(context.headers_for("http://127.0.0.2:9/openapi.json")) == {}


# --------------------------------------------------------------------------- #
# 7. Persistence and the API
# --------------------------------------------------------------------------- #


@pytest.fixture
def client():
    with TestClient(api_app) as test_client:
        yield test_client


@pytest.fixture
def allow_loopback(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "SCANNER_ALLOW_PRIVATE_NETWORKS", True)
    yield


def register(client: TestClient) -> uuid.UUID:
    email = f"api-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={
            "name": "API Test",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


def scan_the_fixture(client: TestClient, base_url: str) -> uuid.UUID:
    user_id = register(client)
    with SessionLocal() as db:
        scan_id = scan_service.enqueue_scan(db, db.get(User, user_id), base_url)
    scan_service.execute_scan(scan_id)
    return scan_id


def test_the_surface_is_persisted_with_no_response_values(
    client, allow_loopback, target
):
    scan_id = scan_the_fixture(client, target.base_url)

    with SessionLocal() as db:
        rows = list(
            db.scalars(select(ApiEndpointRow).where(ApiEndpointRow.scan_id == scan_id))
        )
        documents = list(
            db.scalars(select(ApiDocument).where(ApiDocument.scan_id == scan_id))
        )
        dumped = str(
            [{c.name: getattr(row, c.name) for c in row.__table__.columns} for row in rows]
        )

    assert rows
    assert documents
    assert SECRET_VALUE not in dumped
    # Field names survive; the values behind them do not.
    products = next(r for r in rows if r.path == "/api/products" and r.method == "GET")
    assert "secret_note" in split_list(products.json_field_names)


def test_an_observed_endpoint_links_to_its_crawl_row(client, allow_loopback, target):
    scan_id = scan_the_fixture(client, target.base_url)

    with SessionLocal() as db:
        rows = list(
            db.scalars(select(ApiEndpointRow).where(ApiEndpointRow.scan_id == scan_id))
        )

    observed = [row for row in rows if row.observed]
    documented_only = [row for row in rows if row.documented and not row.observed]

    assert observed and all(row.endpoint_id is not None for row in observed)
    # A documented-only operation has no crawl row, and that absence is the
    # record of nobody having requested it.
    assert documented_only and all(row.endpoint_id is None for row in documented_only)


def test_the_api_endpoints_route_exposes_the_surface(client, allow_loopback, target):
    scan_id = scan_the_fixture(client, target.base_url)

    body = client.get(f"/api/scans/{scan_id}/api-endpoints").json()

    assert body["summary"]["detected"] is True
    assert body["summary"]["endpoints_observed"] > 0
    assert body["summary"]["endpoints_documented_only"] > 0
    assert body["summary"]["graphql_detected"] is True
    assert body["documents"]

    products = next(
        item
        for item in body["items"]
        if item["path"] == "/api/products" and item["method"] == "GET"
    )
    assert set(products["discovery_sources"]) >= {"CRAWLER", "OPENAPI"}
    assert "secret_note" in products["response_fields"]
    assert products["operation_id"] == "listProducts"


def test_no_response_value_or_credential_reaches_any_api_response(
    client, allow_loopback, target
):
    scan_id = scan_the_fixture(client, target.base_url)

    for path in ("", "/api-endpoints", "/endpoints", "/findings", "/report", "/report/json"):
        text = client.get(f"/api/scans/{scan_id}{path}").text
        assert SECRET_VALUE not in text, path
        assert API_TOKEN not in text, path
        assert "Bearer " not in text, path


def test_the_report_carries_the_api_surface(client, allow_loopback, target):
    scan_id = scan_the_fixture(client, target.base_url)

    body = client.get(f"/api/scans/{scan_id}/report").json()
    api = body["coverage"]["api"]

    assert api["detected"] is True
    assert api["endpoints_observed"] > 0
    assert api["endpoints_documented_only"] > 0
    assert api["graphql_detected"] is True
    assert api["graphql_introspection_tested"] is False
    assert api["openapi_documents"] >= 2
    assert any(e["documented_only"] for e in api["endpoints"])
    assert any(e["observed"] for e in api["endpoints"])


def test_a_scan_without_apis_says_so(client):
    user_id = register(client)
    with SessionLocal() as db:
        scan = Scan(
            user_id=user_id, target_url="https://example.test/", status=ScanStatus.COMPLETED
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id

    body = client.get(f"/api/scans/{scan_id}/report").json()
    assert body["coverage"]["api"]["detected"] is False
    assert body["coverage"]["api"]["endpoints_discovered"] == 0
    assert body["coverage"]["api"]["complete_inventory"] is False

    listing = client.get(f"/api/scans/{scan_id}/api-endpoints").json()
    assert listing["items"] == []
    assert listing["summary"]["detected"] is False


def test_another_user_cannot_read_the_api_surface(client, allow_loopback, target):
    scan_id = scan_the_fixture(client, target.base_url)

    with TestClient(api_app) as other:
        register(other)
        assert other.get(f"/api/scans/{scan_id}/api-endpoints").status_code == 404


def test_api_discovery_does_not_duplicate_the_crawl_surface(
    client, allow_loopback, target
):
    """One record per operation. The crawl surface is untouched."""
    scan_id = scan_the_fixture(client, target.base_url)

    endpoints = client.get(f"/api/scans/{scan_id}/endpoints").json()["items"]
    api_endpoints = client.get(f"/api/scans/{scan_id}/api-endpoints").json()["items"]

    identities = [(item["method"], item["path"]) for item in api_endpoints]
    assert len(identities) == len(set(identities))
    # The documented-only operation exists in the API view and not in the crawl
    # view, which is exactly the separation the two tables encode.
    crawl_paths = {item["path"] for item in endpoints}
    assert "/api/legacy/{id}" not in crawl_paths
    assert "/api/legacy/{id}" in {item["path"] for item in api_endpoints}
