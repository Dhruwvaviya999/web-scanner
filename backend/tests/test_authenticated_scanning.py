"""Authenticated scanning: validation, scope, transport, discovery, leakage.

Two kinds of test live here.

The pure ones — validation, the context's scope rule, the health classifier —
need nothing but the objects themselves.

The rest run against a deliberately protected FastAPI application started on a
loopback port inside this process. Nothing here touches a third-party system,
and the fixture's "authentication" is a constant compared with `==`: it exists
to prove a supplied credential *reaches* the target, not to model a real
authentication scheme. Nothing in the scanner ever tries to guess it.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import socket
import threading
import time
import uuid

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app as api_app
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner import ScannerConfig, WebScanner
from app.scanner.active.budget import ProbeBudgetLimits
from app.scanner.active.module import ActiveScanConfig
from app.scanner.auth import (
    MAX_COOKIES,
    MAX_COOKIE_VALUE_LENGTH,
    MAX_TOKEN_LENGTH,
    AuthConfigError,
    AuthenticationContext,
    AuthMode,
    AuthStatus,
    CookieCredential,
    validate_bearer_token,
    validate_cookie,
    validate_cookies,
    validate_mode_payload,
)
from app.scanner.auth.context import build_context
from app.scanner.auth.health import classify
from app.scanner.crawler.types import CrawlConfig
from app.scanner.crawler.url_normalizer import is_same_origin, origin_of
from app.scanner.http_scanner import HttpFetcher
from app.scanner.types import RawHttpResponse
from app.scanner.url_validator import parse_target_url
from app.scanner.vulnerabilities.sqli.detector import SqlInjectionDetector
from app.scanner.vulnerabilities.xss.detector import ReflectedXssDetector
from app.services import scan_service

PASSWORD = "Sup3rSecret!pass"

TOKEN = "phase11-test-token"
COOKIE_NAME = "session"
COOKIE_VALUE = "phase11-test-session"


# --------------------------------------------------------------------------- #
# A protected target, served on loopback for the duration of the module
# --------------------------------------------------------------------------- #


def build_target_app() -> FastAPI:
    """A tiny application with a public half and an authenticated half."""
    target = FastAPI(docs_url=None, redoc_url=None)

    def authorized(request: Request) -> bool:
        if request.headers.get("authorization") == f"Bearer {TOKEN}":
            return True
        return request.cookies.get(COOKIE_NAME) == COOKIE_VALUE

    def page(title: str, body: str) -> str:
        return f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"

    def guard(request: Request) -> Response | None:
        if authorized(request):
            return None
        # Redirecting an anonymous visitor to a sign-in page is what real
        # applications do, and it is what the health check must recognise.
        return RedirectResponse("/login", status_code=302)

    @target.get("/")
    def index() -> HTMLResponse:
        return HTMLResponse(page("Public Home", '<a href="/private">private</a>'))

    @target.get("/login")
    def login() -> HTMLResponse:
        return HTMLResponse(page("Sign in", "<p>Authentication required.</p>"))

    @target.get("/private")
    def private(request: Request):
        return guard(request) or HTMLResponse(
            page(
                "Private Area",
                '<a href="/private/search?q=hello">search</a> '
                '<a href="/private/safe?q=hello">safe</a>',
            )
        )

    @target.get("/private/search")
    def private_search(request: Request, q: str = ""):
        # UNSAFE on purpose: reflects the parameter with no encoding.
        return guard(request) or HTMLResponse(page("Private Search", f"<p>{q}</p>"))

    @target.get("/private/safe")
    def private_safe(request: Request, q: str = ""):
        import html as _html

        return guard(request) or HTMLResponse(
            page("Private Safe", f"<p>{_html.escape(q)}</p>")
        )

    @target.get("/forbidden")
    def forbidden() -> Response:
        """Always 403, whatever is presented. Never a vulnerability."""
        return Response(status_code=403)

    @target.get("/unauthorized")
    def unauthorized() -> Response:
        return Response(status_code=401)

    return target


class _Server:
    """Runs the target application on a free loopback port."""

    def __init__(self, app: FastAPI) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self._config = uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_level="error"
        )
        self._server = uvicorn.Server(self._config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

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
def target() -> _Server:
    server = _Server(build_target_app())
    server.start()
    try:
        yield server
    finally:
        server.stop()


def scanner_config() -> ScannerConfig:
    """Loopback is normally refused by the SSRF guard; the fixture needs it."""
    return ScannerConfig(
        timeout_seconds=5.0,
        total_timeout_seconds=60.0,
        allow_private_networks=True,
    )


def run_scan(url: str, authentication: AuthenticationContext | None = None):
    return WebScanner(
        scanner_config(),
        crawl_config=CrawlConfig(max_pages=15, max_depth=3, time_budget_seconds=30),
        active_config=ActiveScanConfig(
            limits=ProbeBudgetLimits(per_parameter=6, per_endpoint=24, per_scan=120)
        ),
        detectors=[ReflectedXssDetector(), SqlInjectionDetector()],
        authentication=authentication,
    ).scan_sync(url)


def bearer_context(base_url: str, token: str = TOKEN) -> AuthenticationContext:
    return build_context(AuthMode.BEARER_TOKEN, base_url, token=token)


def cookie_context(base_url: str, value: str = COOKIE_VALUE) -> AuthenticationContext:
    return build_context(AuthMode.COOKIE, base_url, cookies=[(COOKIE_NAME, value)])


# --------------------------------------------------------------------------- #
# 1. Validation
# --------------------------------------------------------------------------- #


def test_a_plain_token_is_accepted():
    assert validate_bearer_token("eyJhbGciOi.J9.abc-_~+/=") == "eyJhbGciOi.J9.abc-_~+/="


@pytest.mark.parametrize("raw", ["  abc123\n", "abc123\r", "abc123\r\n", "\tabc123 "])
def test_outer_whitespace_is_removed_from_a_token(raw):
    """A token pasted from a terminal arrives with a line ending; it is not part of it.

    Only the *outer* whitespace goes. A line break in the middle of a token is
    an injection attempt and is refused below, never repaired into something
    sendable.
    """
    assert validate_bearer_token(raw) == "abc123"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "abc\r\nX-Injected: 1",
        "abc\nX-Injected: 1",
        "abc\rX-Injected: 1",
        "abc def",
        "abc\x00def",
        "abc\tdef",
        "a" * (MAX_TOKEN_LENGTH + 1),
    ],
)
def test_a_token_that_cannot_be_sent_as_a_header_is_refused(value):
    with pytest.raises(AuthConfigError):
        validate_bearer_token(value)


def test_the_bearer_prefix_is_not_accepted_in_the_token():
    """Otherwise the header would read 'Bearer Bearer ...' and silently fail."""
    with pytest.raises(AuthConfigError):
        validate_bearer_token("Bearer abc123")


def test_a_validation_message_never_repeats_the_token():
    secret = "sup3r-secret-token-value"
    with pytest.raises(AuthConfigError) as exc:
        validate_bearer_token(f"{secret}\r\nX-Injected: 1")
    assert secret not in str(exc.value)


def test_a_plain_cookie_is_accepted():
    cookie = validate_cookie("session", "abc123==")
    assert cookie == CookieCredential(name="session", value="abc123==")


def test_a_cookie_value_is_not_normalised():
    """Trimming a signed cookie would break its signature."""
    assert validate_cookie("session", '"quoted-value"').value == '"quoted-value"'


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("", "v"),
        ("   ", "v"),
        ("bad name", "v"),
        ("bad;name", "v"),
        ("bad\r\nname", "v"),
        ("session", "a\r\nSet-Cookie: x=1"),
        ("session", "a\nb"),
        ("session", "a;b"),
        ("session", "a b"),
        ("session", "a\x00b"),
        ("session", "a" * (MAX_COOKIE_VALUE_LENGTH + 1)),
    ],
)
def test_a_cookie_that_cannot_be_sent_as_a_header_is_refused(name, value):
    with pytest.raises(AuthConfigError):
        validate_cookie(name, value)


def test_a_cookie_validation_message_never_repeats_the_value():
    secret = "sup3r-secret-session-value"
    with pytest.raises(AuthConfigError) as exc:
        validate_cookie("session", f"{secret}\r\nX-Injected: 1")
    assert secret not in str(exc.value)


def test_too_many_cookies_are_refused():
    with pytest.raises(AuthConfigError):
        validate_cookies([(f"c{i}", "v") for i in range(MAX_COOKIES + 1)])


def test_an_empty_cookie_set_is_refused():
    with pytest.raises(AuthConfigError):
        validate_cookies([])


def test_a_repeated_cookie_name_is_refused():
    """Two values for one name is ambiguous; the target would pick one."""
    with pytest.raises(AuthConfigError):
        validate_cookies([("session", "a"), ("SESSION", "b")])


def test_cookies_larger_than_a_header_are_refused():
    with pytest.raises(AuthConfigError):
        validate_cookies([(f"c{i}", "v" * 1000) for i in range(12)])


@pytest.mark.parametrize(
    ("mode", "token", "cookies"),
    [
        (AuthMode.NONE, "abc", None),
        (AuthMode.NONE, None, [("session", "a")]),
        (AuthMode.BEARER_TOKEN, None, None),
        (AuthMode.BEARER_TOKEN, "abc", [("session", "a")]),
        (AuthMode.COOKIE, None, None),
        (AuthMode.COOKIE, "abc", [("session", "a")]),
    ],
)
def test_material_must_match_the_mode(mode, token, cookies):
    """Silently ignoring a supplied credential would misrepresent the whole scan."""
    with pytest.raises(AuthConfigError):
        validate_mode_payload(mode, token=token, cookies=cookies)


# --------------------------------------------------------------------------- #
# 2. The context and its scope rule
# --------------------------------------------------------------------------- #


def test_an_unauthenticated_context_adds_nothing():
    context = AuthenticationContext.none()
    assert context.configured is False
    assert dict(context.headers_for("https://example.com/")) == {}


def test_a_bearer_context_builds_the_header_centrally():
    context = bearer_context("https://example.com")
    assert dict(context.headers_for("https://example.com/x?y=1")) == {
        "Authorization": f"Bearer {TOKEN}"
    }


def test_a_cookie_context_builds_the_header_centrally():
    context = build_context(
        AuthMode.COOKIE, "https://example.com", cookies=[("a", "1"), ("b", "2")]
    )
    assert dict(context.headers_for("https://example.com/")) == {"Cookie": "a=1; b=2"}


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/",          # another host entirely
        "https://sub.example.com/",       # a subdomain is a different host
        "http://example.com/",            # a different scheme is a different origin
        "https://example.com:8443/",      # a different port is a different origin
        "https://example.com.evil.test/",  # a suffix trick
    ],
)
def test_credentials_are_never_offered_outside_the_authorized_origin(url):
    for context in (bearer_context("https://example.com"), cookie_context("https://example.com")):
        assert context.applies_to(url) is False
        assert dict(context.headers_for(url)) == {}


def test_the_context_refuses_to_render_its_secret():
    """A stray %s or f-string must not be able to leak a credential."""
    context = bearer_context("https://example.com", token="sup3r-secret-token")
    for rendered in (repr(context), str(context), f"{context}", "%s" % (context,)):
        assert "sup3r-secret-token" not in rendered
        assert "redacted" in rendered

    cookie = CookieCredential(name="session", value="sup3r-secret-cookie")
    assert "sup3r-secret-cookie" not in repr(cookie)
    assert "sup3r-secret-cookie" not in f"{cookie}"


def test_describe_carries_no_secret():
    context = cookie_context("https://example.com", value="sup3r-secret-cookie")
    assert "sup3r-secret-cookie" not in str(context.describe())
    assert context.describe()["cookie_names"] == COOKIE_NAME


def test_building_a_context_validates_its_material():
    with pytest.raises(AuthConfigError):
        build_context(AuthMode.BEARER_TOKEN, "https://example.com", token="a\r\nb")


# --------------------------------------------------------------------------- #
# 3. The health classifier (pure)
# --------------------------------------------------------------------------- #


def raw(status: int, *, final_url: str = "https://example.com/", redirects: int = 0):
    return RawHttpResponse(
        status_code=status,
        headers=httpx.Headers({}),
        final_url=final_url,
        is_https=True,
        redirect_count=redirects,
        elapsed_ms=1,
    )


@pytest.mark.parametrize("status", [401, 403])
def test_a_refusal_is_classified_as_rejected(status):
    assert classify(raw(status), seed_url="https://example.com/") is AuthStatus.REJECTED


def test_a_redirect_to_a_sign_in_page_is_a_refusal():
    response = raw(200, final_url="https://example.com/login", redirects=1)
    assert classify(response, seed_url="https://example.com/") is AuthStatus.REJECTED


def test_a_site_whose_home_page_is_the_sign_in_page_is_not_called_rejected():
    """No redirect happened, so the target said nothing about the credentials."""
    response = raw(200, final_url="https://example.com/login", redirects=0)
    assert classify(response, seed_url="https://example.com/login") is AuthStatus.AVAILABLE


def test_a_normal_response_is_classified_as_available():
    assert classify(raw(200), seed_url="https://example.com/") is AuthStatus.AVAILABLE


@pytest.mark.parametrize("status", [500, 502, 429])
def test_a_target_error_says_nothing_about_the_credentials(status):
    assert classify(raw(status), seed_url="https://example.com/") is AuthStatus.UNKNOWN


# --------------------------------------------------------------------------- #
# 4. Transport
# --------------------------------------------------------------------------- #


def record_requests(status: int = 200, location: str | None = None):
    """A mock transport that records every request it is handed."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        headers = {"content-type": "text/html"}
        if location:
            headers["location"] = location
        return httpx.Response(status, headers=headers, content=b"<html></html>")

    return seen, httpx.MockTransport(handler)


async def fetch_with(context: AuthenticationContext, url: str, **kwargs):
    seen, transport = record_requests(**kwargs)
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
        fetcher = HttpFetcher(
            scanner_config(), client, authentication=context, **kwargs.pop("fetcher", {})
        )
        with contextlib.suppress(Exception):
            await fetcher.fetch(parse_target_url(url))
    return seen


def test_the_transport_attaches_the_bearer_header():
    seen = asyncio.run(fetch_with(bearer_context("http://127.0.0.1:9"), "http://127.0.0.1:9/x"))
    assert seen[0].headers["authorization"] == f"Bearer {TOKEN}"


def test_the_transport_attaches_the_cookie_header():
    seen = asyncio.run(fetch_with(cookie_context("http://127.0.0.1:9"), "http://127.0.0.1:9/x"))
    assert seen[0].headers["cookie"] == f"{COOKIE_NAME}={COOKIE_VALUE}"


def test_the_transport_sends_nothing_extra_without_a_context():
    seen = asyncio.run(fetch_with(AuthenticationContext.none(), "http://127.0.0.1:9/x"))
    assert "authorization" not in seen[0].headers
    assert "cookie" not in seen[0].headers


def test_credentials_are_not_sent_to_a_url_outside_the_authorized_origin():
    """The context is bound to one origin; a request elsewhere carries nothing."""
    context = bearer_context("http://127.0.0.1:9")
    seen = asyncio.run(fetch_with(context, "http://127.0.0.2:9/x"))
    assert "authorization" not in seen[0].headers


def follow_redirect(context: AuthenticationContext, location: str, *, allow_url=None):
    """Fetch a URL that 302s to `location`, and return every request sent."""
    seen, transport = record_requests(status=302, location=location)

    async def run():
        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
            fetcher = HttpFetcher(
                scanner_config(), client, allow_url=allow_url, authentication=context
            )
            with contextlib.suppress(Exception):
                await fetcher.fetch(parse_target_url("http://127.0.0.1:9/start"))

    asyncio.run(run())
    return seen


def test_an_off_origin_redirect_is_refused_where_the_scope_lock_is_set():
    """The crawler, the probe engine and the auth check all set this lock."""
    context = bearer_context("http://127.0.0.1:9")
    origin = origin_of("http://127.0.0.1:9/")

    seen = follow_redirect(
        context,
        "http://127.0.0.2:9/elsewhere",
        allow_url=lambda url: is_same_origin(url, origin),
    )

    assert len(seen) == 1, "the off-origin hop must not be requested at all"
    assert seen[0].headers["authorization"] == f"Bearer {TOKEN}"


def test_credentials_are_withheld_even_when_a_redirect_is_followed_off_origin():
    """The seed probe follows redirects anywhere, as it has since phase 2.

    The scope lock is not what protects the credential there — the context is.
    Bound to one origin, it hands out nothing for any other, so the second hop
    goes out as an ordinary anonymous request.
    """
    context = bearer_context("http://127.0.0.1:9")

    seen = follow_redirect(context, "http://127.0.0.2:9/elsewhere")

    assert len(seen) > 1, "the seed probe still follows the redirect"
    assert seen[0].headers["authorization"] == f"Bearer {TOKEN}"
    for request in seen[1:]:
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers


def test_an_in_origin_redirect_keeps_the_credentials():
    """A login-protected page that redirects within the site must stay authenticated."""
    context = bearer_context("http://127.0.0.1:9")

    seen = follow_redirect(context, "http://127.0.0.1:9/next")

    assert len(seen) > 1
    assert all(r.headers.get("authorization") == f"Bearer {TOKEN}" for r in seen)


# --------------------------------------------------------------------------- #
# 5. End to end against the protected target
# --------------------------------------------------------------------------- #


def crawled_paths(report) -> set[str]:
    if report.crawl is None:
        return set()
    return {endpoint.path for endpoint in report.crawl.endpoints}


def test_an_unauthenticated_scan_sees_only_the_public_surface(target):
    report = run_scan(target.base_url)

    paths = crawled_paths(report)
    assert "/" in paths
    assert "/private/search" not in paths
    assert report.auth is not None
    assert report.auth.mode is AuthMode.NONE
    assert report.auth.status is AuthStatus.NOT_CONFIGURED


def test_a_bearer_scan_discovers_the_protected_surface(target):
    report = run_scan(target.base_url, bearer_context(target.base_url))

    paths = crawled_paths(report)
    assert "/private" in paths
    assert "/private/search" in paths
    assert report.auth is not None
    assert report.auth.status is AuthStatus.AVAILABLE


def test_a_cookie_scan_discovers_the_protected_surface(target):
    report = run_scan(target.base_url, cookie_context(target.base_url))

    assert "/private/search" in crawled_paths(report)
    assert report.auth is not None
    assert report.auth.mode is AuthMode.COOKIE
    assert report.auth.status is AuthStatus.AVAILABLE


def test_the_detectors_inherit_authentication_without_knowing_about_it(target):
    """XSS runs on a page only reachable with credentials, and its interface is unchanged."""
    report = run_scan(target.base_url, bearer_context(target.base_url))

    assert report.analysis is not None
    findings = {group.data.rule.value for group in report.analysis.findings}
    assert any(rule.startswith("XSS_") for rule in findings), sorted(findings)

    flagged = {
        url
        for url, finding in report.analysis.observations
        if finding.rule.value.startswith("XSS_") and url
    }
    assert any("/private/search" in url for url in flagged), flagged
    assert not any("/private/safe" in url for url in flagged), flagged


def test_the_detector_interface_is_unchanged():
    """Authentication reaches detectors through the engine, not their signatures."""
    import inspect

    for detector in (ReflectedXssDetector(), SqlInjectionDetector()):
        assert list(inspect.signature(detector.eligible).parameters) == ["target"]
        assert list(inspect.signature(detector.probe).parameters) == ["target", "engine"]


def test_rejected_credentials_are_reported_as_rejected(target):
    report = run_scan(target.base_url + "/private", bearer_context(target.base_url, "wrong-token"))

    assert report.auth is not None
    assert report.auth.status is AuthStatus.REJECTED


def test_a_401_is_not_treated_as_a_vulnerability(target):
    """An access refusal is a fact about permissions, not a finding about a flaw."""
    report = run_scan(target.base_url + "/unauthorized", bearer_context(target.base_url, "wrong"))

    assert report.analysis is not None
    rules = {group.data.rule.value for group in report.analysis.findings}
    assert not any(rule.startswith(("XSS_", "SQLI_")) for rule in rules), sorted(rules)


def test_a_403_is_not_treated_as_a_vulnerability(target):
    report = run_scan(target.base_url + "/forbidden", bearer_context(target.base_url))

    assert report.analysis is not None
    rules = {group.data.rule.value for group in report.analysis.findings}
    assert not any(rule.startswith(("XSS_", "SQLI_")) for rule in rules), sorted(rules)


def test_an_authenticated_scan_makes_no_request_once_cancelled(target):
    """Cancellation stops authenticated traffic at the first safe boundary."""
    from app.scanner.cancellation import CancellationToken

    report = WebScanner(
        scanner_config(),
        crawl_config=CrawlConfig(),
        authentication=bearer_context(target.base_url),
        cancellation=CancellationToken(lambda: True),
    ).scan_sync(target.base_url)

    assert report.cancelled is True
    # The auth check is the first module and honours cancellation before it
    # sends anything, so no credential was put on the wire at all.
    assert report.auth is None
    assert report.crawl is None


# --------------------------------------------------------------------------- #
# 6. The API: secrets in, metadata out
# --------------------------------------------------------------------------- #


@pytest.fixture
def client():
    with TestClient(api_app) as test_client:
        yield test_client


@pytest.fixture
def allow_loopback(monkeypatch):
    """Let the service-level tests reach the loopback fixture.

    `scan_service` builds its scanner config from application settings, where
    private networks are refused — correctly, since that is the SSRF guard. The
    guard itself is not what these tests are about, so it is opened for the
    fixture only, through the same setting an operator would use.
    """
    from app.core.config import settings

    monkeypatch.setattr(settings, "SCANNER_ALLOW_PRIVATE_NETWORKS", True)
    yield


def register(client: TestClient) -> uuid.UUID:
    email = f"auth-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Auth Test",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


@pytest.mark.parametrize(
    "authentication",
    [
        {"mode": "BEARER_TOKEN"},
        {"mode": "BEARER_TOKEN", "token": ""},
        {"mode": "BEARER_TOKEN", "token": "abc\r\nX-Injected: 1"},
        {"mode": "BEARER_TOKEN", "token": "abc", "cookies": [{"name": "a", "value": "b"}]},
        {"mode": "COOKIE"},
        {"mode": "COOKIE", "cookies": []},
        {"mode": "COOKIE", "cookies": [{"name": "bad name", "value": "b"}]},
        {"mode": "COOKIE", "cookies": [{"name": "a", "value": "b\r\nSet-Cookie: x=1"}]},
        {"mode": "NONE", "token": "abc"},
        {"mode": "WHATEVER", "token": "abc"},
    ],
)
def test_malformed_authentication_is_refused_before_a_scan_runs(client, authentication):
    register(client)
    response = client.post(
        "/api/scans",
        json={"target_url": "https://example.test/", "authentication": authentication},
    )

    assert response.status_code == 422, response.text
    # No scan row was created: the request never got as far as running one.
    assert client.get("/api/scans").json()["total"] == 0


def test_a_validation_error_never_echoes_the_credential(client):
    register(client)
    secret = "sup3r-secret-token-value"
    response = client.post(
        "/api/scans",
        json={
            "target_url": "https://example.test/",
            "authentication": {"mode": "BEARER_TOKEN", "token": f"{secret}\r\nX-Injected: 1"},
        },
    )

    assert response.status_code == 422
    assert secret not in response.text


def insert_scan(user_id: uuid.UUID, **overrides) -> uuid.UUID:
    with SessionLocal() as db:
        scan = Scan(user_id=user_id, target_url="https://example.test/", **overrides)
        db.add(scan)
        db.commit()
        return scan.id


def test_a_scan_response_carries_the_mode_and_status_but_no_secret(client):
    user_id = register(client)
    scan_id = insert_scan(
        user_id,
        status=ScanStatus.COMPLETED,
        auth_mode=AuthMode.BEARER_TOKEN.value,
        auth_status=AuthStatus.AVAILABLE.value,
    )

    response = client.get(f"/api/scans/{scan_id}")
    body = response.json()

    assert body["auth_mode"] == "BEARER_TOKEN"
    assert body["auth_status"] == "AVAILABLE"
    assert body["authentication"] == {
        "mode": "BEARER_TOKEN",
        "status": "AVAILABLE",
        "enabled": True,
    }
    # No credential-bearing field exists on this model at all. The mode name
    # legitimately contains the word "token", so the check is on header names
    # and on real secret values, not on the substring.
    lowered = response.text.lower()
    for banned in ("authorization", "set-cookie", "\"cookies\"", "password"):
        assert banned not in lowered, banned
    assert TOKEN not in response.text
    assert COOKIE_VALUE not in response.text


def test_the_report_carries_the_mode_and_status_but_no_secret(client):
    user_id = register(client)
    scan_id = insert_scan(
        user_id,
        status=ScanStatus.COMPLETED,
        auth_mode=AuthMode.COOKIE.value,
        auth_status=AuthStatus.AVAILABLE.value,
    )

    response = client.get(f"/api/scans/{scan_id}/report")
    body = response.json()

    assert body["metadata"]["authentication"] == {
        "mode": "COOKIE",
        "status": "AVAILABLE",
        "authenticated": True,
        "confirmed": True,
    }
    lowered = response.text.lower()
    for banned in ("authorization", "set-cookie", "\"cookies\""):
        assert banned not in lowered, banned
    assert TOKEN not in response.text
    assert COOKIE_VALUE not in response.text


def test_a_rejected_credential_never_reads_as_a_clean_scan(client):
    """The scan finished, but it only ever saw the anonymous surface."""
    user_id = register(client)
    scan_id = insert_scan(
        user_id,
        status=ScanStatus.COMPLETED,
        auth_mode=AuthMode.BEARER_TOKEN.value,
        auth_status=AuthStatus.REJECTED.value,
        endpoints_discovered=3,
        endpoints_analyzed=3,
        endpoints_skipped=0,
        endpoints_failed=0,
    )

    body = client.get(f"/api/scans/{scan_id}/report").json()

    assert body["metadata"]["authentication"]["confirmed"] is False
    assert body["metadata"]["is_conclusive"] is False
    assert body["coverage"]["authentication_usable"] is False
    # Counters alone would say full coverage; the refusal overrides them.
    assert body["coverage"]["is_complete"] is False


def test_an_unauthenticated_scan_still_reports_complete_coverage(client):
    user_id = register(client)
    scan_id = insert_scan(
        user_id,
        status=ScanStatus.COMPLETED,
        endpoints_discovered=2,
        endpoints_analyzed=2,
        endpoints_skipped=0,
        endpoints_failed=0,
    )

    body = client.get(f"/api/scans/{scan_id}/report").json()

    assert body["metadata"]["authentication"]["mode"] == "NONE"
    assert body["metadata"]["authentication"]["authenticated"] is False
    assert body["metadata"]["is_conclusive"] is True
    assert body["coverage"]["is_complete"] is True


def test_another_user_cannot_read_the_authentication_metadata(client):
    """The Phase 1 isolation rule is unchanged: 404, never 403."""
    owner_id = register(client)
    scan_id = insert_scan(
        owner_id,
        status=ScanStatus.COMPLETED,
        auth_mode=AuthMode.BEARER_TOKEN.value,
        auth_status=AuthStatus.AVAILABLE.value,
    )

    with TestClient(api_app) as other:
        register(other)
        assert other.get(f"/api/scans/{scan_id}").status_code == 404
        assert other.get(f"/api/scans/{scan_id}/report").status_code == 404


def test_no_credential_is_written_to_the_scan_row(client, allow_loopback, target):
    """The end-to-end guarantee: run an authenticated scan, then read the row."""
    user_id = register(client)
    context = bearer_context(target.base_url)

    with SessionLocal() as db:
        scan_id = scan_service.enqueue_scan(
            db, db.get(User, user_id), target.base_url, AuthMode.BEARER_TOKEN
        )
    scan_service.execute_scan(scan_id, authentication=context)

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        row = {
            column.name: getattr(scan, column.name) for column in scan.__table__.columns
        }

    assert row["auth_mode"] == "BEARER_TOKEN"
    assert row["auth_status"] == AuthStatus.AVAILABLE.value
    # Not one column of the row contains the token, under any spelling.
    assert TOKEN not in str(row)

    findings = client.get(f"/api/scans/{scan_id}/findings").text
    endpoints = client.get(f"/api/scans/{scan_id}/endpoints").text
    report = client.get(f"/api/scans/{scan_id}/report").text
    for payload in (findings, endpoints, report):
        assert TOKEN not in payload


def test_no_cookie_value_reaches_findings_or_the_report(client, allow_loopback, target):
    user_id = register(client)
    context = cookie_context(target.base_url)

    with SessionLocal() as db:
        scan_id = scan_service.enqueue_scan(
            db, db.get(User, user_id), target.base_url, AuthMode.COOKIE
        )
    scan_service.execute_scan(scan_id, authentication=context)

    for path in ("", "/findings", "/endpoints", "/forms", "/report"):
        body = client.get(f"/api/scans/{scan_id}{path}").text
        assert COOKIE_VALUE not in body, path


def test_a_failure_summary_never_carries_a_credential(client, monkeypatch, target):
    """Even an exception carrying the token cannot reach a user-visible field."""

    class Exploding:
        def __init__(self, *args, **kwargs):
            self.authentication = kwargs.get("authentication")

        def scan_sync(self, url):
            raise RuntimeError(f"connection failed with token {TOKEN}")

    monkeypatch.setattr(scan_service, "WebScanner", Exploding)

    user_id = register(client)
    with SessionLocal() as db:
        scan_id = scan_service.enqueue_scan(
            db, db.get(User, user_id), target.base_url, AuthMode.BEARER_TOKEN
        )
    scan_service.execute_scan(scan_id, authentication=bearer_context(target.base_url))

    body = client.get(f"/api/scans/{scan_id}").text
    assert TOKEN not in body
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "FAILED"


def test_application_logging_does_not_emit_the_credential(client, allow_loopback, caplog, target):
    """Nothing the scanner logs during an authenticated run contains the secret."""
    import logging

    user_id = register(client)
    with caplog.at_level(logging.DEBUG, logger="app"):
        with SessionLocal() as db:
            scan_id = scan_service.enqueue_scan(
                db, db.get(User, user_id), target.base_url, AuthMode.BEARER_TOKEN
            )
        scan_service.execute_scan(
            scan_id, authentication=bearer_context(target.base_url)
        )

    emitted = "\n".join(record.getMessage() for record in caplog.records)
    assert TOKEN not in emitted
    assert "Authorization" not in emitted
