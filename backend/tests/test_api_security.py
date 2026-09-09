"""API security: field classification, property authorization, errors, CORS.

Phase 14 is read-only, so these tests care as much about what the scanner
*declines* to say as about what it reports. A classifier that flags `has_password`
and `token_type`, or that calls every `phone` field a data breach, produces a
report nobody can triage — so the false-positive cases below are as important as
the true-positive ones.

The pure tests need nothing but strings. The rest run against a loopback
application serving a safe half and a deliberately leaky half, and the safe half
is the one that matters: it exists to prove silence.
"""

from __future__ import annotations

import secrets
import socket
import threading
import time
import uuid

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app as api_app
from app.models.finding import Finding
from app.models.user import User
from app.scanner import ScannerConfig, WebScanner
from app.scanner.api.types import ApiDiscoveryConfig
from app.scanner.api_security.configuration import (
    analyze_cors,
    analyze_disclosure,
    analyze_inventory,
    version_of,
)
from app.scanner.api_security.error_analyzer import analyze as analyze_error
from app.scanner.api_security.error_analyzer import detect_error_signals
from app.scanner.api_security.findings import (
    cors_finding,
    sensitive_data_finding,
    verbose_error_finding,
)
from app.scanner.api_security.response_analyzer import analyze_fields, compare_properties
from app.scanner.api_security.sensitive_fields import classify_field, normalize
from app.scanner.api_security.types import (
    ApiSecurityConfig,
    CorsVerdict,
    ErrorSignal,
    ExposureVerdict,
    FieldCategory,
    FieldSensitivity,
)
from app.scanner.crawler.types import CrawlConfig
from app.scanner.security.types import FindingCategory, FindingSeverity
from app.services import scan_service
from sqlalchemy import select

PASSWORD = "Sup3rSecret!pass"

#: Values the fixture serves. None may ever appear in a finding or a report.
FIXTURE_HASH = "FIXTURE_VALUE_ONLY_HASH_9x7"
FIXTURE_KEY = "FIXTURE_VALUE_ONLY_KEY_9x7"
FIXTURE_TRACE = "FIXTURE_VALUE_ONLY_TRACE_9x7"


# --------------------------------------------------------------------------- #
# Field classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("apiKey", "api_key"),
        ("API-KEY", "api_key"),
        ("password_hash", "password_hash"),
        ("Password Hash", "password_hash"),
        ("accessToken", "access_token"),
    ],
)
def test_names_normalise_across_conventions(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize(
    ("name", "category", "sensitivity"),
    [
        ("password", FieldCategory.AUTHENTICATION, FieldSensitivity.HIGHLY_SENSITIVE),
        ("password_hash", FieldCategory.AUTHENTICATION, FieldSensitivity.HIGHLY_SENSITIVE),
        ("client_secret", FieldCategory.AUTHENTICATION, FieldSensitivity.HIGHLY_SENSITIVE),
        ("access_token", FieldCategory.TOKEN, FieldSensitivity.HIGHLY_SENSITIVE),
        ("refresh_token", FieldCategory.TOKEN, FieldSensitivity.HIGHLY_SENSITIVE),
        ("apiKey", FieldCategory.TOKEN, FieldSensitivity.HIGHLY_SENSITIVE),
        ("session_id", FieldCategory.SESSION, FieldSensitivity.HIGHLY_SENSITIVE),
        ("private_key", FieldCategory.CRYPTOGRAPHIC, FieldSensitivity.HIGHLY_SENSITIVE),
        ("card_number", FieldCategory.FINANCIAL, FieldSensitivity.HIGHLY_SENSITIVE),
        ("database_url", FieldCategory.INFRASTRUCTURE, FieldSensitivity.HIGHLY_SENSITIVE),
        ("phone", FieldCategory.PERSONAL, FieldSensitivity.POTENTIALLY_SENSITIVE),
        ("address", FieldCategory.PERSONAL, FieldSensitivity.POTENTIALLY_SENSITIVE),
        ("ssn", FieldCategory.PERSONAL, FieldSensitivity.POTENTIALLY_SENSITIVE),
        ("iban", FieldCategory.FINANCIAL, FieldSensitivity.POTENTIALLY_SENSITIVE),
        ("internal_ip", FieldCategory.INFRASTRUCTURE, FieldSensitivity.POTENTIALLY_SENSITIVE),
    ],
)
def test_sensitive_names_are_classified(name, category, sensitivity):
    classification = classify_field(name)
    assert classification.category is category
    assert classification.sensitivity is sensitivity


@pytest.mark.parametrize(
    "name",
    [
        # Facts *about* a credential, not the credential.
        "has_password",
        "is_password_set",
        "password_changed_at",
        "password_policy",
        "token_type",
        "token_expires_in",
        "requires_token",
        "auth_method",
        # Pagination cursors that happen to be called tokens.
        "page_token",
        "next_page_token",
        "continuation_token",
        # Ordinary fields that merely start with a sensitive-looking word.
        "keyboard",
        "address_type",
        "phone_type",
        # Far too generic to mean anything.
        "key",
        "keys",
        "id",
        "name",
        "email",
        "created_at",
        "title",
        "description",
    ],
)
def test_ordinary_names_are_not_flagged(name):
    """Every one of these would be a false positive in a report a human reads."""
    assert classify_field(name).sensitive is False


def test_a_qualified_name_still_matches():
    """`user_password_hash` is a password hash however it is prefixed."""
    assert classify_field("user_password_hash").sensitivity is (
        FieldSensitivity.HIGHLY_SENSITIVE
    )
    assert classify_field("admin_api_key").category is FieldCategory.TOKEN


def test_a_word_containing_a_head_does_not_match():
    """Matching whole word runs is what keeps `passwordless` out."""
    assert classify_field("passwordless").sensitive is False
    assert classify_field("tokenizer").sensitive is False


# --------------------------------------------------------------------------- #
# Verdicts: when a sensitive field is actually a problem
# --------------------------------------------------------------------------- #


def _fields(names, **kwargs):
    defaults = dict(
        url="https://x.test/api/users/1",
        method="GET",
        context_id="scan",
        context_label="scan identity",
        field_names=names,
        anonymous=False,
    )
    defaults.update(kwargs)
    return analyze_fields(**defaults)


def test_a_password_hash_is_never_legitimate():
    """No policy could make this correct, so none is required to report it."""
    observations = _fields(["id", "name", "password_hash"])
    assert len(observations) == 1
    assert observations[0].verdict is ExposureVerdict.UNAUTHORIZED


def test_a_private_key_is_never_legitimate():
    assert _fields(["private_key"])[0].verdict is ExposureVerdict.UNAUTHORIZED


def test_a_token_to_an_anonymous_request_is_unauthorized():
    observations = _fields(["access_token"], anonymous=True)
    assert observations[0].verdict is ExposureVerdict.UNAUTHORIZED


def test_a_token_to_an_authenticated_request_needs_a_policy():
    """Returning your own token after you sign in is an API working correctly."""
    observations = _fields(["access_token"], anonymous=False)
    assert observations[0].verdict is ExposureVerdict.UNKNOWN_POLICY


def test_personal_data_without_a_policy_is_not_a_vulnerability():
    """A staff directory returning phone numbers is doing its job."""
    observations = _fields(["name", "phone", "address"], anonymous=True)
    assert {o.verdict for o in observations} == {ExposureVerdict.UNKNOWN_POLICY}


def test_a_denied_resource_makes_any_sensitive_field_unauthorized():
    observations = _fields(["phone"], resource_denied=True, policy_declared=True)
    assert observations[0].verdict is ExposureVerdict.UNAUTHORIZED


def test_an_allowed_resource_makes_ordinary_sensitive_fields_expected():
    observations = _fields(["phone"], policy_declared=True)
    assert observations[0].verdict is ExposureVerdict.EXPECTED


def test_non_sensitive_fields_produce_nothing():
    assert _fields(["id", "name", "email", "created_at"]) == ()


def test_a_repeated_sensitive_field_is_recorded_once():
    observations = _fields(["password_hash", "password_hash"])
    assert len(observations) == 1


# --------------------------------------------------------------------------- #
# Property-level comparison
# --------------------------------------------------------------------------- #


def _compare(reference, subject, **kwargs):
    defaults = dict(
        url="https://x.test/api/users/1",
        reference_context_id="user",
        subject_context_id="other",
        subject_context_label="other",
        reference_fields=reference,
        subject_fields=subject,
    )
    defaults.update(kwargs)
    return compare_properties(**defaults)


def test_identical_field_sets_produce_nothing():
    assert _compare(["id", "name"], ["id", "name"]) is None


def test_an_extra_ordinary_field_produces_nothing():
    """An admin seeing more fields is the system working."""
    assert _compare(["id", "name"], ["id", "name", "internal_notes", "salary"]) is not None
    assert (
        _compare(["id", "name"], ["id", "name", "created_at"]) is None
    )


def test_an_expected_difference_is_not_a_finding():
    comparison = _compare(
        ["id", "name"], ["id", "name", "salary"], policy_declared=True
    )
    assert comparison is not None
    assert comparison.verdict is ExposureVerdict.EXPECTED


def test_a_difference_without_policy_is_unknown():
    comparison = _compare(["id", "name"], ["id", "name", "salary"])
    assert comparison is not None
    assert comparison.verdict is ExposureVerdict.UNKNOWN_POLICY


def test_a_never_legitimate_extra_field_is_unauthorized_without_policy():
    """A password hash needs no policy to be wrong."""
    comparison = _compare(["id", "name"], ["id", "name", "password_hash"])
    assert comparison is not None
    assert comparison.verdict is ExposureVerdict.UNAUTHORIZED


def test_a_denied_resource_makes_the_difference_unauthorized():
    comparison = _compare(
        ["id"], ["id", "salary"], resource_denied=True, policy_declared=True
    )
    assert comparison is not None
    assert comparison.verdict is ExposureVerdict.UNAUTHORIZED


# --------------------------------------------------------------------------- #
# Verbose errors
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("body", "signal"),
    [
        ('Traceback (most recent call last):\n  File "/app/main.py", line 3',
         ErrorSignal.STACK_TRACE),
        ("psycopg2.errors.UndefinedColumn: column x does not exist",
         ErrorSignal.DATABASE_ERROR),
        ("SELECT id, name FROM users WHERE id = 1", ErrorSignal.SQL_STATEMENT),
        ("Werkzeug Debugger enabled", ErrorSignal.FRAMEWORK_DEBUG),
        ("DATABASE_URL=postgres://localhost", ErrorSignal.ENVIRONMENT_DUMP),
        ("connect failed to 10.0.0.5", ErrorSignal.INTERNAL_HOST),
    ],
)
def test_diagnostic_signals_are_recognised(body, signal):
    assert signal in detect_error_signals(body, status_code=500)


@pytest.mark.parametrize(
    "body",
    [
        '{"detail":"Not Found"}',
        '{"error":"invalid request","field":"email"}',
        '{"message":"Internal Server Error"}',
        "",
        "<html><body><h1>404</h1></body></html>",
    ],
)
def test_ordinary_errors_produce_no_signals(body):
    """A generic error page is the application behaving correctly."""
    assert detect_error_signals(body, status_code=500) == ()


def test_successful_responses_are_never_scanned():
    """Searching every 200 for exception-shaped text is how a scanner invents findings."""
    body = "Traceback (most recent call last):"
    assert detect_error_signals(body, status_code=200) == ()


def test_one_strong_signal_is_enough():
    observation = analyze_error(
        url="https://x.test/api/x",
        method="GET",
        status_code=500,
        content_type="application/json",
        signals=(ErrorSignal.STACK_TRACE,),
    )
    assert observation is not None
    assert observation.strong is True


def test_a_single_weak_signal_is_not_enough():
    """A filesystem path alone might be a legitimate resource name."""
    assert (
        analyze_error(
            url="https://x.test/api/x",
            method="GET",
            status_code=404,
            content_type="application/json",
            signals=(ErrorSignal.FILESYSTEM_PATH,),
        )
        is None
    )


def test_two_weak_signals_are_enough():
    observation = analyze_error(
        url="https://x.test/api/x",
        method="GET",
        status_code=500,
        content_type="text/html",
        signals=(ErrorSignal.FILESYSTEM_PATH, ErrorSignal.EXCEPTION_CLASS),
    )
    assert observation is not None
    assert observation.strong is False


def test_a_verbose_error_finding_carries_no_body():
    observation = analyze_error(
        url="https://x.test/api/x",
        method="GET",
        status_code=500,
        content_type="application/json",
        signals=(ErrorSignal.STACK_TRACE, ErrorSignal.FILESYSTEM_PATH),
    )
    finding = verbose_error_finding(observation)
    rendered = f"{finding.description} {finding.evidence} {finding.impact}"
    assert "Traceback" not in rendered
    assert finding.category is FindingCategory.API_SECURITY


# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #


def test_no_cors_headers_is_not_a_weakness():
    """CORS is not required for every API."""
    observation = analyze_cors("https://x.test/api", {})
    assert observation.verdict is CorsVerdict.ABSENT
    assert observation.unsafe is False


def test_a_wildcard_without_credentials_is_ordinary():
    observation = analyze_cors(
        "https://x.test/api", {"Access-Control-Allow-Origin": "*"}
    )
    assert observation.verdict is CorsVerdict.SAFE
    assert observation.unsafe is False


def test_a_wildcard_with_credentials_is_unsafe():
    observation = analyze_cors(
        "https://x.test/api",
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert observation.verdict is CorsVerdict.WILDCARD_WITH_CREDENTIALS
    assert observation.unsafe is True


def test_a_specific_origin_with_credentials_and_vary_is_safe():
    observation = analyze_cors(
        "https://x.test/api",
        {
            "Access-Control-Allow-Origin": "https://trusted.example",
            "Access-Control-Allow-Credentials": "true",
            "Vary": "Origin",
        },
    )
    assert observation.verdict is CorsVerdict.SAFE
    assert observation.unsafe is False


def test_credentials_without_vary_is_reported():
    observation = analyze_cors(
        "https://x.test/api",
        {
            "Access-Control-Allow-Origin": "https://trusted.example",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert observation.verdict is CorsVerdict.CREDENTIALED_WITHOUT_VARY
    assert observation.unsafe is True


def test_the_null_origin_with_credentials_is_unsafe():
    observation = analyze_cors(
        "https://x.test/api",
        {
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert observation.verdict is CorsVerdict.NULL_ORIGIN_ALLOWED


def test_a_cors_finding_names_the_headers_it_read():
    observation = analyze_cors(
        "https://x.test/api",
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    finding = cors_finding(observation)
    assert finding.severity is FindingSeverity.MEDIUM
    assert "Access-Control-Allow-Origin" in finding.evidence


# --------------------------------------------------------------------------- #
# Header disclosure
# --------------------------------------------------------------------------- #


def test_a_versioned_banner_is_reported():
    observations = analyze_disclosure("https://x.test/api", {"Server": "nginx/1.18.0"})
    assert len(observations) == 1
    assert observations[0].header == "Server"


def test_an_unversioned_banner_is_not_reported():
    """`Server: nginx` tells an attacker nothing they could not guess."""
    assert analyze_disclosure("https://x.test/api", {"Server": "nginx"}) == ()


def test_a_debug_header_is_reported_at_any_value():
    observations = analyze_disclosure("https://x.test/api", {"X-Debug-Token": "abc"})
    assert len(observations) == 1


def test_credential_headers_are_never_recorded():
    """A disclosure finding must not become the disclosure."""
    observations = analyze_disclosure(
        "https://x.test/api",
        {
            "Authorization": "Bearer secret-value",
            "Set-Cookie": "session=secret-value",
            "Server": "nginx/1.18.0",
        },
    )
    rendered = str(observations)
    assert "secret-value" not in rendered
    assert {o.header for o in observations} == {"Server"}


# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "expected"),
    [("/api/v1/users", "v1"), ("/v2/orders", "v2"), ("/api/users", None)],
)
def test_version_segments_are_recognised(path, expected):
    assert version_of(path) == expected


def test_a_single_version_produces_no_observation():
    assert analyze_inventory(
        observed=("/api/v1/users",), documented_only=(), undocumented=()
    ) == ()


def test_multiple_versions_are_recorded_as_informational():
    observations = analyze_inventory(
        observed=("/api/v1/users", "/api/v2/users"), documented_only=(), undocumented=()
    )
    assert len(observations) == 1
    assert observations[0].kind == "MULTIPLE_VERSIONS"
    assert set(observations[0].versions) == {"v1", "v2"}


def test_documentation_drift_is_recorded_both_ways():
    observations = analyze_inventory(
        observed=("/api/users",),
        documented_only=("/api/legacy",),
        undocumented=("/api/users",),
    )
    kinds = {observation.kind for observation in observations}
    assert kinds == {"DOCUMENTED_NOT_OBSERVED", "OBSERVED_NOT_DOCUMENTED"}


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #


def build_target_app() -> FastAPI:
    """A target with a careful half and a leaky half."""
    target = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @target.get("/")
    def index() -> HTMLResponse:
        return HTMLResponse(
            "<!doctype html><html><head><title>Home</title></head><body>"
            '<a href="/api/public">public</a> '
            '<a href="/api/profile">profile</a> '
            '<a href="/api/error">error</a> '
            '<a href="/api/cors-safe">cors safe</a> '
            '<a href="/api/user-profile">leaky</a> '
            '<a href="/api/debug-error">debug</a> '
            '<a href="/api/cors-unsafe">cors unsafe</a> '
            '<a href="/api/v1/users">v1</a> '
            '<a href="/api/v2/users">v2</a>'
            "</body></html>"
        )

    # --- the careful half ---------------------------------------------- #

    @target.get("/api/public")
    def public() -> JSONResponse:
        return JSONResponse({"id": 1, "name": "Public Item"})

    @target.get("/api/profile")
    def profile() -> JSONResponse:
        return JSONResponse({"id": 1, "name": "Alice", "role": "user"})

    @target.get("/api/error")
    def generic_error() -> JSONResponse:
        return JSONResponse({"detail": "Not Found"}, status_code=404)

    @target.get("/api/cors-safe")
    def cors_safe() -> JSONResponse:
        return JSONResponse(
            {"id": 1},
            headers={
                "Access-Control-Allow-Origin": "https://trusted.example",
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            },
        )

    @target.get("/api/v1/users")
    def v1_users() -> JSONResponse:
        return JSONResponse({"users": [{"id": 1, "name": "Alice"}]})

    @target.get("/api/v2/users")
    def v2_users() -> JSONResponse:
        return JSONResponse({"users": [{"id": 1, "name": "Alice"}]})

    # --- the leaky half ------------------------------------------------- #

    @target.get("/api/user-profile")
    def leaky_profile() -> JSONResponse:
        return JSONResponse(
            {
                "id": 1,
                "name": "Alice",
                "email": "alice@example.test",
                "password_hash": FIXTURE_HASH,
                "api_key": FIXTURE_KEY,
            }
        )

    @target.get("/api/debug-error")
    def debug_error() -> JSONResponse:
        return JSONResponse(
            {
                "error": "Internal Server Error",
                "trace": (
                    f"Traceback (most recent call last):\n"
                    f'  File "/var/www/app/handlers.py", line 42, in get_user\n'
                    f"    {FIXTURE_TRACE}\n"
                    f"psycopg2.errors.UndefinedColumn: column users.x does not exist"
                ),
            },
            status_code=500,
        )

    @target.get("/api/cors-unsafe")
    def cors_unsafe() -> JSONResponse:
        return JSONResponse(
            {"id": 1},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "Server": "nginx/1.18.0",
            },
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


def run_scan(base_url: str, **overrides):
    return WebScanner(
        ScannerConfig(
            timeout_seconds=5.0, total_timeout_seconds=90.0, allow_private_networks=True
        ),
        crawl_config=CrawlConfig(max_pages=20, max_depth=3, time_budget_seconds=30),
        detectors=[],
        api_config=ApiDiscoveryConfig(fetch_documents=False),
        api_security_config=ApiSecurityConfig(**overrides),
    ).scan_sync(base_url)


def rules_of(report) -> set[str]:
    if report.analysis is None:
        return set()
    return {
        group.data.rule.value
        for group in report.analysis.findings
        if group.data.category is FindingCategory.API_SECURITY
    }


def test_the_leaky_endpoint_is_reported(target):
    report = run_scan(target.base_url)
    assert "API_SENSITIVE_DATA_EXPOSURE" in rules_of(report)


def test_the_debug_error_is_reported(target):
    report = run_scan(target.base_url)
    assert "API_VERBOSE_ERROR" in rules_of(report)


def test_the_unsafe_cors_is_reported(target):
    report = run_scan(target.base_url)
    assert "API_CORS_MISCONFIGURATION" in rules_of(report)


def test_the_versioned_banner_is_reported(target):
    report = run_scan(target.base_url)
    assert "API_INFORMATION_DISCLOSURE" in rules_of(report)


def test_multiple_versions_are_recorded(target):
    report = run_scan(target.base_url)
    assert "API_LEGACY_VERSION" in rules_of(report)


def test_the_careful_endpoints_produce_no_sensitive_findings(target):
    """The safe half must be silent. A scanner that flags it is unusable."""
    report = run_scan(target.base_url)
    assert report.api_security is not None

    flagged = {
        observation.url
        for observation in report.api_security.sensitive_fields
        if observation.verdict is ExposureVerdict.UNAUTHORIZED
    }
    assert not any("/api/public" in url for url in flagged), flagged
    assert not any("/api/profile" in url for url in flagged), flagged
    assert any("/api/user-profile" in url for url in flagged), flagged

    unsafe_cors = {observation.url for observation in report.api_security.cors}
    assert not any("/api/cors-safe" in url for url in unsafe_cors), unsafe_cors


def test_the_generic_error_is_not_reported(target):
    report = run_scan(target.base_url)
    errored = {observation.url for observation in report.api_security.errors}
    assert not any("/api/error" in url for url in errored), errored
    assert any("/api/debug-error" in url for url in errored), errored


def test_no_fixture_value_reaches_a_finding(target):
    report = run_scan(target.base_url)
    rendered = " ".join(
        f"{g.data.title} {g.data.description} {g.data.evidence} {g.data.impact} "
        f"{g.data.remediation} {g.data.subject}"
        for g in (report.analysis.findings if report.analysis else [])
    )
    for value in (FIXTURE_HASH, FIXTURE_KEY, FIXTURE_TRACE):
        assert value not in rendered
    assert "Traceback" not in rendered
    assert "/var/www" not in rendered


def test_no_response_body_is_retained(target):
    report = run_scan(target.base_url)
    rendered = str(report.api_security)
    for value in (FIXTURE_HASH, FIXTURE_KEY, FIXTURE_TRACE):
        assert value not in rendered


def test_the_stage_sends_no_request_of_its_own(target):
    """Phase 14 reads what other stages captured. It adds no traffic."""
    report = run_scan(target.base_url)
    assert report.api_security is not None
    assert report.api_security.stats.requests_sent == 0


def test_the_stage_can_be_disabled(target):
    report = run_scan(target.base_url, enabled=False)
    assert report.api_security is not None
    assert report.api_security.stats.endpoints_analyzed == 0
    assert rules_of(report) == set()


# --------------------------------------------------------------------------- #
# Persistence and the API
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
    email = f"apisec-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={
            "name": "API Security Test",
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


def test_findings_reach_the_normal_pipeline(client, allow_loopback, target):
    """No separate findings table, no separate report path."""
    scan_id = scan_the_fixture(client, target.base_url)

    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.category == FindingCategory.API_SECURITY,
                )
            )
        )

    assert rows
    assert all(row.occurrence_count >= 1 for row in rows)

    body = client.get(f"/api/scans/{scan_id}/findings").json()
    rules = {item["rule_id"] for item in body["items"]}
    assert any(rule.startswith("API_") for rule in rules), sorted(rules)


def test_no_fixture_value_reaches_any_api_response(client, allow_loopback, target):
    scan_id = scan_the_fixture(client, target.base_url)

    for path in ("", "/findings", "/endpoints", "/api-endpoints", "/report", "/report/json"):
        text = client.get(f"/api/scans/{scan_id}{path}").text
        for value in (FIXTURE_HASH, FIXTURE_KEY, FIXTURE_TRACE):
            assert value not in text, path
        assert "Traceback" not in text, path


def test_the_report_carries_api_security_coverage(client, allow_loopback, target):
    scan_id = scan_the_fixture(client, target.base_url)

    body = client.get(f"/api/scans/{scan_id}/report").json()
    coverage = body["coverage"]["api_security"]

    assert coverage["analyzed"] is True
    assert coverage["endpoints_analyzed"] > 0
    assert coverage["responses_analyzed"] > 0
    assert coverage["findings_count"] > 0
    assert "unknown_policy" in coverage


def test_a_scan_without_apis_reports_no_analysis(client):
    user_id = register(client)
    from app.models.scan import Scan, ScanStatus

    with SessionLocal() as db:
        scan = Scan(
            user_id=user_id, target_url="https://example.test/", status=ScanStatus.COMPLETED
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id

    coverage = client.get(f"/api/scans/{scan_id}/report").json()["coverage"]["api_security"]
    assert coverage["analyzed"] is False
    assert coverage["findings_count"] == 0
    assert coverage["judged"] is False
