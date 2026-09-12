"""Configuration, deployment and transport security.

Phase 16 is the first stage since Phase 13 that sends requests of its own, so
two families of test carry most of the weight.

**Restraint.** Nothing here may become a brute-forcer. The candidate lists are
constants and the tests assert that: no wordlist, no recursion, no filename
generation, at most three backup spellings per file the scan actually found, and
`/.git/HEAD` alone rather than a walk of the repository. The safe-method
guarantee is asserted against a fixture that records every request it receives.

**Not overclaiming.** A path containing "admin" is not an exposure, a `Server`
header is not a weakness, `{"status":"UP"}` is a correctly built health check,
and a page with links on it is not a directory listing. The secure and ambiguous
fixtures exist to prove the scanner stays quiet about all four.

Every secret in the fixtures below is fake, and several tests assert that none
of them reaches a finding, a report or an API response.
"""

from __future__ import annotations

import secrets
import socket
import threading
import time
import uuid

import pytest
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.main import app as api_app
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner import ScannerConfig, WebScanner
from app.scanner.api.types import ApiDiscoveryConfig
from app.scanner.authorization.matrix import (
    AccessRule,
    AuthorizationMatrix,
    AuthorizationPlan,
)
from app.scanner.authorization.types import AccessExpectation
from app.scanner.config_security import discovery
from app.scanner.config_security.deployment import (
    detect_debug,
    detect_directory_listing,
    detect_technology,
    find_source_map_reference,
    is_default_content,
    signals_for,
)
from app.scanner.config_security.discovery import (
    backup_variants,
    body_matches_candidate,
    classify,
)
from app.scanner.config_security.findings import (
    admin_interface_finding,
    repository_metadata_finding,
    sensitive_file_finding,
    technology_finding,
    weak_csp_finding,
    weak_hsts_finding,
)
from app.scanner.config_security.headers import analyze_csp, analyze_header_defects
from app.scanner.config_security.methods import (
    analyze_options,
    parse_methods,
    surprising_methods,
)
from app.scanner.config_security.path_confusion import analyze as analyze_paths
from app.scanner.config_security.transport import (
    analyze as analyze_transport,
)
from app.scanner.config_security.transport import (
    grade_hsts,
    is_local_target,
    parse_hsts,
)
from app.scanner.config_security.types import (
    CandidateKind,
    CandidateOutcome,
    ConfigSecurityConfig,
    ConfigSecurityLimits,
    CspGrade,
    DebugSignal,
    HeaderDefect,
    HstsQuality,
    NormalizationSignal,
    RedirectBehaviour,
    TlsObservation,
)
from app.scanner.crawler.types import CrawlConfig
from app.scanner.security.types import FindingCategory, FindingSeverity
from app.scanner.types import ScanErrorCode
from app.services import scan_service

PASSWORD = "Sup3rSecret!pass"

#: Fake, fixture-only. Several tests assert these never reach a finding.
FIXTURE_DB_PASSWORD = "fixture-only-db-pass-8f3a2c"
FIXTURE_API_KEY = "fixture-only-api-key-91bd77"
FIXTURE_GIT_REF = "ref: refs/heads/fixture-branch"
FIXTURE_SOURCE = "function fixtureOnlySecretHelper(){return 42}"


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host,local",
    [
        ("localhost", True),
        ("127.0.0.1", True),
        ("192.168.1.10", True),
        ("10.0.0.5", True),
        ("172.16.0.1", True),
        ("172.31.255.1", True),
        ("app.test", True),
        ("service.internal", True),
        ("172.32.0.1", False),
        ("example.com", False),
        ("11.0.0.1", False),
    ],
)
def test_local_targets_are_exempt_from_https_expectations(host, local):
    """A developer scanning their own machine has misconfigured nothing."""
    assert is_local_target(host) is local


def test_https_target_is_recognised():
    observation = analyze_transport(
        host="example.com",
        requested_https=True,
        final_url="https://example.com/",
        redirect_count=0,
        headers={},
    )
    assert observation.secure_transport is True
    assert observation.redirect is RedirectBehaviour.NOT_APPLICABLE


def test_http_redirecting_to_https_is_the_correct_setup():
    observation = analyze_transport(
        host="example.com",
        requested_https=False,
        final_url="https://example.com/",
        redirect_count=1,
        headers={},
    )
    assert observation.redirect is RedirectBehaviour.REDIRECTS_TO_HTTPS
    assert observation.secure_transport is True


def test_http_with_no_redirect_is_recorded():
    observation = analyze_transport(
        host="example.com",
        requested_https=False,
        final_url="http://example.com/",
        redirect_count=0,
        headers={},
    )
    assert observation.redirect is RedirectBehaviour.SERVES_OVER_HTTP
    assert observation.secure_transport is False


def test_an_https_target_has_no_redirect_verdict_invented():
    """`NOT_APPLICABLE`, not "no redirect" — there was no plaintext request."""
    observation = analyze_transport(
        host="example.com",
        requested_https=True,
        final_url="https://example.com/",
        redirect_count=0,
        headers={},
    )
    assert observation.redirect is RedirectBehaviour.NOT_APPLICABLE


@pytest.mark.parametrize(
    "value,expected",
    [
        ("max-age=31536000; includeSubDomains", HstsQuality.STRONG),
        ("max-age=31536000", HstsQuality.HOST_ONLY),
        ("max-age=31536000; includeSubDomains; preload", HstsQuality.STRONG),
        # Phase 3 owns both of these, so this module declines to grade them.
        ("max-age=0", HstsQuality.UNKNOWN),
        ("max-age=300", HstsQuality.UNKNOWN),
    ],
)
def test_hsts_quality_grading(value, expected):
    max_age, include_subdomains, _ = parse_hsts(value)
    assert (
        grade_hsts(
            value,
            is_https=True,
            max_age=max_age,
            include_subdomains=include_subdomains,
        )
        is expected
    )


def test_hsts_over_plain_http_is_inert():
    assert (
        grade_hsts(
            "max-age=31536000", is_https=False, max_age=31536000, include_subdomains=False
        )
        is HstsQuality.INEFFECTIVE_OVER_HTTP
    )


def test_preload_is_recorded_and_never_required():
    _, _, preload = parse_hsts("max-age=31536000; includeSubDomains; preload")
    assert preload is True
    observation = analyze_transport(
        host="example.com",
        requested_https=True,
        final_url="https://example.com/",
        redirect_count=0,
        headers={"strict-transport-security": "max-age=31536000; includeSubDomains"},
    )
    # No preload, and no finding: plenty of correct deployments decline it.
    assert observation.hsts_preload is False
    assert weak_hsts_finding(observation) is None


def test_phase_three_hsts_cases_produce_no_phase_sixteen_finding():
    """The boundary that stops one defect being reported twice."""
    for header in (None, "max-age=0", "max-age=300"):
        observation = analyze_transport(
            host="example.com",
            requested_https=True,
            final_url="https://example.com/",
            redirect_count=0,
            headers={"strict-transport-security": header} if header else {},
        )
        assert weak_hsts_finding(observation) is None, header


def test_host_only_hsts_is_a_low_finding():
    observation = analyze_transport(
        host="example.com",
        requested_https=True,
        final_url="https://example.com/",
        redirect_count=0,
        headers={"strict-transport-security": "max-age=31536000"},
    )
    finding = weak_hsts_finding(observation)
    assert finding is not None
    assert finding.severity is FindingSeverity.LOW
    assert "includeSubDomains" in finding.description


def test_certificate_failure_is_classified_without_naming_a_cause():
    observation = analyze_transport(
        host="example.com",
        requested_https=True,
        final_url=None,
        redirect_count=0,
        headers={},
        reached=False,
        error_code=ScanErrorCode.TLS_ERROR,
    )
    assert observation.tls is TlsObservation.CERTIFICATE_REJECTED


def test_a_connection_failure_is_not_a_certificate_failure():
    observation = analyze_transport(
        host="example.com",
        requested_https=True,
        final_url=None,
        redirect_count=0,
        headers={},
        reached=False,
        error_code=ScanErrorCode.CONNECTION_FAILED,
    )
    assert observation.tls is TlsObservation.UNREACHABLE


# --------------------------------------------------------------------------- #
# HTTP methods
# --------------------------------------------------------------------------- #


def test_allow_header_is_parsed():
    assert parse_methods("GET, POST, OPTIONS") == ("GET", "POST", "OPTIONS")
    assert parse_methods(None) == ()
    assert parse_methods("  get ,, PoSt ") == ("GET", "POST")


def test_cors_advertised_methods_count_as_advertised():
    observation = analyze_options(
        "https://x/api/thing",
        {"access-control-allow-methods": "GET, DELETE"},
        status_code=204,
    )
    assert "DELETE" in observation.advertised


def test_rest_methods_on_an_api_path_are_not_surprising():
    """DELETE on a REST resource is the design, not a vulnerability."""
    observation = analyze_options(
        "https://x/api/orders/1",
        {"allow": "GET, POST, PUT, PATCH, DELETE, OPTIONS"},
        status_code=200,
    )
    assert surprising_methods(observation) == ()


def test_state_changing_methods_off_an_api_path_are_surprising():
    observation = analyze_options(
        "https://x/contact", {"allow": "GET, POST, DELETE"}, status_code=200
    )
    assert "DELETE" in surprising_methods(observation)


def test_trace_is_always_surprising():
    observation = analyze_options(
        "https://x/api/thing", {"allow": "GET, TRACE"}, status_code=200
    )
    assert "TRACE" in surprising_methods(observation)
    assert observation.trace_advertised is True


def test_advertised_methods_are_never_treated_as_observed():
    """Documentation is not behaviour, and the two stay in separate fields."""
    observation = analyze_options(
        "https://x/thing", {"allow": "GET, DELETE"}, status_code=200, observed=("GET",)
    )
    assert observation.observed == ("GET",)
    assert "DELETE" in observation.untested
    assert "DELETE" not in observation.observed


def test_trace_is_not_confirmed_without_being_sent():
    observation = analyze_options(
        "https://x/thing", {"allow": "GET, TRACE"}, status_code=200
    )
    assert observation.trace_confirmed is False


# --------------------------------------------------------------------------- #
# Candidate discovery: bounded, and no enumeration
# --------------------------------------------------------------------------- #


def test_candidate_lists_are_small_fixed_constants():
    """The property that keeps this a scanner rather than a brute-forcer."""
    total = sum(
        len(paths)
        for paths in (
            discovery.ADMIN_CANDIDATES,
            discovery.MANAGEMENT_CANDIDATES,
            discovery.HEALTH_CANDIDATES,
            discovery.DEBUG_CANDIDATES,
            discovery.SENSITIVE_FILE_CANDIDATES,
            discovery.REPOSITORY_CANDIDATES,
            discovery.SAMPLE_CANDIDATES,
        )
    )
    assert total < 100, total
    # Tuples, so nothing can append to them at runtime.
    assert isinstance(discovery.SENSITIVE_FILE_CANDIDATES, tuple)


def test_repository_check_is_one_path_only():
    """`.git/HEAD` proves the directory is served. Nothing else is fetched."""
    assert discovery.REPOSITORY_CANDIDATES == ("/.git/HEAD",)


def test_backup_variants_derive_from_a_real_path_and_are_capped():
    variants = backup_variants("/config.json", limit=3)
    assert len(variants) == 3
    assert all(v.startswith("/config.json") for v in variants)


def test_backup_variants_are_not_generated_for_uninteresting_files():
    assert backup_variants("/logo.png") == ()
    assert backup_variants("/index.html") == ()


def test_no_candidate_list_can_produce_an_arbitrary_filename():
    """Every path is literal; none is built from a pattern."""
    for kind in (
        CandidateKind.ADMIN,
        CandidateKind.MANAGEMENT,
        CandidateKind.DEBUG,
        CandidateKind.SENSITIVE_FILE,
        CandidateKind.REPOSITORY,
        CandidateKind.SAMPLE,
    ):
        for path in discovery.candidates_for(kind):
            assert path.startswith("/")
            assert "*" not in path and "{" not in path


@pytest.mark.parametrize(
    "path,body,matches",
    [
        ("/.env", b"DB_HOST=localhost\nDB_PASS=x\n", True),
        ("/.env", b"<html><body>Not found</body></html>", False),
        ("/.git/HEAD", b"ref: refs/heads/main\n", True),
        ("/.git/HEAD", b"<!doctype html><html>", False),
        ("/config.json", b'{"a": 1}', True),
        ("/config.json", b"<html>", False),
        ("/robots.txt", b"User-agent: *\nDisallow: /x\n", True),
    ],
)
def test_body_shape_guards_against_catch_all_routes(path, body, matches):
    """The guard that stops every SPA reporting every candidate as exposed."""
    assert body_matches_candidate(path, body) is matches


def test_a_single_page_app_catch_all_is_not_an_exposure():
    observation = classify(
        path="/.env",
        kind=CandidateKind.SENSITIVE_FILE,
        status_code=200,
        headers={"content-type": "text/html; charset=utf-8"},
        body=b"<!doctype html><html><div id='root'></div></html>",
    )
    assert observation.outcome is CandidateOutcome.NOT_FOUND
    assert "body:html-catch-all" in observation.signals


def test_a_refused_candidate_is_protected_not_exposed():
    for status in (401, 403):
        observation = classify(
            path="/admin", kind=CandidateKind.ADMIN, status_code=status
        )
        assert observation.outcome is CandidateOutcome.PROTECTED


def test_untested_candidates_are_distinct_from_absent_ones():
    """Coverage honesty: a budget cut is not a clean result."""
    untested = discovery.not_tested(("/a", "/b"), CandidateKind.ADMIN)
    assert all(o.outcome is CandidateOutcome.NOT_TESTED for o in untested)
    assert all(not o.exposed for o in untested)


# --------------------------------------------------------------------------- #
# Findings: no content, ever
# --------------------------------------------------------------------------- #


def test_an_env_finding_carries_no_value_from_the_file():
    observation = classify(
        path="/.env",
        kind=CandidateKind.SENSITIVE_FILE,
        status_code=200,
        headers={"content-type": "text/plain"},
        body=f"DB_PASSWORD={FIXTURE_DB_PASSWORD}\nAPI_KEY={FIXTURE_API_KEY}\n".encode(),
    )
    finding = sensitive_file_finding(observation)
    assert finding is not None
    assert finding.severity is FindingSeverity.HIGH
    blob = " ".join(
        [
            finding.title,
            finding.description,
            finding.evidence,
            finding.impact,
            finding.remediation,
        ]
    )
    assert FIXTURE_DB_PASSWORD not in blob
    assert FIXTURE_API_KEY not in blob
    assert "DB_PASSWORD" not in blob


def test_a_git_finding_carries_no_repository_content():
    observation = classify(
        path="/.git/HEAD",
        kind=CandidateKind.REPOSITORY,
        status_code=200,
        headers={"content-type": "text/plain"},
        body=FIXTURE_GIT_REF.encode(),
    )
    finding = repository_metadata_finding(observation)
    assert finding is not None
    assert finding.severity is FindingSeverity.HIGH
    assert "fixture-branch" not in finding.evidence + finding.description
    assert "refs/heads" not in finding.evidence


def test_robots_txt_is_fetched_but_never_reported():
    observation = classify(
        path="/robots.txt",
        kind=CandidateKind.SENSITIVE_FILE,
        status_code=200,
        headers={"content-type": "text/plain"},
        body=b"User-agent: *\nDisallow: /private\n",
    )
    assert observation.exposed is True
    assert sensitive_file_finding(observation) is None


def test_an_admin_path_alone_is_only_informational():
    """"admin" in a path is not an exposure. A login form looks like this."""
    observation = classify(
        path="/admin",
        kind=CandidateKind.ADMIN,
        status_code=200,
        headers={"content-type": "text/html"},
        body=b"<html><form>login</form></html>",
    )
    finding = admin_interface_finding(observation)
    assert finding is not None
    assert finding.severity is FindingSeverity.INFO
    assert "No authorization policy was supplied" in finding.description


def test_a_declared_policy_turns_admin_exposure_into_a_real_finding():
    observation = classify(
        path="/admin",
        kind=CandidateKind.ADMIN,
        status_code=200,
        headers={"content-type": "text/html"},
        body=b"<html>dashboard</html>",
    )
    finding = admin_interface_finding(observation, policy_denies=True)
    assert finding is not None
    assert finding.severity is FindingSeverity.HIGH


def test_technology_disclosure_stays_informational():
    observation = detect_technology("https://x/", {"server": "nginx/1.24.0"})[0]
    finding = technology_finding(observation)
    assert finding.severity is FindingSeverity.INFO
    assert "not a vulnerability" in finding.description


def test_credential_headers_are_never_read_as_technology():
    observations = detect_technology(
        "https://x/",
        {
            "server": "nginx",
            "authorization": "Bearer fixture-token",
            "set-cookie": "session=fixture",
            "x-api-key": FIXTURE_API_KEY,
        },
    )
    blob = repr(observations)
    assert "fixture-token" not in blob
    assert FIXTURE_API_KEY not in blob
    assert [o.header for o in observations] == ["server"]


# --------------------------------------------------------------------------- #
# CSP and header defects
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "policy,grade",
    [
        ("default-src 'self'; script-src 'self'", CspGrade.RESTRICTED),
        ("default-src 'self'; script-src 'self' 'unsafe-inline'", CspGrade.WEAKENED),
        ("script-src 'nonce-r4nd0m' 'unsafe-inline'", CspGrade.NONCE_OR_HASH),
        ("script-src 'sha256-abc123='", CspGrade.NONCE_OR_HASH),
        ("default-src *", CspGrade.UNRESTRICTED),
        ("default-src 'self'; script-src https:", CspGrade.UNRESTRICTED),
        ("default-src 'self'; script-src 'self' data:", CspGrade.UNRESTRICTED),
    ],
)
def test_csp_is_graded_on_source_breadth(policy, grade):
    assert analyze_csp("https://x/", {"content-security-policy": policy}).grade is grade


def test_only_an_unrestricted_csp_produces_a_phase_sixteen_finding():
    """unsafe-inline is Phase 3's to report; saying it twice helps nobody."""
    weakened = analyze_csp(
        "https://x/", {"content-security-policy": "script-src 'self' 'unsafe-inline'"}
    )
    assert weak_csp_finding(weakened) is None

    unrestricted = analyze_csp("https://x/", {"content-security-policy": "default-src *"})
    finding = weak_csp_finding(unrestricted)
    assert finding is not None
    assert finding.rule.value == "CONFIG_WEAK_CSP"


def test_a_nonce_makes_unsafe_inline_inert_and_the_grade_says_so():
    observation = analyze_csp(
        "https://x/", {"content-security-policy": "script-src 'nonce-abc' 'unsafe-inline'"}
    )
    assert observation.grade is CspGrade.NONCE_OR_HASH
    assert observation.has_unsafe_inline is True
    assert weak_csp_finding(observation) is None


def test_a_missing_csp_is_left_to_phase_three():
    observation = analyze_csp("https://x/", {})
    assert observation.grade is CspGrade.ABSENT
    assert weak_csp_finding(observation) is None


def test_script_src_falls_back_to_default_src():
    observation = analyze_csp("https://x/", {"content-security-policy": "default-src *"})
    assert observation.grade is CspGrade.UNRESTRICTED
    assert "*" in observation.wildcard_sources


@pytest.mark.parametrize(
    "headers,defect",
    [
        ({"x-frame-options": "DENY, SAMEORIGIN"}, HeaderDefect.DUPLICATE_CONFLICTING),
        ({"x-content-type-options": ""}, HeaderDefect.EMPTY_VALUE),
        ({"x-frame-options": "ALLOW-FROM https://x"}, HeaderDefect.INVALID_VALUE),
        ({"x-xss-protection": "1; mode=block"}, HeaderDefect.DEPRECATED),
    ],
)
def test_present_but_broken_headers_are_detected(headers, defect):
    defects = analyze_header_defects("https://x/", headers)
    assert defect in {d.defect for d in defects}


def test_a_correct_header_produces_no_defect():
    assert analyze_header_defects("https://x/", {"x-frame-options": "DENY"}) == ()


def test_absent_headers_are_never_reported_here():
    """Absence is Phase 3's subject. This module only grades what is present."""
    assert analyze_header_defects("https://x/", {}) == ()


# --------------------------------------------------------------------------- #
# Debug, listings, defaults, source maps
# --------------------------------------------------------------------------- #


def test_two_markers_are_needed_to_call_something_debug_mode():
    one = detect_debug("https://x/", headers={"server": "Werkzeug/2.3.0"}, body=b"")
    assert one is not None
    assert one.conclusive is False

    two = detect_debug(
        "https://x/",
        headers={"server": "Werkzeug/2.3.0"},
        body=b"<html>Traceback (most recent call last): ...</html>",
    )
    assert two.conclusive is True


def test_one_marker_plus_a_phase_fourteen_leak_is_conclusive():
    observation = detect_debug(
        "https://x/",
        headers={"server": "Werkzeug/2.3.0"},
        body=b"",
        corroborated=True,
    )
    assert observation.conclusive is True


def test_a_normal_page_produces_no_debug_signal():
    assert (
        detect_debug(
            "https://x/",
            headers={"server": "nginx/1.24"},
            body=b"<html><h1>Welcome</h1><p>debug your workflow</p></html>",
        )
        is None
    )


def test_debug_signals_carry_no_page_text():
    observation = detect_debug(
        "https://x/",
        headers={"server": "Werkzeug/2.3.0"},
        body=f"<html>Traceback (most recent call last): {FIXTURE_DB_PASSWORD}</html>".encode(),
    )
    assert FIXTURE_DB_PASSWORD not in repr(observation)
    assert all(isinstance(s, DebugSignal) for s in observation.signals)


def test_a_directory_index_is_recognised():
    observation = detect_directory_listing(
        "https://x/files/",
        headers={"server": "nginx/1.24"},
        body=(
            b"<html><head><title>Index of /files/</title></head><body>"
            b'<h1>Index of /files/</h1><a href="a.txt">a</a><a href="b.txt">b</a>'
            b"</body></html>"
        ),
    )
    assert observation is not None
    assert observation.server_style == "nginx"
    assert observation.entry_count == 2


def test_a_normal_index_page_is_not_a_directory_listing():
    assert (
        detect_directory_listing(
            "https://x/",
            body=(
                b"<html><h1>My Blog</h1>"
                b'<a href="/p/1">First</a><a href="/p/2">Second</a></html>'
            ),
        )
        is None
    )


def test_default_server_content_is_recognised():
    assert is_default_content(b"<html><h1>Welcome to nginx!</h1></html>") is True
    assert is_default_content(b"<html><h1>Our Product</h1></html>") is False


def test_a_source_map_is_only_found_when_the_asset_names_it():
    assert (
        find_source_map_reference("https://x/app.js", b"var a=1;\n//# sourceMappingURL=app.js.map")
        == "https://x/app.js.map"
    )
    # No reference means no map is looked for. Nothing is guessed.
    assert find_source_map_reference("https://x/app.js", b"var a=1;") is None


def test_an_inlined_source_map_is_not_a_separate_exposure():
    assert (
        find_source_map_reference(
            "https://x/app.js", b"//# sourceMappingURL=data:application/json;base64,eyJ4Ijox"
        )
        is None
    )


def test_capture_time_signals_hold_no_page_text():
    signals = signals_for(
        "https://x/app.js",
        headers={"server": "Werkzeug/2.3.0"},
        body=f"//# sourceMappingURL=app.js.map\n{FIXTURE_SOURCE}".encode(),
    )
    assert signals is not None
    assert signals.source_map_reference == "https://x/app.js.map"
    assert FIXTURE_SOURCE not in repr(signals)


def test_capture_time_signals_are_none_when_nothing_is_notable():
    assert signals_for("https://x/", headers={"server": "nginx"}, body=b"<html>hi</html>") is None


# --------------------------------------------------------------------------- #
# Path normalization
# --------------------------------------------------------------------------- #


def test_a_tolerant_router_is_not_a_misconfiguration():
    """Both spellings serving 200 is normal, and must produce nothing."""
    assert analyze_paths({"https://x/a": 200, "https://x/a/": 200}) == ()


def test_divergent_trailing_slash_behaviour_is_recorded():
    observed = analyze_paths({"https://x/a": 200, "https://x/a/": 403})
    assert [o.signal for o in observed] == [NormalizationSignal.TRAILING_SLASH_DIVERGENCE]


def test_a_slash_normalising_redirect_is_not_a_finding():
    assert analyze_paths({"https://x/a": 301}, redirects={"https://x/a": "/a/"}) == ()


def test_a_redirect_leaving_the_tree_is_recorded():
    observed = analyze_paths(
        {"https://x/a": 301}, redirects={"https://x/a": "/somewhere/else"}
    )
    assert [o.signal for o in observed] == [NormalizationSignal.REDIRECT_REWRITES_PATH]


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


class _Recorder:
    """Records every request a fixture receives, so tests can assert on them."""

    def __init__(self) -> None:
        self.received: list[dict] = []


def _install_recorder(target: FastAPI, recorder: _Recorder) -> None:
    @target.middleware("http")
    async def record(request: Request, call_next):
        recorder.received.append({"method": request.method, "path": request.url.path})
        return await call_next(request)


def build_secure_app(recorder: _Recorder) -> FastAPI:
    """A correctly configured deployment. It must produce no finding."""
    target = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    _install_recorder(target, recorder)

    @target.get("/")
    def index() -> HTMLResponse:
        return HTMLResponse(
            "<!doctype html><html><head><title>Secure</title></head><body>"
            '<h1>Product</h1><a href="/about">about</a><a href="/pricing">pricing</a>'
            "</body></html>",
            headers={
                "content-security-policy": "default-src 'self'; script-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
            },
        )

    @target.get("/about")
    def about() -> HTMLResponse:
        return HTMLResponse("<html><head><title>About</title></head><body>us</body></html>")

    @target.get("/pricing")
    def pricing() -> HTMLResponse:
        return HTMLResponse("<html><head><title>Pricing</title></head><body>£</body></html>")

    return target


def build_vulnerable_app(recorder: _Recorder) -> FastAPI:
    """A deployment that gets it wrong in the ways this phase can see."""
    target = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    _install_recorder(target, recorder)

    @target.get("/")
    def index() -> HTMLResponse:
        return HTMLResponse(
            "<!doctype html><html><head><title>Vulnerable</title></head><body>"
            '<a href="/files/">files</a><a href="/debug">debug</a>'
            '<a href="/admin">admin</a><script src="/app.js"></script>'
            "</body></html>",
            headers={
                # Wildcard script source: the one CSP case Phase 16 reports.
                "content-security-policy": "default-src *; script-src *",
                "server": "Werkzeug/2.3.0 Python/3.12",
                "x-frame-options": "DENY, SAMEORIGIN",
            },
        )

    @target.get("/.env")
    def env_file() -> PlainTextResponse:
        return PlainTextResponse(
            f"DB_PASSWORD={FIXTURE_DB_PASSWORD}\nAPI_KEY={FIXTURE_API_KEY}\n"
        )

    @target.get("/.git/HEAD")
    def git_head() -> PlainTextResponse:
        return PlainTextResponse(f"{FIXTURE_GIT_REF}\n")

    @target.get("/debug")
    def debug_page() -> HTMLResponse:
        return HTMLResponse(
            "<html><body>Traceback (most recent call last):"
            "<div>Werkzeug Debugger</div>The console is locked</body></html>"
        )

    @target.get("/admin")
    def admin() -> HTMLResponse:
        return HTMLResponse("<html><body><h1>Admin dashboard</h1></body></html>")

    @target.get("/actuator/env")
    def actuator_env() -> JSONResponse:
        return JSONResponse({"activeProfiles": ["prod"], "propertySources": []})

    @target.get("/files/")
    def listing() -> HTMLResponse:
        return HTMLResponse(
            "<html><head><title>Index of /files/</title></head><body>"
            '<h1>Index of /files/</h1><a href="../">Parent Directory</a>'
            '<a href="a.txt">a.txt</a><a href="b.txt">b.txt</a></body></html>",',
            headers={"server": "nginx/1.24.0"},
        )

    @target.get("/app.js")
    def asset() -> Response:
        return Response(
            content=b"var x=1;\n//# sourceMappingURL=/app.js.map",
            media_type="application/javascript",
        )

    @target.get("/app.js.map")
    def source_map() -> JSONResponse:
        return JSONResponse(
            {"version": 3, "sources": ["src/a.ts", "src/b.ts"], "mappings": ""}
        )

    @target.get("/test.html")
    def sample() -> HTMLResponse:
        return HTMLResponse("<html><body>Welcome to nginx!</body></html>")

    @target.api_route("/contact", methods=["GET", "OPTIONS"])
    def contact() -> Response:
        return Response(
            content=b"contact",
            media_type="text/plain",
            headers={"allow": "GET, POST, DELETE, TRACE"},
        )

    return target


def build_ambiguous_app(recorder: _Recorder) -> FastAPI:
    """A deployment where the honest answer is "nothing conclusive"."""
    target = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    _install_recorder(target, recorder)

    @target.get("/")
    def index() -> HTMLResponse:
        return HTMLResponse(
            "<!doctype html><html><head><title>Ambiguous</title></head><body>"
            '<a href="/health">health</a><a href="/admin">admin</a></body></html>',
            headers={
                # Weakened but not unrestricted: Phase 3's to report, not this.
                "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
                "server": "nginx/1.24.0",
            },
        )

    @target.get("/health")
    def health() -> JSONResponse:
        return JSONResponse({"status": "UP"})

    @target.get("/metrics")
    def metrics() -> PlainTextResponse:
        return PlainTextResponse("requests_total 42\n")

    @target.get("/admin")
    def admin() -> JSONResponse:
        # Correctly protected. This is what a well-built deployment looks like.
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

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


def _serve(app: FastAPI, recorder: _Recorder):
    server = _Server(app)
    server.recorder = recorder  # type: ignore[attr-defined]
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="module")
def secure_target():
    recorder = _Recorder()
    yield from _serve(build_secure_app(recorder), recorder)


@pytest.fixture(scope="module")
def vulnerable_target():
    recorder = _Recorder()
    yield from _serve(build_vulnerable_app(recorder), recorder)


@pytest.fixture(scope="module")
def ambiguous_target():
    recorder = _Recorder()
    yield from _serve(build_ambiguous_app(recorder), recorder)


def run_scan(base_url: str, *, plan: AuthorizationPlan | None = None, **overrides):
    return WebScanner(
        ScannerConfig(
            timeout_seconds=5.0, total_timeout_seconds=120.0, allow_private_networks=True
        ),
        crawl_config=CrawlConfig(max_pages=20, max_depth=3, time_budget_seconds=30),
        detectors=[],
        api_config=ApiDiscoveryConfig(fetch_documents=False),
        authorization=plan or AuthorizationPlan(),
        config_security=ConfigSecurityConfig(**overrides),
    ).scan_sync(base_url)


def config_rules(report) -> set[str]:
    if report.analysis is None:
        return set()
    return {
        group.data.rule.value
        for group in report.analysis.findings
        if group.data.category is FindingCategory.CONFIGURATION
    }


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #


def test_only_safe_methods_ever_reach_the_target(vulnerable_target):
    """The guarantee the whole phase rests on."""
    before = len(vulnerable_target.recorder.received)
    run_scan(vulnerable_target.base_url)

    methods = {e["method"] for e in vulnerable_target.recorder.received[before:]}
    assert methods <= {"GET", "HEAD", "OPTIONS"}, methods
    assert not methods & {"PUT", "PATCH", "DELETE", "TRACE", "POST", "CONNECT"}


def test_the_secure_target_produces_no_configuration_finding(secure_target):
    """The fixture that matters most: it exists to prove silence."""
    report = run_scan(secure_target.base_url)
    result = report.config_security
    assert result is not None

    rules = config_rules(report)
    for rule in (
        "CONFIG_SENSITIVE_FILE_EXPOSURE",
        "CONFIG_REPOSITORY_METADATA_EXPOSURE",
        "CONFIG_DEBUG_EXPOSURE",
        "CONFIG_DIRECTORY_LISTING",
        "CONFIG_WEAK_CSP",
        "CONFIG_SOURCE_MAP_EXPOSURE",
        "CONFIG_DEFAULT_SAMPLE_EXPOSURE",
        "CONFIG_ADMIN_INTERFACE_EXPOSURE",
        "CONFIG_HEADER_MISCONFIGURATION",
        "CONFIG_INSECURE_HTTP",
    ):
        assert rule not in rules, rule
    assert result.stats.sensitive_files_exposed == 0


def test_the_vulnerable_target_is_reported(vulnerable_target):
    report = run_scan(vulnerable_target.base_url)
    result = report.config_security
    assert result is not None

    rules = config_rules(report)
    assert "CONFIG_SENSITIVE_FILE_EXPOSURE" in rules
    assert "CONFIG_REPOSITORY_METADATA_EXPOSURE" in rules
    assert "CONFIG_WEAK_CSP" in rules
    assert "CONFIG_HEADER_MISCONFIGURATION" in rules
    assert result.stats.sensitive_files_exposed >= 2


def test_the_repository_is_never_enumerated(vulnerable_target):
    """One metadata file, then stop. No objects, refs or config."""
    before = len(vulnerable_target.recorder.received)
    run_scan(vulnerable_target.base_url)

    git_paths = [
        e["path"]
        for e in vulnerable_target.recorder.received[before:]
        if e["path"].startswith("/.git")
    ]
    assert git_paths == ["/.git/HEAD"], git_paths


def test_no_arbitrary_filenames_are_requested(vulnerable_target):
    """Every path Phase 16 adds is a constant or a backup of a found file.

    Phase 16's own traffic is isolated by differencing against a passive run:
    whatever the crawl would have requested anyway is subtracted, so what is
    left is exactly what this stage contributed.
    """
    before = len(vulnerable_target.recorder.received)
    run_scan(vulnerable_target.base_url, probe_candidates=False)
    crawl_only = {e["path"] for e in vulnerable_target.recorder.received[before:]}

    before = len(vulnerable_target.recorder.received)
    run_scan(vulnerable_target.base_url)
    with_probing = {e["path"] for e in vulnerable_target.recorder.received[before:]}

    known = set()
    for kind in CandidateKind:
        known.update(discovery.candidates_for(kind))

    added = with_probing - crawl_only
    assert added, "the probing run should have requested something extra"

    invented = {
        path
        for path in added
        if path not in known
        # Backups derive from a file the scan found; the suffix set is fixed.
        and not path.endswith(tuple(discovery.BACKUP_SUFFIXES))
    }
    assert not invented, invented


def test_no_fixture_secret_reaches_any_finding(vulnerable_target):
    report = run_scan(vulnerable_target.base_url)
    assert report.analysis is not None
    for group in report.analysis.findings:
        blob = " ".join(
            [
                group.data.title,
                group.data.description,
                group.data.evidence,
                group.data.impact,
                group.data.remediation,
                group.data.subject or "",
            ]
        )
        assert FIXTURE_DB_PASSWORD not in blob
        assert FIXTURE_API_KEY not in blob
        assert "fixture-branch" not in blob
        assert FIXTURE_SOURCE not in blob


def test_the_ambiguous_target_is_not_exaggerated(ambiguous_target):
    report = run_scan(ambiguous_target.base_url)
    result = report.config_security
    assert result is not None

    rules = config_rules(report)
    # A health check answering {"status":"UP"} is a correct health check.
    assert "CONFIG_MANAGEMENT_INTERFACE_EXPOSURE" not in rules
    # unsafe-inline without a wildcard is Phase 3's to report.
    assert "CONFIG_WEAK_CSP" not in rules
    # A 401 from /admin is the correct answer.
    assert "CONFIG_ADMIN_INTERFACE_EXPOSURE" not in rules
    assert "CONFIG_SENSITIVE_FILE_EXPOSURE" not in rules
    assert "CONFIG_DEBUG_EXPOSURE" not in rules
    # A Server header is normal, and is recorded at INFO.
    assert "CONFIG_TECHNOLOGY_DISCLOSURE" in rules


def test_a_protected_admin_endpoint_is_not_an_exposure(ambiguous_target):
    report = run_scan(ambiguous_target.base_url)
    result = report.config_security
    assert result is not None
    admin = [c for c in result.candidates if c.path == "/admin"]
    assert admin
    assert admin[0].outcome is CandidateOutcome.PROTECTED


def test_no_configuration_finding_is_ever_critical(vulnerable_target):
    report = run_scan(vulnerable_target.base_url)
    assert report.analysis is not None
    for group in report.analysis.findings:
        if group.data.category is FindingCategory.CONFIGURATION:
            assert group.data.severity is not FindingSeverity.CRITICAL


def test_localhost_is_never_reported_as_insecure_transport(vulnerable_target):
    """Even with the flag on: a loopback target has misconfigured nothing."""
    report = run_scan(vulnerable_target.base_url, require_https=True)
    assert "CONFIG_INSECURE_HTTP" not in config_rules(report)


def test_the_budget_is_respected_and_shortfall_is_reported(vulnerable_target):
    report = run_scan(
        vulnerable_target.base_url,
        limits=ConfigSecurityLimits(max_requests=5),
    )
    result = report.config_security
    assert result is not None
    assert result.stats.requests_sent <= 5
    assert result.stats.budget_exhausted is True
    assert result.stats.candidates_not_tested > 0
    # A candidate the budget never reached is not a candidate that passed.
    untested = [c for c in result.candidates if c.outcome is CandidateOutcome.NOT_TESTED]
    assert untested
    assert all(not c.exposed for c in untested)


def test_passive_mode_sends_nothing_and_still_analyses(vulnerable_target):
    before = len(vulnerable_target.recorder.received)
    report = run_scan(vulnerable_target.base_url, probe_candidates=False)
    result = report.config_security
    assert result is not None
    assert result.stats.requests_sent == 0
    assert result.candidates == ()
    # The passive half still works: headers, CSP and technology all analysed.
    assert result.technologies
    assert config_rules(report)
    # Only crawl traffic reached the fixture, no candidate probing.
    paths = {e["path"] for e in vulnerable_target.recorder.received[before:]}
    assert "/.env" not in paths


def test_the_stage_can_be_disabled(secure_target):
    report = run_scan(secure_target.base_url, enabled=False)
    result = report.config_security
    assert result is not None
    assert result.candidates == ()
    assert config_rules(report) == set()


def test_a_declared_policy_escalates_admin_exposure(vulnerable_target):
    plan = AuthorizationPlan(
        matrix=AuthorizationMatrix(
            rules=(
                AccessRule(
                    context_id="anonymous",
                    pattern="/admin*",
                    expectation=AccessExpectation.DENIED,
                ),
            )
        )
    )
    report = run_scan(vulnerable_target.base_url, plan=plan)
    assert "CONFIG_ADMIN_INTERFACE_EXPOSURE" in config_rules(report)

    admin = [
        g
        for g in (report.analysis.findings if report.analysis else [])
        if g.data.rule.value == "CONFIG_ADMIN_INTERFACE_EXPOSURE"
    ]
    assert admin
    assert admin[0].data.severity is FindingSeverity.HIGH


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
    email = f"config-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Config Security Test",
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


def test_config_findings_reach_the_normal_pipeline(client, allow_loopback, vulnerable_target):
    scan_id = scan_the_fixture(client, vulnerable_target.base_url)

    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.category == FindingCategory.CONFIGURATION,
                )
            )
        )
    assert rows

    body = client.get(f"/api/scans/{scan_id}/findings").json()
    rules = {item["rule_id"] for item in body["items"]}
    assert any(rule.startswith("CONFIG_") for rule in rules), sorted(rules)


def test_no_fixture_secret_reaches_any_api_response(client, allow_loopback, vulnerable_target):
    """The invariant, checked at the outermost boundary a secret could cross."""
    scan_id = scan_the_fixture(client, vulnerable_target.base_url)

    for path in ("", "/findings", "/endpoints", "/api-endpoints", "/report", "/report/json"):
        text = client.get(f"/api/scans/{scan_id}{path}").text
        assert FIXTURE_DB_PASSWORD not in text, path
        assert FIXTURE_API_KEY not in text, path
        assert "fixture-branch" not in text, path
        assert FIXTURE_SOURCE not in text, path


def test_the_report_carries_configuration_coverage(client, allow_loopback, vulnerable_target):
    scan_id = scan_the_fixture(client, vulnerable_target.base_url)

    coverage = client.get(f"/api/scans/{scan_id}/report").json()["coverage"][
        "config_security"
    ]
    assert coverage["analyzed"] is True
    assert coverage["https_used"] is False
    assert coverage["sensitive_files_exposed"] >= 1
    assert coverage["requests_sent"] > 0
    assert "candidates_not_tested" in coverage
    assert coverage["coverage_complete"] is True


def test_the_counters_are_persisted_on_the_scan_row(client, allow_loopback, vulnerable_target):
    scan_id = scan_the_fixture(client, vulnerable_target.base_url)

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.config_analyzed is True
        assert scan.config_requests_sent and scan.config_requests_sent > 0
        assert scan.config_files_exposed and scan.config_files_exposed >= 1
        assert scan.config_findings and scan.config_findings > 0


def test_a_scan_that_never_ran_the_stage_reports_so(client):
    user_id = register(client)

    with SessionLocal() as db:
        scan = Scan(
            user_id=user_id, target_url="https://example.test/", status=ScanStatus.COMPLETED
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id

    coverage = client.get(f"/api/scans/{scan_id}/report").json()["coverage"][
        "config_security"
    ]
    assert coverage["analyzed"] is False
    assert coverage["findings_count"] == 0
    assert coverage["coverage_complete"] is False
