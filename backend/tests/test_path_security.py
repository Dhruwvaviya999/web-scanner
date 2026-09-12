"""Path traversal and local file inclusion.

Phase 17 sends real requests, so the tests carry two burdens beyond "does it
find the bug".

**Safety.** Every probe must aim at the controlled canary and nothing else —
there is a test that renders the entire payload set and asserts no real
system-file token appears in any of it, and another that records every request
the fixture receives and asserts every one was a GET. The proof of a finding is
that a *harmless marker* came back, never that a sensitive file was read.

**Restraint.** A reflected payload is not retrieval, a generic 404 is not
retrieval, and a status change is not retrieval. The secure, echo and missing
fixtures exist to prove the detector stays silent on all three, and the analyzer
tests pin the verdict boundary directly.

Every canary in the fixtures is a marker string with no secret in it, and
several tests assert the marker never reaches a finding, a report or the API.
"""

from __future__ import annotations

import secrets
import socket
import threading
import time
import uuid
from urllib.parse import unquote

import pytest
import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from app.core.database import SessionLocal
from app.main import app as api_app
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner import ScannerConfig, WebScanner
from app.scanner.api.types import ApiDiscoveryConfig
from app.scanner.auth import AuthMode
from app.scanner.auth.context import build_context
from app.scanner.config_security.types import ConfigSecurityConfig
from app.scanner.crawler.types import CrawlConfig
from app.scanner.path_security.analyzer import (
    BaselineEvidence,
    ProbeEvidence,
    analyze,
    baseline_is_usable,
)
from app.scanner.path_security.parameter_classifier import classify, classify_name
from app.scanner.path_security.payloads import (
    CANARY_MARKER,
    CANARY_SUFFIX,
    TRAVERSAL_PROBES,
    is_safe_probe,
    traversal_probes,
)
from app.scanner.path_security.types import (
    ParameterClass,
    PathSecurityConfig,
    PathSecurityLimits,
    TraversalVerdict,
)
from app.scanner.security.types import FindingCategory, FindingSeverity
from app.services import scan_service

PASSWORD = "Sup3rSecret!pass"
FIXTURE_TOKEN = "fixture-bearer-" + "a" * 24

#: The harmless marker the fixture places outside the intended directory. Tests
#: assert it never reaches a finding, a report or an API response.
CANARY_BODY = f"{CANARY_MARKER}\nHarmless fixture canary. No secret here.\n"


# --------------------------------------------------------------------------- #
# Parameter classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name,expected",
    [
        ("file", ParameterClass.LIKELY_FILE_PARAMETER),
        ("filename", ParameterClass.LIKELY_FILE_PARAMETER),
        ("filepath", ParameterClass.LIKELY_FILE_PARAMETER),
        ("file_path", ParameterClass.LIKELY_FILE_PARAMETER),
        ("path", ParameterClass.LIKELY_FILE_PARAMETER),
        ("template", ParameterClass.LIKELY_FILE_PARAMETER),
        ("document", ParameterClass.LIKELY_FILE_PARAMETER),
        ("include", ParameterClass.LIKELY_FILE_PARAMETER),
        ("download", ParameterClass.LIKELY_FILE_PARAMETER),
        ("page", ParameterClass.POSSIBLE_FILE_PARAMETER),
        ("src", ParameterClass.POSSIBLE_FILE_PARAMETER),
        ("image", ParameterClass.POSSIBLE_FILE_PARAMETER),
        ("id", ParameterClass.NOT_FILE_PARAMETER),
        ("user_id", ParameterClass.NOT_FILE_PARAMETER),
        ("q", ParameterClass.NOT_FILE_PARAMETER),
        ("search", ParameterClass.NOT_FILE_PARAMETER),
        ("page_size", ParameterClass.NOT_FILE_PARAMETER),
        ("token", ParameterClass.NOT_FILE_PARAMETER),
    ],
)
def test_parameter_classification_is_conservative(name, expected):
    assert classify_name(name)[0] is expected


def test_only_file_like_classes_are_eligible():
    assert classify_name("file")[0].eligible is True
    assert classify_name("page")[0].eligible is True
    assert classify_name("id")[0].eligible is False
    assert ParameterClass.UNKNOWN.eligible is False


def test_an_excluded_name_is_never_lifted_by_context():
    """`id` on a download endpoint returning a PDF is still not a file param."""
    assessment = classify("id", endpoint="/download", content_type="application/pdf")
    assert assessment.classification is ParameterClass.NOT_FILE_PARAMETER


def test_context_promotes_a_borderline_name():
    plain = classify("page", endpoint="/blog")
    assert plain.classification is ParameterClass.POSSIBLE_FILE_PARAMETER

    promoted = classify("page", endpoint="/view", content_type="text/plain")
    assert promoted.classification is ParameterClass.LIKELY_FILE_PARAMETER
    assert "promoted:context" in promoted.signals


def test_a_file_suffix_name_is_recognised():
    assert classify_name("report_file")[0] is ParameterClass.LIKELY_FILE_PARAMETER
    assert classify_name("doc_path")[0] is ParameterClass.LIKELY_FILE_PARAMETER


# --------------------------------------------------------------------------- #
# Payload generation
# --------------------------------------------------------------------------- #


def test_payload_set_is_bounded():
    assert len(TRAVERSAL_PROBES) <= 8
    assert len(traversal_probes(limit=3)) == 3
    assert len(traversal_probes(limit=100)) == len(TRAVERSAL_PROBES)


def test_payload_generation_is_deterministic():
    first = [p.render() for p in traversal_probes()]
    second = [p.render() for p in traversal_probes()]
    assert first == second


def test_every_payload_aims_at_the_canary_and_no_system_file():
    for probe in TRAVERSAL_PROBES:
        value = probe.render()
        assert is_safe_probe(value), value
        assert "scanner-canary" in value.lower() or "traversal-marker" in value.lower()


def test_no_payload_targets_a_real_sensitive_file():
    forbidden = (
        "etc/passwd",
        "etc/shadow",
        ".ssh",
        "id_rsa",
        "system32",
        "sam",
        "win.ini",
        ".env",
        ".aws",
        "metadata",
        "proc/self",
    )
    for probe in TRAVERSAL_PROBES:
        lowered = probe.render().lower()
        assert not any(token in lowered for token in forbidden), probe.label


def test_no_payload_is_a_url_or_command():
    for probe in TRAVERSAL_PROBES:
        value = probe.render()
        assert "://" not in value
        assert not value.startswith(("http", "//", "ftp"))
        for shell in (";", "|", "`", "$(", "&&"):
            assert shell not in value, probe.label


def test_labels_carry_no_file_content():
    for probe in TRAVERSAL_PROBES:
        assert CANARY_MARKER not in probe.label


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #


def _baseline(status=200, media="application/pdf", canary=False):
    return BaselineEvidence(
        usable=baseline_is_usable(status),
        status=status,
        media_type=media,
        canary_present=canary,
    )


def _probe(status=200, media="text/plain", canary=False, similarity=1.0, reflected=False):
    return ProbeEvidence(
        status=status,
        media_type=media,
        canary_present=canary,
        body_similarity=similarity,
        reflected=reflected,
    )


def test_reproduced_canary_is_strong():
    result = analyze(_baseline(), (_probe(canary=True), _probe(canary=True)))
    assert result.verdict is TraversalVerdict.STRONG
    assert result.canary_matched and result.reproduced


def test_single_canary_is_possible_not_strong():
    result = analyze(_baseline(), (_probe(canary=True),))
    assert result.verdict is TraversalVerdict.POSSIBLE
    assert result.canary_matched and not result.reproduced


def test_reflection_only_is_none():
    result = analyze(_baseline(), (_probe(reflected=True, similarity=0.3),))
    assert result.verdict is TraversalVerdict.NONE


def test_generic_404_is_none():
    result = analyze(_baseline(), (_probe(status=404, media="text/html", similarity=0.9),))
    assert result.verdict is TraversalVerdict.NONE


def test_status_change_alone_is_not_a_finding():
    result = analyze(
        _baseline(media="text/html"),
        (_probe(status=500, media="text/html", similarity=0.9),),
    )
    assert result.verdict is TraversalVerdict.NONE


def test_body_size_change_alone_same_media_is_none():
    result = analyze(
        _baseline(media="text/html"),
        (_probe(status=200, media="text/html", similarity=0.96),),
    )
    assert result.verdict is TraversalVerdict.NONE


def test_media_type_change_is_possible():
    result = analyze(
        _baseline(media="application/pdf"),
        (_probe(status=200, media="text/plain", similarity=0.9),),
    )
    assert result.verdict is TraversalVerdict.POSSIBLE


def test_baseline_already_containing_canary_is_unknown():
    result = analyze(_baseline(canary=True), (_probe(canary=True), _probe(canary=True)))
    assert result.verdict is TraversalVerdict.UNKNOWN


def test_unusable_baseline_is_unknown():
    result = analyze(BaselineEvidence(usable=False), (_probe(canary=True),))
    assert result.verdict is TraversalVerdict.UNKNOWN


def test_no_probes_is_none():
    assert analyze(_baseline(), ()).verdict is TraversalVerdict.NONE


# --------------------------------------------------------------------------- #
# Fixture
# --------------------------------------------------------------------------- #


def _decode_twice(value: str) -> str:
    """Two decode passes, so a doubly-encoded traversal collapses like a naive
    server's would. Fixture-only — models a vulnerable resolver."""
    current = value
    for _ in range(2):
        nxt = unquote(current)
        if nxt == current:
            break
        current = nxt
    return current


def _reached_canary(raw: str) -> bool:
    """Whether a vulnerable resolver would land on the canary for this input."""
    collapsed = _decode_twice(raw).replace("\\", "/").replace("....//", "../")
    return "scanner-canary/traversal-marker" in collapsed


def _has_parent(raw: str) -> bool:
    return ".." in _decode_twice(raw).replace("\\", "/")


def build_fixture_app() -> FastAPI:
    """A localhost-only fixture with secure and deliberately vulnerable routes.

    Every "file" is simulated in-memory. No real filesystem path is ever opened,
    so the fixture cannot expose a real system file even by mistake.
    """
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.received = []

    @app.middleware("http")
    async def record(request: Request, call_next):
        app.state.received.append({"method": request.method, "path": request.url.path})
        return await call_next(request)

    @app.get("/")
    def index() -> HTMLResponse:
        # Links carry query parameters so the crawler discovers them by name.
        return HTMLResponse(
            "<!doctype html><html><head><title>Files</title></head><body>"
            '<a href="/download?file=readme.txt">secure</a>'
            '<a href="/download-vulnerable?file=readme.txt">vuln</a>'
            '<a href="/include?template=main.html">include</a>'
            '<a href="/echo?file=readme.txt">echo</a>'
            '<a href="/missing?file=readme.txt">missing</a>'
            '<a href="/catalogue?id=7">catalogue</a>'
            '<a href="/private-download?file=readme.txt">private</a>'
            "</body></html>"
        )

    @app.get("/download")
    def secure_download(file: str = "readme.txt") -> PlainTextResponse:
        # Secure: reject traversal and any attempt to name the canary directly.
        decoded = _decode_twice(file).replace("\\", "/")
        if ".." in decoded or "scanner-canary" in decoded:
            return PlainTextResponse("invalid path", status_code=400)
        if file == "readme.txt":
            return PlainTextResponse("Public readme. Nothing sensitive.")
        return PlainTextResponse("not found", status_code=404)

    @app.get("/download-vulnerable")
    def vulnerable_download(file: str = "readme.txt") -> PlainTextResponse:
        if _reached_canary(file):
            return PlainTextResponse(CANARY_BODY)
        if file == "readme.txt":
            return PlainTextResponse("Public readme. Nothing sensitive.")
        if _has_parent(file):
            return PlainTextResponse("escaped, but not to the canary")
        return PlainTextResponse("not found", status_code=404)

    @app.get("/include")
    def vulnerable_include(template: str = "main.html") -> HTMLResponse:
        # Models an include endpoint that renders whatever template name it is
        # given (or a default) with a 200 — so a normal name gives a usable
        # baseline — and resolves a traversal straight to the canary.
        if _reached_canary(template):
            return HTMLResponse(f"<html><body>{CANARY_BODY}</body></html>")
        return HTMLResponse("<html><body>Rendered template.</body></html>")

    @app.get("/echo")
    def echo(file: str = "readme.txt") -> HTMLResponse:
        # Reflection only: the input is echoed, never resolved to a file.
        return HTMLResponse(f"<html><body>You requested: {file}</body></html>")

    @app.get("/missing")
    def missing(file: str = "readme.txt") -> PlainTextResponse:
        return PlainTextResponse("File not found", status_code=404)

    @app.get("/catalogue")
    def catalogue(id: str = "1") -> JSONResponse:
        # An ordinary non-file parameter. Must never be probed.
        return JSONResponse({"id": id, "name": "Widget"})

    @app.get("/private-download")
    def private_download(
        file: str = "readme.txt", authorization: str | None = Header(default=None)
    ) -> PlainTextResponse:
        if authorization != f"Bearer {FIXTURE_TOKEN}":
            return PlainTextResponse("unauthorized", status_code=401)
        if _reached_canary(file):
            return PlainTextResponse(CANARY_BODY)
        if file == "readme.txt":
            return PlainTextResponse("Private readme for the signed-in user.")
        return PlainTextResponse("not found", status_code=404)

    return app


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
    def received(self) -> list:
        return self.app.state.received

    def start(self) -> None:
        self._thread.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("the fixture did not start")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


@pytest.fixture(scope="module")
def target():
    server = _Server(build_fixture_app())
    server.start()
    try:
        yield server
    finally:
        server.stop()


def run_scan(base_url: str, *, authentication=None, **overrides):
    return WebScanner(
        ScannerConfig(
            timeout_seconds=5.0, total_timeout_seconds=120.0, allow_private_networks=True
        ),
        crawl_config=CrawlConfig(max_pages=20, max_depth=3, time_budget_seconds=30),
        detectors=[],
        api_config=ApiDiscoveryConfig(fetch_documents=False),
        config_security=ConfigSecurityConfig(enabled=False),
        authentication=authentication,
        path_security=PathSecurityConfig(**overrides),
    ).scan_sync(base_url)


def path_rules(report) -> set[str]:
    if report.analysis is None:
        return set()
    return {
        group.data.rule.value
        for group in report.analysis.findings
        if group.data.category is FindingCategory.INPUT_VALIDATION
    }


def _observation(report, parameter):
    result = report.path_security
    assert result is not None
    for obs in result.observations:
        if obs.parameter == parameter:
            return obs
    return None


# --------------------------------------------------------------------------- #
# End to end — detection
# --------------------------------------------------------------------------- #


def test_vulnerable_download_is_reported(target):
    report = run_scan(target.base_url)
    assert "PATH_TRAVERSAL" in path_rules(report)

    finding = next(
        g.data
        for g in report.analysis.findings
        if g.data.rule.value == "PATH_TRAVERSAL"
    )
    assert finding.severity is FindingSeverity.HIGH
    assert finding.subject == "parameter:file"


def test_vulnerable_include_is_reported_as_lfi(target):
    report = run_scan(target.base_url)
    assert "LOCAL_FILE_INCLUSION" in path_rules(report)


def test_secure_download_is_clean(target):
    """The finding names the parameter, and the secure route never appears."""
    report = run_scan(target.base_url)
    for group in report.analysis.findings:
        if group.data.category is FindingCategory.INPUT_VALIDATION:
            # Every confirmed finding must come from a vulnerable endpoint.
            occ_urls = " ".join(o.endpoint_url or "" for o in group.occurrences)
            assert "/download?" not in occ_urls and "/download " not in occ_urls
            assert "/echo" not in occ_urls
            assert "/missing" not in occ_urls


def test_echo_reflection_is_not_a_finding(target):
    report = run_scan(target.base_url)
    obs = None
    for o in report.path_security.observations:
        if "/echo" in o.endpoint:
            obs = o
            break
    assert obs is not None
    assert obs.verdict is not TraversalVerdict.STRONG
    assert not obs.canary_matched


def test_missing_endpoint_yields_no_finding(target):
    report = run_scan(target.base_url)
    for o in report.path_security.observations:
        if "/missing" in o.endpoint:
            # Baseline is a 404, so the parameter is skipped, never confirmed.
            assert o.verdict is not TraversalVerdict.STRONG


def test_ordinary_id_parameter_is_never_probed(target):
    report = run_scan(target.base_url)
    result = report.path_security
    # /catalogue?id= must not appear among tested parameters.
    for o in result.observations:
        assert not (o.endpoint.endswith("/catalogue") and o.parameter == "id")


def test_reproduction_is_recorded_for_a_strong_finding(target):
    report = run_scan(target.base_url)
    obs = _observation(report, "file")
    assert obs is not None
    assert obs.verdict is TraversalVerdict.STRONG
    assert obs.reproduced is True


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


def test_private_traversal_needs_the_authenticated_context(target):
    # Anonymous: the private endpoint 401s, so its baseline is unusable and it
    # is never confirmed.
    anon = run_scan(target.base_url)
    for o in anon.path_security.observations:
        if "/private-download" in o.endpoint:
            assert o.verdict is not TraversalVerdict.STRONG


def test_private_traversal_is_found_with_authentication(target):
    context = build_context(AuthMode.BEARER_TOKEN, target.base_url, token=FIXTURE_TOKEN)
    report = run_scan(target.base_url, authentication=context)

    private = [
        o
        for o in report.path_security.observations
        if "/private-download" in o.endpoint
    ]
    assert private
    assert any(o.verdict is TraversalVerdict.STRONG for o in private)
    strong = next(o for o in private if o.verdict is TraversalVerdict.STRONG)
    assert strong.authenticated is True
    assert strong.context_label == AuthMode.BEARER_TOKEN.value


# --------------------------------------------------------------------------- #
# Budget, cancellation, coverage
# --------------------------------------------------------------------------- #


def test_probe_budget_fails_closed(target):
    report = run_scan(
        target.base_url,
        limits=PathSecurityLimits(max_probes_per_scan=2),
    )
    result = report.path_security
    assert result is not None
    assert result.stats.requests_sent <= 2
    assert result.stats.budget_exhausted is True


def test_stage_can_be_disabled(target):
    report = run_scan(target.base_url, enabled=False)
    result = report.path_security
    assert result is not None
    assert result.observations == ()
    assert path_rules(report) == set()


def test_cancellation_stops_the_stage_before_any_probe():
    from app.scanner.cancellation import CancellationToken, ScanCancelled
    from app.scanner.crawler.types import CrawlResult, DiscoveredEndpoint
    from app.scanner.analysis.types import AnalysisResult
    from app.scanner.path_security.module import PathSecurityModule
    from app.scanner.types import RawHttpResponse, ScanReport
    from app.scanner.url_validator import parse_target_url

    base = "http://127.0.0.1:9/"
    report = ScanReport(target=parse_target_url(base))
    report.raw = RawHttpResponse(
        status_code=200, headers={}, final_url=base, is_https=False,
        redirect_count=0, elapsed_ms=1,
    )
    crawl = CrawlResult()
    crawl.endpoints.append(
        DiscoveredEndpoint(
            url=f"{base}download-vulnerable", path="/download-vulnerable",
            method="GET", depth=1, parameters=("file",),
        )
    )
    report.crawl = crawl
    report.analysis = AnalysisResult()

    token = CancellationToken(lambda: True)  # cancelled from the outset
    module = PathSecurityModule(
        ScannerConfig(allow_private_networks=True), PathSecurityConfig(),
        cancellation=token,
    )

    import asyncio

    with pytest.raises(ScanCancelled):
        asyncio.run(module.run(report.target, report))
    assert report.path_security.stats.requests_sent == 0


def test_coverage_counts_considered_and_tested(target):
    report = run_scan(target.base_url)
    result = report.path_security
    assert result is not None
    assert result.stats.parameters_considered > 0
    assert result.stats.file_parameters > 0
    assert result.stats.parameters_tested > 0
    assert result.stats.canary_matches >= 1


# --------------------------------------------------------------------------- #
# Security — traffic stays safe and in scope
# --------------------------------------------------------------------------- #


def test_only_get_requests_ever_reach_the_target(target):
    before = len(target.received)
    run_scan(target.base_url)
    methods = {e["method"] for e in target.received[before:]}
    assert methods <= {"GET"}, methods
    assert not methods & {"POST", "PUT", "PATCH", "DELETE", "TRACE"}


def test_no_request_targets_a_real_system_path(target):
    before = len(target.received)
    run_scan(target.base_url)
    for entry in target.received[before:]:
        lowered = entry["path"].lower()
        for token in ("etc/passwd", "etc/shadow", ".ssh", "system32", "win.ini", ".env"):
            assert token not in lowered, entry["path"]


# --------------------------------------------------------------------------- #
# Privacy — nothing sensitive is persisted
# --------------------------------------------------------------------------- #


def test_no_canary_content_reaches_a_finding(target):
    report = run_scan(target.base_url)
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
        assert CANARY_MARKER not in blob
        assert "Harmless fixture canary" not in blob


def test_no_probe_payload_is_stored_in_a_finding(target):
    report = run_scan(target.base_url)
    for group in report.analysis.findings:
        blob = group.data.description + group.data.evidence
        # The literal traversal payload must not be echoed into evidence.
        assert "../" not in blob
        assert "%2e%2e%2f" not in blob
        assert "scanner-canary/traversal-marker" not in blob


def test_observations_hold_no_body_or_payload(target):
    report = run_scan(target.base_url)
    for obs in report.path_security.observations:
        assert CANARY_MARKER not in repr(obs)
        assert "../" not in repr(obs)


# --------------------------------------------------------------------------- #
# Persistence and the API
# --------------------------------------------------------------------------- #


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    with TestClient(api_app) as test_client:
        yield test_client


@pytest.fixture
def allow_loopback(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "SCANNER_ALLOW_PRIVATE_NETWORKS", True)
    yield


def register(client) -> uuid.UUID:
    email = f"path-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Path Security Test",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


def scan_the_fixture(client, base_url: str) -> uuid.UUID:
    user_id = register(client)
    with SessionLocal() as db:
        scan_id = scan_service.enqueue_scan(db, db.get(User, user_id), base_url)
    scan_service.execute_scan(scan_id)
    return scan_id


def test_findings_reach_the_normal_pipeline(client, allow_loopback, target):
    from sqlalchemy import select

    scan_id = scan_the_fixture(client, target.base_url)
    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.category == FindingCategory.INPUT_VALIDATION,
                )
            )
        )
    assert rows
    body = client.get(f"/api/scans/{scan_id}/findings").json()
    rules = {item["rule_id"] for item in body["items"]}
    assert "PATH_TRAVERSAL" in rules or "LOCAL_FILE_INCLUSION" in rules


def test_no_canary_reaches_any_api_response(client, allow_loopback, target):
    scan_id = scan_the_fixture(client, target.base_url)
    for path in ("", "/findings", "/endpoints", "/report", "/report/json"):
        text = client.get(f"/api/scans/{scan_id}{path}").text
        assert CANARY_MARKER not in text, path
        assert "Harmless fixture canary" not in text, path


def test_report_carries_path_coverage(client, allow_loopback, target):
    scan_id = scan_the_fixture(client, target.base_url)
    coverage = client.get(f"/api/scans/{scan_id}/report").json()["coverage"][
        "path_security"
    ]
    assert coverage["analyzed"] is True
    assert coverage["file_parameters"] >= 1
    assert coverage["canary_matches"] >= 1
    assert coverage["findings_count"] >= 1
    assert "coverage_complete" in coverage


def test_counters_are_persisted_on_the_scan_row(client, allow_loopback, target):
    scan_id = scan_the_fixture(client, target.base_url)
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.path_analyzed is True
        assert scan.path_file_parameters and scan.path_file_parameters >= 1
        assert scan.path_findings and scan.path_findings >= 1


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
        "path_security"
    ]
    assert coverage["analyzed"] is False
    assert coverage["findings_count"] == 0
    assert coverage["coverage_complete"] is False
