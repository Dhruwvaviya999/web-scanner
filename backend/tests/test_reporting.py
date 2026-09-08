"""Report generation: construction, determinism, authorization, leakage.

The builder is pure, so most cases are exercised by handing it rows directly.
The API cases drive the real app through TestClient.
"""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models.attack_surface import Endpoint, EndpointParameter, Form, FormField
from app.models.finding import Finding, FindingOccurrence
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.reporting.builder import build_report
from app.reporting.types import SEVERITY_RANK
from app.scanner.crawler.types import FormFieldKind, ParameterLocation
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
)

PASSWORD = "Sup3rSecret!pass"
PINNED = datetime(2026, 9, 8, 12, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# In-memory row factories (no database needed for builder tests)
# --------------------------------------------------------------------------- #


def make_scan(**overrides) -> Scan:
    scan = Scan(
        target_url="https://report.test/",
        status=ScanStatus.COMPLETED,
        http_status_code=200,
        is_https=True,
        final_url="https://report.test/",
        started_at=PINNED,
        completed_at=PINNED + timedelta(seconds=12, milliseconds=500),
        endpoints_discovered=5,
        endpoints_analyzed=4,
        endpoints_skipped=1,
        endpoints_failed=0,
        forms_discovered=2,
        parameters_discovered=3,
        pages_crawled=5,
        pages_skipped=1,
        max_depth_reached=2,
        crawl_limit_reached=False,
    )
    scan.id = overrides.pop("id", uuid.uuid4())
    for key, value in overrides.items():
        setattr(scan, key, value)
    return scan


def make_finding(
    rule_id: str,
    severity: FindingSeverity,
    category: FindingCategory = FindingCategory.SECURITY_HEADER,
    *,
    subject: str | None = None,
    endpoint_urls: tuple[str, ...] = (),
    evidence: str = "normalised evidence",
) -> Finding:
    finding = Finding(
        rule_id=rule_id,
        title=f"Title for {rule_id}",
        category=category,
        severity=severity,
        confidence=FindingConfidence.HIGH,
        description="description",
        evidence=evidence,
        impact="impact",
        remediation="remediation",
        subject=subject,
        occurrence_count=max(1, len(endpoint_urls)),
    )
    finding.endpoint = None
    finding.occurrences = [
        FindingOccurrence(endpoint_id=None, endpoint_url=url, evidence=evidence)
        for url in endpoint_urls
    ]
    return finding


def make_endpoint(url: str, path: str, params: tuple[str, ...] = ()) -> Endpoint:
    endpoint = Endpoint(url=url, path=path, method="GET", depth=0, status_code=200)
    endpoint.parameters = [
        EndpointParameter(name=name, location=ParameterLocation.QUERY) for name in params
    ]
    return endpoint


def make_form(action: str) -> Form:
    form = Form(page_url=action, action=action, method="POST")
    form.fields = [FormField(name="email", kind=FormFieldKind.INPUT, input_type="email")]
    return form


# --------------------------------------------------------------------------- #
# Report construction
# --------------------------------------------------------------------------- #


def test_zero_findings_report():
    report = build_report(make_scan(), [], [], [], generated_at=PINNED)

    assert report.has_findings is False
    assert report.severity.total == 0
    assert report.findings == ()
    assert report.categories == ()


def test_single_finding_report():
    finding = make_finding("SECURITY_HEADER_CSP_MISSING", FindingSeverity.MEDIUM)
    report = build_report(make_scan(), [finding], [], [], generated_at=PINNED)

    assert report.severity.total == 1
    assert report.severity.medium == 1
    assert report.findings[0].rule_id == "SECURITY_HEADER_CSP_MISSING"


def test_multiple_severities_are_counted():
    findings = [
        make_finding("A", FindingSeverity.HIGH),
        make_finding("B", FindingSeverity.MEDIUM),
        make_finding("C", FindingSeverity.LOW),
        make_finding("D", FindingSeverity.INFO),
        make_finding("E", FindingSeverity.HIGH),
    ]
    report = build_report(make_scan(), findings, [], [], generated_at=PINNED)

    assert report.severity.total == 5
    assert report.severity.high == 2
    assert report.severity.critical == 0


def test_multiple_categories_are_grouped():
    findings = [
        make_finding("H1", FindingSeverity.MEDIUM, FindingCategory.SECURITY_HEADER),
        make_finding("C1", FindingSeverity.LOW, FindingCategory.COOKIE),
        make_finding("X1", FindingSeverity.HIGH, FindingCategory.XSS),
        make_finding("H2", FindingSeverity.LOW, FindingCategory.SECURITY_HEADER),
    ]
    report = build_report(make_scan(), findings, [], [], generated_at=PINNED)

    groups = {g.category: g for g in report.categories}
    assert groups[FindingCategory.SECURITY_HEADER].total == 2
    assert groups[FindingCategory.XSS].severity.high == 1
    # Ordered by the category enum's declaration order.
    assert [g.category for g in report.categories] == [
        FindingCategory.SECURITY_HEADER,
        FindingCategory.COOKIE,
        FindingCategory.XSS,
    ]


def test_multiple_occurrences_are_flattened_and_deduplicated():
    finding = make_finding(
        "SECURITY_HEADER_CSP_MISSING",
        FindingSeverity.MEDIUM,
        endpoint_urls=("https://report.test/b", "https://report.test/a", "https://report.test/a"),
    )
    report = build_report(make_scan(), [finding], [], [], generated_at=PINNED)

    urls = [e.url for e in report.findings[0].endpoints]
    assert urls == ["https://report.test/a", "https://report.test/b"]  # sorted, unique


def test_attack_surface_counts_distinct_parameter_names():
    endpoints = [
        make_endpoint("https://report.test/a?q", "/a", ("q",)),
        make_endpoint("https://report.test/b?q&page", "/b", ("q", "page")),
    ]
    report = build_report(make_scan(), [], endpoints, [make_form("https://report.test/login")],
                          generated_at=PINNED)

    assert report.attack_surface.endpoints == 2
    assert report.attack_surface.forms == 1
    assert report.attack_surface.parameters == 2  # q counted once
    assert report.parameter_names == ("page", "q")


def test_metadata_duration_and_status():
    report = build_report(make_scan(), [], [], [], generated_at=PINNED)

    assert report.metadata.status == "COMPLETED"
    assert report.metadata.duration_seconds == 12.5
    assert report.metadata.generated_at == PINNED


def test_running_scan_has_no_duration():
    scan = make_scan(status=ScanStatus.RUNNING, completed_at=None)
    report = build_report(scan, [], [], [], generated_at=PINNED)

    assert report.metadata.status == "RUNNING"
    assert report.metadata.duration_seconds is None


def test_failed_scan_carries_its_error():
    scan = make_scan(status=ScanStatus.FAILED, error_message="Could not resolve host.")
    report = build_report(scan, [], [], [], generated_at=PINNED)

    assert report.metadata.status == "FAILED"
    assert report.metadata.error_message == "Could not resolve host."


# --------------------------------------------------------------------------- #
# Coverage
# --------------------------------------------------------------------------- #


def test_complete_coverage():
    scan = make_scan(endpoints_discovered=5, endpoints_analyzed=4,
                     endpoints_skipped=1, endpoints_failed=0)
    assert build_report(scan, [], [], [], generated_at=PINNED).coverage.is_complete is True


def test_failed_endpoints_make_coverage_incomplete():
    """A clean result must not read as reassuring when analysis failed."""
    scan = make_scan(endpoints_discovered=5, endpoints_analyzed=4,
                     endpoints_skipped=0, endpoints_failed=1)
    assert build_report(scan, [], [], [], generated_at=PINNED).coverage.is_complete is False


def test_unanalyzed_endpoints_make_coverage_incomplete():
    scan = make_scan(endpoints_discovered=10, endpoints_analyzed=4,
                     endpoints_skipped=1, endpoints_failed=0)
    assert build_report(scan, [], [], [], generated_at=PINNED).coverage.is_complete is False


def test_scan_without_a_crawl_is_not_complete():
    """NULL counters mean the stage never ran, which is not 'complete'."""
    scan = make_scan(endpoints_discovered=None, endpoints_analyzed=None)
    report = build_report(scan, [], [], [], generated_at=PINNED)

    assert report.coverage.is_complete is False
    assert report.coverage.endpoints_discovered is None


def test_skipped_endpoints_are_reported():
    scan = make_scan(endpoints_skipped=3)
    assert build_report(scan, [], [], [], generated_at=PINNED).coverage.endpoints_skipped == 3


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def test_findings_are_ordered_severity_then_category_then_rule_then_subject():
    findings = [
        make_finding("Z_RULE", FindingSeverity.LOW, FindingCategory.COOKIE),
        make_finding("A_RULE", FindingSeverity.CRITICAL, FindingCategory.XSS),
        make_finding("M_RULE", FindingSeverity.LOW, FindingCategory.COOKIE, subject="b"),
        make_finding("M_RULE", FindingSeverity.LOW, FindingCategory.COOKIE, subject="a"),
        make_finding("B_RULE", FindingSeverity.HIGH, FindingCategory.SQLI),
    ]
    report = build_report(make_scan(), findings, [], [], generated_at=PINNED)

    keys = [(f.severity, f.rule_id, f.subject) for f in report.findings]
    assert keys[0][0] is FindingSeverity.CRITICAL
    assert keys[1][0] is FindingSeverity.HIGH
    # Same severity + category + rule -> subject breaks the tie.
    assert [k[2] for k in keys if k[1] == "M_RULE"] == ["a", "b"]
    # Severity is non-decreasing in rank across the whole list.
    ranks = [SEVERITY_RANK[f.severity] for f in report.findings]
    assert ranks == sorted(ranks)


def test_same_rows_produce_an_identical_report_regardless_of_input_order():
    a = make_finding("A", FindingSeverity.HIGH, FindingCategory.XSS)
    b = make_finding("B", FindingSeverity.LOW, FindingCategory.COOKIE)
    c = make_finding("C", FindingSeverity.MEDIUM, FindingCategory.SQLI)

    first = build_report(make_scan(id=uuid.UUID(int=1)), [a, b, c], [], [], generated_at=PINNED)
    second = build_report(make_scan(id=uuid.UUID(int=1)), [c, a, b], [], [], generated_at=PINNED)

    assert [f.rule_id for f in first.findings] == [f.rule_id for f in second.findings]
    assert first == second


# --------------------------------------------------------------------------- #
# API: authorization and behaviour
# --------------------------------------------------------------------------- #


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def register(client: TestClient) -> TestClient:
    email = f"report-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={"name": "Report Test", "email": email,
              "password": PASSWORD, "confirm_password": PASSWORD},
    )
    assert response.status_code == 201, response.text
    return client


def user_id_for(client: TestClient) -> uuid.UUID:
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


SECRET_COOKIE = "s3ss10n-c00k13-value"
SECRET_TOKEN = "Bearer eyJhbGciOi-secret"


def persist_scan(user_id: uuid.UUID, *, status=ScanStatus.COMPLETED, with_findings=True) -> uuid.UUID:
    with SessionLocal() as db:
        scan = Scan(
            user_id=user_id, target_url="https://report.test/", status=status,
            http_status_code=200, is_https=True, final_url="https://report.test/",
            started_at=PINNED, completed_at=PINNED + timedelta(seconds=5),
            endpoints_discovered=2, endpoints_analyzed=2, endpoints_skipped=0,
            endpoints_failed=0, forms_discovered=1, parameters_discovered=1,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        endpoint = Endpoint(scan_id=scan.id, url="https://report.test/search?q",
                            path="/search", method="GET", depth=0, status_code=200)
        endpoint.parameters = [EndpointParameter(name="q", location=ParameterLocation.QUERY)]
        db.add(endpoint)

        form = Form(scan_id=scan.id, page_url="https://report.test/login",
                    action="https://report.test/login", method="POST")
        db.add(form)
        db.flush()

        if with_findings:
            finding = Finding(
                scan_id=scan.id, rule_id="SECURITY_HEADER_CSP_MISSING",
                title="Content-Security-Policy header not set",
                category=FindingCategory.SECURITY_HEADER,
                severity=FindingSeverity.MEDIUM, confidence=FindingConfidence.HIGH,
                description="d", evidence="No CSP header was present.",
                impact="i", remediation="r", endpoint_id=endpoint.id, occurrence_count=1,
            )
            finding.occurrences = [
                FindingOccurrence(endpoint_id=endpoint.id,
                                  endpoint_url="https://report.test/search?q",
                                  evidence="No CSP header was present.")
            ]
            db.add(finding)

        db.commit()
        return scan.id


def test_owner_can_read_the_report(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner))

    response = owner.get(f"/api/scans/{scan_id}/report")
    assert response.status_code == 200

    body = response.json()
    assert body["metadata"]["scan_id"] == str(scan_id)
    assert body["metadata"]["status"] == "COMPLETED"
    assert body["severity"]["total"] == 1
    assert body["attack_surface"]["endpoints"] == 1
    assert body["parameter_names"] == ["q"]
    assert body["findings"][0]["rule_id"] == "SECURITY_HEADER_CSP_MISSING"


def test_anonymous_access_is_rejected(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner))

    with TestClient(app) as anonymous:
        assert anonymous.get(f"/api/scans/{scan_id}/report").status_code == 401
        assert anonymous.get(f"/api/scans/{scan_id}/report/json").status_code == 401


def test_another_user_gets_404_not_403(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner))

    with TestClient(app) as intruder:
        register(intruder)
        response = intruder.get(f"/api/scans/{scan_id}/report")

    assert response.status_code == 404
    # The body must not confirm the scan exists.
    assert str(scan_id) not in response.text


def test_unknown_scan_id_returns_404(client):
    owner = register(client)
    assert owner.get(f"/api/scans/{uuid.uuid4()}/report").status_code == 404


def test_zero_finding_report_over_the_api(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner), with_findings=False)

    body = owner.get(f"/api/scans/{scan_id}/report").json()
    assert body["findings"] == []
    assert body["severity"]["total"] == 0
    # Coverage is still reported, so a clean result can be judged in context.
    assert body["coverage"]["is_complete"] is True


def test_failed_scan_report(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner), status=ScanStatus.FAILED, with_findings=False)

    body = owner.get(f"/api/scans/{scan_id}/report").json()
    assert body["metadata"]["status"] == "FAILED"


def test_running_scan_report(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner), status=ScanStatus.RUNNING, with_findings=False)

    body = owner.get(f"/api/scans/{scan_id}/report").json()
    assert body["metadata"]["status"] == "RUNNING"


def test_json_download_has_attachment_headers(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner))

    response = owner.get(f"/api/scans/{scan_id}/report/json")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "attachment" in response.headers["content-disposition"]
    assert str(scan_id) in response.headers["content-disposition"]


def test_download_matches_the_report_endpoint(client):
    """The two endpoints must never drift apart."""
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner))

    inline = owner.get(f"/api/scans/{scan_id}/report").json()
    downloaded = json.loads(owner.get(f"/api/scans/{scan_id}/report/json").text)

    inline["metadata"].pop("generated_at")
    downloaded["metadata"].pop("generated_at")
    assert inline == downloaded


def test_repeated_requests_are_deterministic(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner))

    first = owner.get(f"/api/scans/{scan_id}/report").json()
    second = owner.get(f"/api/scans/{scan_id}/report").json()

    first["metadata"].pop("generated_at")
    second["metadata"].pop("generated_at")
    assert first == second


# --------------------------------------------------------------------------- #
# Secret leakage
# --------------------------------------------------------------------------- #


def test_report_schema_has_no_field_for_secret_material():
    """Structural: there is nowhere in the wire shape to put a secret."""
    from app.schemas.report import ReportFindingRead, ScanReportRead

    forbidden = {"cookie", "cookies", "authorization", "token", "password",
                 "credentials", "request_body", "payload", "probe_value", "headers"}
    for model in (ScanReportRead, ReportFindingRead):
        assert not (set(model.model_fields) & forbidden), model.__name__


def test_report_body_contains_no_secret_material(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner))

    body = owner.get(f"/api/scans/{scan_id}/report").text
    for secret in (SECRET_COOKIE, SECRET_TOKEN, PASSWORD, "Set-Cookie", "Authorization"):
        assert secret not in body, secret


def test_report_carries_no_probe_or_payload_syntax(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner))

    body = owner.get(f"/api/scans/{scan_id}/report").text
    for marker in ("1=1", "1=2", "' OR ", "<script", "javascript:", "SELECT * FROM"):
        assert marker not in body, marker


def test_endpoint_urls_in_a_report_carry_no_query_values(client):
    owner = register(client)
    scan_id = persist_scan(user_id_for(owner))

    body = owner.get(f"/api/scans/{scan_id}/report").json()
    for finding in body["findings"]:
        for endpoint in finding["endpoints"]:
            query = endpoint["url"].partition("?")[2]
            assert "=" not in query, endpoint["url"]


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    with SessionLocal() as db:
        db.query(User).filter(User.email.like("report-%@example.com")).delete(
            synchronize_session=False
        )
        db.commit()
