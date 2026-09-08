"""XSS findings inside the existing finding architecture.

Confirms there is no separate XSS result path: these findings deduplicate,
associate with endpoints and reach the API exactly like every other finding.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner.analysis.aggregator import aggregate_findings
from app.scanner.analysis.types import AggregatedFinding, FindingOccurrence as OccurrenceData
from app.scanner.crawler.types import CrawlResult, DiscoveredEndpoint
from app.scanner.security.types import FindingCategory, FindingRule
from app.scanner.vulnerabilities.xss.analyzer import analyze_reflection
from app.scanner.vulnerabilities.xss.findings import build_finding
from app.scanner.vulnerabilities.xss.payloads import CANARY
from app.scanner.vulnerabilities.xss.types import XssProbe
from app.services import attack_surface_service, finding_service

PASSWORD = "Sup3rSecret!pass"
SEARCH = "https://xss.test/search?q"
FILTER = "https://xss.test/filter?category"

PROBE = XssProbe(token="wscafebabe0011", canary=CANARY)
RAW = PROBE.value


def xss_finding(parameter: str):
    analysis = analyze_reflection(f"<div>{RAW}</div>", PROBE.open_marker, PROBE.close_marker, CANARY)
    finding = build_finding(parameter, analysis)
    assert finding is not None
    return finding


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def register(client: TestClient) -> TestClient:
    email = f"xss-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={"name": "Xss Test", "email": email,
              "password": PASSWORD, "confirm_password": PASSWORD},
    )
    assert response.status_code == 201, response.text
    return client


def user_id_for(client: TestClient) -> uuid.UUID:
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


def build_scan(user_id: uuid.UUID) -> uuid.UUID:
    crawl = CrawlResult(pages_crawled=2, max_depth_reached=1)
    crawl.endpoints = [
        DiscoveredEndpoint(url=SEARCH, path="/search", method="GET", depth=0,
                           status_code=200, content_type="text/html", parameters=("q",)),
        DiscoveredEndpoint(url=FILTER, path="/filter", method="GET", depth=1,
                           status_code=200, content_type="text/html", parameters=("category",)),
    ]

    grouped = [
        AggregatedFinding(
            data=xss_finding("q"),
            occurrences=[OccurrenceData(endpoint_url=SEARCH, evidence="reflected on /search")],
        ),
        AggregatedFinding(
            data=xss_finding("category"),
            occurrences=[OccurrenceData(endpoint_url=FILTER, evidence="reflected on /filter")],
        ),
    ]

    with SessionLocal() as db:
        scan = Scan(user_id=user_id, target_url="https://xss.test/",
                    status=ScanStatus.COMPLETED, http_status_code=200, is_https=True)
        db.add(scan)
        db.commit()
        db.refresh(scan)

        endpoints_by_url = attack_surface_service.replace_attack_surface(db, scan, crawl)
        finding_service.replace_findings(db, scan, grouped, endpoints_by_url)
        db.commit()
        return scan.id


# --- 1. Stable rule id ------------------------------------------------------ #


def test_rule_id_is_xss_reflected(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    items = owner.get(f"/api/scans/{scan_id}/findings").json()["items"]
    xss = [f for f in items if f["rule_id"] == "XSS_REFLECTED"]

    assert len(xss) == 2
    assert all(f["category"] == "XSS" for f in xss)


# --- 2 & 3. Scan and endpoint association ---------------------------------- #


def test_finding_links_to_the_correct_scan_and_endpoint(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    items = owner.get(f"/api/scans/{scan_id}/findings").json()["items"]
    search = next(f for f in items if f["subject"] == "parameter:q")

    assert search["scan_id"] == str(scan_id)
    assert search["endpoint"]["url"] == SEARCH
    assert search["endpoint"]["path"] == "/search"


# --- 4. Subject identifies the parameter ------------------------------------ #


def test_subject_identifies_the_parameter(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    items = owner.get(f"/api/scans/{scan_id}/findings").json()["items"]
    subjects = {f["subject"] for f in items if f["rule_id"] == "XSS_REFLECTED"}

    assert subjects == {"parameter:q", "parameter:category"}


# --- 5 & 6. Aggregation ----------------------------------------------------- #


def test_same_parameter_on_many_endpoints_aggregates():
    finding = xss_finding("q")
    grouped = aggregate_findings(
        [("https://xss.test/a?q", finding), ("https://xss.test/b?q", finding)]
    )
    assert len(grouped) == 1
    assert grouped[0].occurrence_count == 2


def test_different_parameters_never_merge():
    grouped = aggregate_findings(
        [("https://xss.test/s?q", xss_finding("q")),
         ("https://xss.test/s?page", xss_finding("page"))]
    )
    assert len(grouped) == 2
    assert {g.data.subject for g in grouped} == {"parameter:q", "parameter:page"}


def test_xss_never_merges_with_a_header_finding():
    from app.scanner.security.headers import analyze_security_headers

    header_finding = analyze_security_headers({}, is_https=True, content_type="text/html")[0]
    grouped = aggregate_findings(
        [("https://xss.test/", xss_finding("q")), ("https://xss.test/", header_finding)]
    )
    assert len(grouped) == 2
    assert {g.data.rule for g in grouped} == {FindingRule.XSS_REFLECTED, header_finding.rule}


# --- 7. No secrets in evidence ---------------------------------------------- #


def test_stored_evidence_contains_no_marker_or_value(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    body = owner.get(f"/api/scans/{scan_id}/findings").text
    assert PROBE.token not in body
    assert PROBE.open_marker not in body
    assert CANARY not in body


# --- Summary participation --------------------------------------------------- #


def test_xss_findings_appear_in_the_severity_summary(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    summary = owner.get(f"/api/scans/{scan_id}/findings").json()["summary"]
    assert summary["total"] == 2
    assert summary["high"] == 2
    assert summary["critical"] == 0


def test_isolation_still_holds_for_xss_findings(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    with TestClient(app) as intruder:
        register(intruder)
        assert intruder.get(f"/api/scans/{scan_id}/findings").status_code == 404

    with TestClient(app) as anonymous:
        assert anonymous.get(f"/api/scans/{scan_id}/findings").status_code == 401


def test_xss_category_is_persisted_and_queryable():
    """The 0006 migration's enum label round-trips through the database."""
    with SessionLocal() as db:
        from sqlalchemy import text

        labels = [
            row[0]
            for row in db.execute(
                text("SELECT unnest(enum_range(NULL::finding_category))")
            ).all()
        ]
    assert FindingCategory.XSS.value in labels


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    with SessionLocal() as db:
        db.query(User).filter(User.email.like("xss-%@example.com")).delete(
            synchronize_session=False
        )
        db.commit()
