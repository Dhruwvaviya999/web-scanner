"""SQLi findings inside the existing finding architecture.

Confirms there is no separate SQLi path: these findings deduplicate, associate
with endpoints and reach the API exactly like every other finding.
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
from app.scanner.vulnerabilities.sqli.findings import (
    build_boolean_finding,
    build_error_based_finding,
)
from app.scanner.vulnerabilities.sqli.types import DatabaseFamily, ErrorSignalStrength
from app.services import attack_surface_service, finding_service

PASSWORD = "Sup3rSecret!pass"
PRODUCTS = "https://sqli.test/products?id"
SEARCH = "https://sqli.test/search?q"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def register(client: TestClient) -> TestClient:
    email = f"sqli-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={"name": "Sqli Test", "email": email,
              "password": PASSWORD, "confirm_password": PASSWORD},
    )
    assert response.status_code == 201, response.text
    return client


def user_id_for(client: TestClient) -> uuid.UUID:
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


def build_scan(user_id: uuid.UUID) -> uuid.UUID:
    crawl = CrawlResult(pages_crawled=2, max_depth_reached=1)
    crawl.endpoints = [
        DiscoveredEndpoint(url=PRODUCTS, path="/products", method="GET", depth=0,
                           status_code=200, content_type="text/html", parameters=("id",)),
        DiscoveredEndpoint(url=SEARCH, path="/search", method="GET", depth=1,
                           status_code=200, content_type="text/html", parameters=("q",)),
    ]

    error_finding = build_error_based_finding(
        "id", DatabaseFamily.POSTGRESQL, ErrorSignalStrength.STRONG, "single_quote"
    )
    boolean_finding = build_boolean_finding("q", "numeric_and")

    grouped = [
        AggregatedFinding(data=error_finding,
                          occurrences=[OccurrenceData(endpoint_url=PRODUCTS, evidence="pg error under probe")]),
        AggregatedFinding(data=boolean_finding,
                          occurrences=[OccurrenceData(endpoint_url=SEARCH, evidence="stable differential")]),
    ]

    with SessionLocal() as db:
        scan = Scan(user_id=user_id, target_url="https://sqli.test/",
                    status=ScanStatus.COMPLETED, http_status_code=200, is_https=True)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        endpoints_by_url = attack_surface_service.replace_attack_surface(db, scan, crawl)
        finding_service.replace_findings(db, scan, grouped, endpoints_by_url)
        db.commit()
        return scan.id


# --- Rule id and category --------------------------------------------------- #


def test_rule_ids_and_category(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    items = owner.get(f"/api/scans/{scan_id}/findings").json()["items"]
    sqli = [f for f in items if f["category"] == "SQLI"]

    assert len(sqli) == 2
    rules = {f["rule_id"] for f in sqli}
    assert rules == {"SQLI_ERROR_BASED", "SQLI_BOOLEAN_DIFFERENTIAL"}


# --- Severity and confidence ------------------------------------------------ #


def test_severity_and_confidence(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    items = owner.get(f"/api/scans/{scan_id}/findings").json()["items"]
    error = next(f for f in items if f["rule_id"] == "SQLI_ERROR_BASED")
    boolean = next(f for f in items if f["rule_id"] == "SQLI_BOOLEAN_DIFFERENTIAL")

    assert error["severity"] == "HIGH" and error["confidence"] == "HIGH"
    assert boolean["severity"] == "HIGH" and boolean["confidence"] == "HIGH"
    # Never CRITICAL.
    assert all(f["severity"] != "CRITICAL" for f in items)


# --- Endpoint association and subject --------------------------------------- #


def test_endpoint_and_subject(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    items = owner.get(f"/api/scans/{scan_id}/findings").json()["items"]
    error = next(f for f in items if f["rule_id"] == "SQLI_ERROR_BASED")

    assert error["endpoint"]["url"] == PRODUCTS
    assert error["endpoint"]["path"] == "/products"
    assert error["subject"] == "parameter:id"


# --- Aggregation ------------------------------------------------------------ #


def test_same_rule_and_parameter_aggregates():
    finding = build_error_based_finding(
        "id", DatabaseFamily.MYSQL, ErrorSignalStrength.STRONG, "single_quote"
    )
    grouped = aggregate_findings(
        [("https://sqli.test/a?id", finding), ("https://sqli.test/b?id", finding)]
    )
    assert len(grouped) == 1
    assert grouped[0].occurrence_count == 2


def test_different_parameters_stay_distinct():
    a = build_error_based_finding("id", DatabaseFamily.MYSQL, ErrorSignalStrength.STRONG, "q")
    b = build_error_based_finding("code", DatabaseFamily.MYSQL, ErrorSignalStrength.STRONG, "q")
    grouped = aggregate_findings([("https://sqli.test/s?id", a), ("https://sqli.test/s?code", b)])
    assert len(grouped) == 2
    assert {g.data.subject for g in grouped} == {"parameter:id", "parameter:code"}


def test_error_and_boolean_rules_stay_distinct():
    err = build_error_based_finding("id", DatabaseFamily.MYSQL, ErrorSignalStrength.STRONG, "q")
    bln = build_boolean_finding("id", "numeric_and")
    grouped = aggregate_findings([("https://sqli.test/s?id", err), ("https://sqli.test/s?id", bln)])
    assert len(grouped) == 2  # same subject, different rule → separate


def test_sqli_never_merges_with_xss():
    from app.scanner.vulnerabilities.xss.analyzer import analyze_reflection
    from app.scanner.vulnerabilities.xss.findings import build_finding
    from app.scanner.vulnerabilities.xss.payloads import CANARY, new_probe

    probe = new_probe()
    xss = build_finding("id", analyze_reflection(f"<div>{probe.value}</div>",
                                                 probe.open_marker, probe.close_marker, CANARY))
    sqli = build_error_based_finding("id", DatabaseFamily.MYSQL, ErrorSignalStrength.STRONG, "q")
    grouped = aggregate_findings([("https://sqli.test/s?id", xss), ("https://sqli.test/s?id", sqli)])

    assert len(grouped) == 2
    assert {g.data.rule for g in grouped} == {FindingRule.XSS_REFLECTED, FindingRule.SQLI_ERROR_BASED}


# --- Evidence safety and summary -------------------------------------------- #


def test_evidence_contains_no_secrets(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    body = owner.get(f"/api/scans/{scan_id}/findings").text
    # No raw SQL fragments, probe syntax, or query values.
    assert "1=1" not in body and "1=2" not in body
    assert "SELECT" not in body and "select *" not in body.lower()


def test_summary_counts_sqli_findings(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    summary = owner.get(f"/api/scans/{scan_id}/findings").json()["summary"]
    assert summary["total"] == 2
    assert summary["high"] == 2


def test_isolation_holds_for_sqli_findings(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    with TestClient(app) as intruder:
        register(intruder)
        assert intruder.get(f"/api/scans/{scan_id}/findings").status_code == 404
    with TestClient(app) as anon:
        assert anon.get(f"/api/scans/{scan_id}/findings").status_code == 401


def test_sqli_category_persisted():
    from sqlalchemy import text

    with SessionLocal() as db:
        labels = [r[0] for r in db.execute(
            text("SELECT unnest(enum_range(NULL::finding_category))")).all()]
    assert FindingCategory.SQLI.value in labels


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    with SessionLocal() as db:
        db.query(User).filter(User.email.like("sqli-%@example.com")).delete(
            synchronize_session=False
        )
        db.commit()
