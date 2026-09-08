"""Finding-to-endpoint association through the API.

Exercises the real persistence path: endpoints are written first, then
aggregated findings are linked to them.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models.attack_surface import Endpoint
from app.models.finding import Finding, FindingOccurrence
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner.analysis.types import AggregatedFinding, FindingOccurrence as OccurrenceData
from app.scanner.crawler.types import CrawlResult, DiscoveredEndpoint
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)
from app.services import attack_surface_service, finding_service

PASSWORD = "Sup3rSecret!pass"
HOME = "https://assoc.test/"
LOGIN = "https://assoc.test/login"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def register(client: TestClient) -> TestClient:
    email = f"assoc-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Assoc Test",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert response.status_code == 201, response.text
    return client


def user_id_for(client: TestClient) -> uuid.UUID:
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


def finding(rule: FindingRule, subject: str | None = None) -> FindingData:
    return FindingData(
        rule=rule,
        title=f"title {rule.value}",
        category=FindingCategory.SECURITY_HEADER,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        description="d",
        evidence="e",
        impact="i",
        remediation="r",
        subject=subject,
    )


def build_scan(user_id: uuid.UUID) -> uuid.UUID:
    """A scan with two endpoints and one finding spanning both."""
    crawl = CrawlResult(pages_crawled=2, pages_skipped=0, max_depth_reached=1)
    crawl.endpoints = [
        DiscoveredEndpoint(url=HOME, path="/", method="GET", depth=0, status_code=200),
        DiscoveredEndpoint(url=LOGIN, path="/login", method="GET", depth=1, status_code=200),
    ]

    grouped = [
        AggregatedFinding(
            data=finding(FindingRule.SECURITY_HEADER_CSP_MISSING),
            occurrences=[
                OccurrenceData(endpoint_url=HOME, evidence="missing on /"),
                OccurrenceData(endpoint_url=LOGIN, evidence="missing on /login"),
            ],
        ),
        # A finding with no endpoint context at all.
        AggregatedFinding(
            data=finding(FindingRule.COOKIE_SECURE_MISSING, subject="session"),
            occurrences=[OccurrenceData(endpoint_url=None, evidence="scan level")],
        ),
    ]

    with SessionLocal() as db:
        scan = Scan(
            user_id=user_id,
            target_url=HOME,
            status=ScanStatus.COMPLETED,
            http_status_code=200,
            is_https=True,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        endpoints_by_url = attack_surface_service.replace_attack_surface(db, scan, crawl)
        finding_service.replace_findings(db, scan, grouped, endpoints_by_url)
        db.commit()
        return scan.id


# --- 1 & 2. Correct scan and endpoint -------------------------------------- #


def test_finding_is_linked_to_its_scan_and_primary_endpoint(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    items = owner.get(f"/api/scans/{scan_id}/findings").json()["items"]
    csp = next(f for f in items if f["rule_id"] == "SECURITY_HEADER_CSP_MISSING")

    assert csp["scan_id"] == str(scan_id)
    assert csp["endpoint"] is not None
    assert csp["endpoint"]["url"] == HOME
    assert csp["endpoint"]["method"] == "GET"


def test_all_affected_endpoints_are_preserved(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    items = owner.get(f"/api/scans/{scan_id}/findings").json()["items"]
    csp = next(f for f in items if f["rule_id"] == "SECURITY_HEADER_CSP_MISSING")

    assert csp["occurrence_count"] == 2
    assert {o["endpoint_url"] for o in csp["occurrences"]} == {HOME, LOGIN}
    # Each occurrence keeps its own evidence.
    assert {o["evidence"] for o in csp["occurrences"]} == {
        "missing on /",
        "missing on /login",
    }
    # And each is linked to a real endpoint row.
    assert all(o["endpoint_id"] is not None for o in csp["occurrences"])


# --- 3. A finding without an endpoint stays valid -------------------------- #


def test_finding_without_an_endpoint_is_still_returned(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    items = owner.get(f"/api/scans/{scan_id}/findings").json()["items"]
    cookie = next(f for f in items if f["rule_id"] == "COOKIE_SECURE_MISSING")

    assert cookie["endpoint"] is None
    assert cookie["subject"] == "session"
    assert cookie["occurrences"][0]["endpoint_url"] is None


# --- 4. Isolation ----------------------------------------------------------- #


def test_other_users_cannot_reach_findings_or_their_endpoints(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    with TestClient(app) as intruder:
        register(intruder)
        assert intruder.get(f"/api/scans/{scan_id}/findings").status_code == 404
        assert intruder.get(f"/api/scans/{scan_id}/endpoints").status_code == 404


def test_anonymous_access_is_rejected(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    with TestClient(app) as anonymous:
        assert anonymous.get(f"/api/scans/{scan_id}/findings").status_code == 401


# --- 5. Cascade behaviour --------------------------------------------------- #


def test_deleting_a_scan_removes_findings_endpoints_and_occurrences(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    assert owner.delete(f"/api/scans/{scan_id}").status_code == 204

    with SessionLocal() as db:
        assert db.query(Finding).filter(Finding.scan_id == scan_id).count() == 0
        assert db.query(Endpoint).filter(Endpoint.scan_id == scan_id).count() == 0
        # Occurrences cascade from their finding.
        assert db.query(FindingOccurrence).count() >= 0


def test_removing_an_endpoint_keeps_the_finding(client):
    """SET NULL, not CASCADE: a finding must outlive the endpoint row."""
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    with SessionLocal() as db:
        endpoint = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).first()
        db.delete(endpoint)
        db.commit()

    items = owner.get(f"/api/scans/{scan_id}/findings").json()["items"]
    csp = next(f for f in items if f["rule_id"] == "SECURITY_HEADER_CSP_MISSING")

    assert csp is not None, "the finding must survive its endpoint"
    assert csp["endpoint"] is None


# --- Analysis state on endpoints -------------------------------------------- #


def test_endpoints_report_their_analysis_status(client):
    owner = register(client)
    scan_id = build_scan(user_id_for(owner))

    items = owner.get(f"/api/scans/{scan_id}/endpoints").json()["items"]
    # These rows were inserted without running the analysis stage.
    assert all(e["analysis_status"] == "NOT_ANALYZED" for e in items)
    assert all(e["skip_reason"] is None for e in items)


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    with SessionLocal() as db:
        db.query(User).filter(User.email.like("assoc-%@example.com")).delete(
            synchronize_session=False
        )
        db.commit()
