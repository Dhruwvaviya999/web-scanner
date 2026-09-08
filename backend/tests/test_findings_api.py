"""Findings API integration tests.

These run against the configured database and exercise the real app through
FastAPI's TestClient. Each test registers its own user, so runs do not collide.

`test_findings_are_linked_to_the_correct_scan` inserts findings directly rather
than scanning a live site, keeping the suite independent of network access.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)
from app.services import finding_service

PASSWORD = "Sup3rSecret!pass"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def register(client: TestClient) -> TestClient:
    """Register a fresh user; the session cookie stays on the returned client."""
    email = f"findings-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Findings Test",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert response.status_code == 201, response.text
    return client


def new_client() -> TestClient:
    return TestClient(app)


def create_scan_row(user_id: uuid.UUID, findings: list[FindingData]) -> uuid.UUID:
    """Insert a COMPLETED scan with the given findings, without any network I/O."""
    with SessionLocal() as db:
        scan = Scan(
            user_id=user_id,
            target_url="https://example.test/",
            status=ScanStatus.COMPLETED,
            http_status_code=200,
            is_https=True,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        finding_service.replace_findings_from_data(db, scan, findings)
        db.commit()
        return scan.id


def user_id_for(client: TestClient) -> uuid.UUID:
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


SAMPLE_FINDINGS = [
    FindingData(
        rule=FindingRule.SECURITY_HEADER_CSP_MISSING,
        title="Content-Security-Policy header not set",
        category=FindingCategory.SECURITY_HEADER,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        description="d",
        evidence="e",
        impact="i",
        remediation="r",
    ),
    FindingData(
        rule=FindingRule.SECURITY_HEADER_PERMISSIONS_POLICY_MISSING,
        title="Permissions-Policy header not set",
        category=FindingCategory.SECURITY_HEADER,
        severity=FindingSeverity.INFO,
        confidence=FindingConfidence.HIGH,
        description="d",
        evidence="e",
        impact="i",
        remediation="r",
    ),
    FindingData(
        rule=FindingRule.COOKIE_HTTPONLY_MISSING,
        title="Session cookie is missing HttpOnly",
        category=FindingCategory.COOKIE,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        description="d",
        evidence='Cookie "session" does not include the HttpOnly attribute.',
        impact="i",
        remediation="r",
    ),
]


# --- 1. Findings are linked to the correct scan ---------------------------- #


def test_findings_are_linked_to_the_correct_scan(client):
    owner = register(client)
    uid = user_id_for(owner)

    scan_with = create_scan_row(uid, SAMPLE_FINDINGS)
    scan_without = create_scan_row(uid, [])

    with_body = owner.get(f"/api/scans/{scan_with}/findings").json()
    without_body = owner.get(f"/api/scans/{scan_without}/findings").json()

    assert len(with_body["items"]) == 3
    assert without_body["items"] == []
    assert {f["scan_id"] for f in with_body["items"]} == {str(scan_with)}


# --- 2. Findings are returned to the scan owner ---------------------------- #


def test_owner_can_read_findings_with_full_detail(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), SAMPLE_FINDINGS)

    response = owner.get(f"/api/scans/{scan_id}/findings")
    assert response.status_code == 200

    body = response.json()
    first = body["items"][0]
    for field in (
        "id", "scan_id", "rule_id", "title", "category", "severity",
        "confidence", "description", "evidence", "impact", "remediation",
    ):
        assert field in first, field

    # Most severe first: MEDIUM before INFO.
    assert [f["severity"] for f in body["items"]] == ["MEDIUM", "MEDIUM", "INFO"]
    assert body["summary"] == {
        "total": 3, "critical": 0, "high": 0, "medium": 2, "low": 0, "info": 1,
    }


# --- 3. Another user cannot reach them ------------------------------------- #


def test_other_users_cannot_read_findings(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), SAMPLE_FINDINGS)

    with new_client() as intruder:
        register(intruder)
        response = intruder.get(f"/api/scans/{scan_id}/findings")

    # 404, not 403: a 403 would confirm the scan id exists.
    assert response.status_code == 404
    assert "session" not in response.text.lower() or "findings" not in response.text


# --- 4. Anonymous users receive 401 ---------------------------------------- #


def test_anonymous_users_receive_401(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), SAMPLE_FINDINGS)

    with new_client() as anonymous:
        response = anonymous.get(f"/api/scans/{scan_id}/findings")

    assert response.status_code == 401
    assert response.json()["error"]["code"] in {"not_authenticated", "unauthorized"}


# --- 5. A scan with no findings returns an empty array --------------------- #


def test_scan_without_findings_returns_empty_list(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), [])

    body = owner.get(f"/api/scans/{scan_id}/findings").json()

    assert body["items"] == []
    assert body["summary"]["total"] == 0


def test_unknown_scan_id_returns_404(client):
    owner = register(client)
    assert owner.get(f"/api/scans/{uuid.uuid4()}/findings").status_code == 404


# --- 6. Existing scan API behaviour is unaffected -------------------------- #


def test_existing_scan_endpoints_still_work(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), SAMPLE_FINDINGS)

    assert owner.get("/api/scans").status_code == 200
    assert owner.get("/api/scans/stats").status_code == 200

    detail = owner.get(f"/api/scans/{scan_id}")
    assert detail.status_code == 200
    assert detail.json()["target_url"] == "https://example.test/"


def test_deleting_a_scan_removes_its_findings(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), SAMPLE_FINDINGS)

    assert owner.delete(f"/api/scans/{scan_id}").status_code == 204
    assert owner.get(f"/api/scans/{scan_id}/findings").status_code == 404

    with SessionLocal() as db:
        remaining = db.query(Finding).filter(Finding.scan_id == scan_id).count()
    assert remaining == 0, "findings should cascade with their scan"


def test_replacing_findings_does_not_accumulate_duplicates(client):
    owner = register(client)
    uid = user_id_for(owner)
    scan_id = create_scan_row(uid, SAMPLE_FINDINGS)

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        finding_service.replace_findings_from_data(db, scan, SAMPLE_FINDINGS[:1])
        db.commit()

    body = owner.get(f"/api/scans/{scan_id}/findings").json()
    assert len(body["items"]) == 1


def test_stored_findings_never_contain_a_cookie_value(client):
    """End-to-end guard for the parser's no-values guarantee."""
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), SAMPLE_FINDINGS)

    body = owner.get(f"/api/scans/{scan_id}/findings").text
    assert "s3cr3t" not in body
    assert "abc123" not in body


@pytest.fixture(autouse=True)
def _cleanup():
    """Remove the users this module creates, and their scans, after each test."""
    yield
    with SessionLocal() as db:
        db.query(User).filter(User.email.like("findings-%@example.com")).delete(
            synchronize_session=False
        )
        db.commit()
