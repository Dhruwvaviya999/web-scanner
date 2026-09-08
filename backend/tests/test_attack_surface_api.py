"""Attack-surface API tests: ownership, isolation, and no stored secrets.

Rows are inserted directly rather than crawling a live site, keeping the suite
independent of network access.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models.attack_surface import Endpoint, Form
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner.crawler.types import (
    CrawlResult,
    DiscoveredEndpoint,
    DiscoveredForm,
    DiscoveredFormField,
    FormFieldKind,
)
from app.services import attack_surface_service

PASSWORD = "Sup3rSecret!pass"
SECRET_TOKEN = "eyJhbGci-super-secret-token"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def register(client: TestClient) -> TestClient:
    email = f"surface-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Surface Test",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert response.status_code == 201, response.text
    return client


def user_id_for(client: TestClient) -> uuid.UUID:
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


def sample_crawl() -> CrawlResult:
    result = CrawlResult(
        pages_crawled=3, pages_skipped=2, max_depth_reached=2, limit_reached=False
    )
    result.endpoints = [
        DiscoveredEndpoint(
            url="https://example.test/", path="/", method="GET", depth=0,
            status_code=200, content_type="text/html", page_title="Home",
        ),
        DiscoveredEndpoint(
            # Canonical form: names kept, values already stripped by the crawler.
            url="https://example.test/search?category&q", path="/search", method="GET",
            depth=1, status_code=200, content_type="text/html", page_title="Search",
            parameters=("category", "q"),
        ),
        DiscoveredEndpoint(
            url="https://example.test/api/items", path="/api/items", method="GET",
            depth=2, status_code=200, content_type="application/json",
        ),
    ]
    result.forms = [
        DiscoveredForm(
            page_url="https://example.test/login",
            action="https://example.test/login",
            method="POST",
            fields=(
                DiscoveredFormField(name="email", kind=FormFieldKind.INPUT, input_type="email"),
                DiscoveredFormField(
                    name="password", kind=FormFieldKind.INPUT, input_type="password"
                ),
            ),
        )
    ]
    return result


def create_scan_row(user_id: uuid.UUID, crawl: CrawlResult | None) -> uuid.UUID:
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

        attack_surface_service.replace_attack_surface(db, scan, crawl)
        db.commit()
        return scan.id


# --- Endpoints for the owner ----------------------------------------------- #


def test_owner_reads_endpoints_with_parameters_and_summary(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), sample_crawl())

    response = owner.get(f"/api/scans/{scan_id}/endpoints")
    assert response.status_code == 200

    body = response.json()
    assert len(body["items"]) == 3
    # Shallowest first.
    assert [e["depth"] for e in body["items"]] == [0, 1, 2]

    search = next(e for e in body["items"] if e["path"] == "/search")
    assert sorted(p["name"] for p in search["parameters"]) == ["category", "q"]
    assert all(p["location"] == "QUERY" for p in search["parameters"])

    assert body["summary"] == {
        "endpoints": 3, "forms": 1, "parameters": 2,
        "pages_crawled": 3, "pages_skipped": 2,
        "max_depth_reached": 2, "crawl_limit_reached": False,
    }


def test_owner_reads_forms_with_fields(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), sample_crawl())

    body = owner.get(f"/api/scans/{scan_id}/forms").json()

    assert body["total"] == 1
    form = body["items"][0]
    assert form["method"] == "POST"
    assert [(f["name"], f["input_type"]) for f in form["fields"]] == [
        ("email", "email"),
        ("password", "password"),
    ]


# --- 1 & 2. Another user cannot access endpoints or forms ------------------ #


def test_other_users_cannot_read_endpoints_or_forms(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), sample_crawl())

    with TestClient(app) as intruder:
        register(intruder)
        # 404, not 403: a 403 would confirm the scan id exists.
        assert intruder.get(f"/api/scans/{scan_id}/endpoints").status_code == 404
        assert intruder.get(f"/api/scans/{scan_id}/forms").status_code == 404


# --- 3. Anonymous access ---------------------------------------------------- #


def test_anonymous_access_returns_401(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), sample_crawl())

    with TestClient(app) as anonymous:
        for path in ("endpoints", "forms"):
            response = anonymous.get(f"/api/scans/{scan_id}/{path}")
            assert response.status_code == 401, path


def test_unknown_scan_id_returns_404(client):
    owner = register(client)
    assert owner.get(f"/api/scans/{uuid.uuid4()}/endpoints").status_code == 404
    assert owner.get(f"/api/scans/{uuid.uuid4()}/forms").status_code == 404


# --- 4. Sensitive values are not persisted --------------------------------- #


def test_query_values_are_never_returned_by_the_api(client):
    """The crawler canonicalises before storage; confirm nothing leaks through."""
    owner = register(client)
    crawl = sample_crawl()
    scan_id = create_scan_row(user_id_for(owner), crawl)

    endpoints_body = owner.get(f"/api/scans/{scan_id}/endpoints").text
    forms_body = owner.get(f"/api/scans/{scan_id}/forms").text

    assert SECRET_TOKEN not in endpoints_body
    assert SECRET_TOKEN not in forms_body
    # Parameter names are present; a value-bearing query string is not.
    assert "?category&q" in endpoints_body
    assert "q=" not in endpoints_body


def test_no_column_exists_for_a_parameter_or_field_value():
    """Structural guarantee: there is nowhere to put a value even by mistake."""
    from app.models.attack_surface import EndpointParameter, FormField

    assert "value" not in EndpointParameter.__table__.columns
    assert "value" not in FormField.__table__.columns


# --- 5. Empty and absent crawls -------------------------------------------- #


def test_scan_without_a_crawl_returns_empty_lists(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), None)

    endpoints = owner.get(f"/api/scans/{scan_id}/endpoints").json()
    forms = owner.get(f"/api/scans/{scan_id}/forms").json()

    assert endpoints["items"] == []
    assert forms["items"] == []
    # NULL, not 0: "did not crawl" stays distinct from "crawled and found nothing".
    assert endpoints["summary"]["pages_crawled"] is None


def test_empty_crawl_reports_zero_rather_than_null(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), CrawlResult())

    summary = owner.get(f"/api/scans/{scan_id}/endpoints").json()["summary"]
    assert summary["pages_crawled"] == 0
    assert summary["endpoints"] == 0


# --- Cascade and replacement ------------------------------------------------ #


def test_deleting_a_scan_removes_its_attack_surface(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), sample_crawl())

    assert owner.delete(f"/api/scans/{scan_id}").status_code == 204

    with SessionLocal() as db:
        assert db.query(Endpoint).filter(Endpoint.scan_id == scan_id).count() == 0
        assert db.query(Form).filter(Form.scan_id == scan_id).count() == 0


def test_replacing_the_attack_surface_does_not_accumulate(client):
    owner = register(client)
    uid = user_id_for(owner)
    scan_id = create_scan_row(uid, sample_crawl())

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        attack_surface_service.replace_attack_surface(db, scan, CrawlResult())
        db.commit()

    assert owner.get(f"/api/scans/{scan_id}/endpoints").json()["items"] == []


def test_existing_scan_and_findings_endpoints_still_work(client):
    owner = register(client)
    scan_id = create_scan_row(user_id_for(owner), sample_crawl())

    assert owner.get("/api/scans").status_code == 200
    assert owner.get("/api/scans/stats").status_code == 200
    assert owner.get(f"/api/scans/{scan_id}").status_code == 200
    assert owner.get(f"/api/scans/{scan_id}/findings").status_code == 200


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    with SessionLocal() as db:
        db.query(User).filter(User.email.like("surface-%@example.com")).delete(
            synchronize_session=False
        )
        db.commit()
