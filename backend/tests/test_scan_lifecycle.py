"""Scan execution lifecycle: state machine, cancellation, progress, failure.

Nothing here touches the network. The scanner is replaced with a stub whose
behaviour each test chooses — completing, raising, or reporting itself
cancelled — so the orchestration around it can be driven through every path
including the ones a real target would rarely produce.

The API cases drive the real app through TestClient against the configured
database, as the other integration suites do.
"""

from __future__ import annotations

import asyncio
import secrets
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.core.errors import ConflictError
from app.main import app
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner.cancellation import CancellationToken, ScanCancelled
from app.scanner.types import HttpProbeResult, ScanErrorCode, ScanReport, ScanTarget
from app.services import scan_service
from app.services.cancellation import cancellation_token_for
from app.services.scan_lifecycle import (
    ALLOWED_TRANSITIONS,
    STAGE_MESSAGE,
    STAGE_PROGRESS,
    TERMINAL_STAGE,
    TERMINAL_STATUSES,
    ScanStage,
    can_transition,
    is_terminal,
    transition,
)

PASSWORD = "Sup3rSecret!pass"
TARGET = "https://lifecycle.test/"


# --------------------------------------------------------------------------- #
# Fixtures and stubs
# --------------------------------------------------------------------------- #


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def register(client: TestClient) -> uuid.UUID:
    """Register a fresh user; the session cookie stays on the client."""
    email = f"lifecycle-{secrets.token_hex(6)}@example.com"
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Lifecycle Test",
            "email": email,
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(client.get("/api/auth/me").json()["id"])


def make_report(**overrides) -> ScanReport:
    """A successful report, unless a test overrides part of it."""
    defaults = dict(
        target=ScanTarget(
            raw_url=TARGET,
            normalized_url=TARGET,
            scheme="https",
            host="lifecycle.test",
            port=443,
            is_https=True,
        ),
        probe=HttpProbeResult(
            http_status_code=200,
            response_time_ms=12,
            final_url=TARGET,
            is_https=True,
            redirect_count=0,
            content_type="text/html",
            page_title="Lifecycle",
        ),
    )
    defaults.update(overrides)
    return ScanReport(**defaults)


class StubScanner:
    """Stands in for `WebScanner`, recording what it was handed.

    Constructed exactly as the real scanner is, so a signature change in
    `scan_service` shows up here as a failure rather than silently diverging.
    """

    instances: list["StubScanner"] = []

    #: Set per test: the report to return, or an exception to raise.
    report: ScanReport | None = None
    raises: BaseException | None = None
    #: Called with the scanner instance once `scan_sync` starts.
    on_scan = None

    def __init__(self, config, *, crawl_config, active_config, detectors,
                 cancellation, on_module_start, authentication):
        self.config = config
        self.cancellation = cancellation
        self.on_module_start = on_module_start
        self.authentication = authentication
        StubScanner.instances.append(self)

    def scan_sync(self, raw_url: str) -> ScanReport:
        if StubScanner.on_scan is not None:
            StubScanner.on_scan(self)
        if StubScanner.raises is not None:
            raise StubScanner.raises
        assert StubScanner.report is not None
        return StubScanner.report


@pytest.fixture
def stub_scanner(monkeypatch):
    StubScanner.instances = []
    StubScanner.report = make_report()
    StubScanner.raises = None
    StubScanner.on_scan = None
    monkeypatch.setattr(scan_service, "WebScanner", StubScanner)
    yield StubScanner
    StubScanner.on_scan = None
    StubScanner.raises = None


def load(scan_id: uuid.UUID) -> Scan:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        return scan


def insert_scan(user_id: uuid.UUID, **overrides) -> uuid.UUID:
    with SessionLocal() as db:
        scan = Scan(user_id=user_id, target_url=TARGET, **overrides)
        db.add(scan)
        db.commit()
        return scan.id


def enqueue(user_id: uuid.UUID) -> uuid.UUID:
    """Queue a scan the way the API does, in a session of its own."""
    with SessionLocal() as db:
        return scan_service.enqueue_scan(db, db.get(User, user_id), TARGET)


# --------------------------------------------------------------------------- #
# The state machine
# --------------------------------------------------------------------------- #


def test_every_status_has_a_transition_rule():
    """A new status must be given edges deliberately, not inherit none by accident."""
    assert set(ALLOWED_TRANSITIONS) == set(ScanStatus)


def test_every_stage_has_progress_and_a_message():
    assert set(STAGE_PROGRESS) == set(ScanStage)
    assert set(STAGE_MESSAGE) == set(ScanStage)
    assert set(TERMINAL_STAGE) == TERMINAL_STATUSES


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (ScanStatus.QUEUED, ScanStatus.RUNNING),
        (ScanStatus.QUEUED, ScanStatus.CANCELLED),
        (ScanStatus.QUEUED, ScanStatus.FAILED),
        (ScanStatus.RUNNING, ScanStatus.COMPLETED),
        (ScanStatus.RUNNING, ScanStatus.FAILED),
        (ScanStatus.RUNNING, ScanStatus.CANCELLED),
    ],
)
def test_legal_transitions(current, target):
    assert transition(current, target) is target


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (ScanStatus.COMPLETED, ScanStatus.RUNNING),
        (ScanStatus.COMPLETED, ScanStatus.CANCELLED),
        (ScanStatus.FAILED, ScanStatus.COMPLETED),
        (ScanStatus.FAILED, ScanStatus.RUNNING),
        (ScanStatus.CANCELLED, ScanStatus.RUNNING),
        (ScanStatus.CANCELLED, ScanStatus.COMPLETED),
        (ScanStatus.RUNNING, ScanStatus.QUEUED),
    ],
)
def test_illegal_transitions_are_refused(current, target):
    assert can_transition(current, target) is False
    with pytest.raises(ConflictError) as exc:
        transition(current, target)
    assert exc.value.code == "invalid_scan_transition"
    assert exc.value.status_code == 409


def test_terminal_states_have_no_outgoing_edges():
    for status in TERMINAL_STATUSES:
        assert is_terminal(status)
        assert ALLOWED_TRANSITIONS[status] == frozenset()


def test_a_status_may_be_reasserted():
    """Re-applying the status a scan already has is a no-op, not a conflict."""
    for status in ScanStatus:
        assert transition(status, status) is status


# --------------------------------------------------------------------------- #
# The cancellation token (pure)
# --------------------------------------------------------------------------- #


def test_a_token_without_a_predicate_never_cancels():
    token = CancellationToken.none()
    assert token.cancelled is False
    token.raise_if_cancelled("CRAWLING")  # does not raise


def test_a_token_latches_once_cancelled():
    """Asked once and told to stop, it never reports 'keep going' again."""
    answers = iter([True, False, False])
    token = CancellationToken(lambda: next(answers))

    assert token.cancelled is True
    assert token.cancelled is True
    assert token.cancelled is True


def test_a_failing_predicate_does_not_stop_the_scan():
    """A broken cancellation check must not end a scan that was never cancelled."""
    def boom() -> bool:
        raise RuntimeError("database unavailable")

    assert CancellationToken(boom).cancelled is False


def test_raise_if_cancelled_carries_the_stage():
    token = CancellationToken(lambda: True)
    with pytest.raises(ScanCancelled) as exc:
        token.raise_if_cancelled("CRAWLING")
    assert exc.value.stage == "CRAWLING"


# --------------------------------------------------------------------------- #
# The database-backed token
# --------------------------------------------------------------------------- #


def test_db_token_reads_the_cancel_flag(client):
    user_id = register(client)
    scan_id = insert_scan(user_id, status=ScanStatus.RUNNING)

    # No throttle: each call is allowed to hit the database.
    token = cancellation_token_for(scan_id, poll_interval_seconds=0)
    assert token.cancelled is False

    with SessionLocal() as db:
        db.get(Scan, scan_id).cancel_requested = True
        db.commit()

    assert token.cancelled is True


def test_db_token_throttles_its_reads(client):
    """A hot loop must not become one query per crawled page."""
    user_id = register(client)
    scan_id = insert_scan(user_id, status=ScanStatus.RUNNING)

    token = cancellation_token_for(scan_id, poll_interval_seconds=3600)
    assert token.cancelled is False

    with SessionLocal() as db:
        db.get(Scan, scan_id).cancel_requested = True
        db.commit()

    # Inside the interval the previous answer stands.
    assert token.cancelled is False


def test_db_token_for_a_missing_scan_does_not_cancel():
    token = cancellation_token_for(uuid.uuid4(), poll_interval_seconds=0)
    assert token.cancelled is False


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #


def test_a_successful_run_walks_queued_to_completed(client, stub_scanner):
    register(client)
    response = client.post("/api/scans", json={"target_url": TARGET})
    assert response.status_code == 201, response.text
    body = response.json()

    assert body["status"] == "COMPLETED"
    assert body["current_stage"] == "COMPLETED"
    assert body["progress_percent"] == 100
    assert body["cancel_requested"] is False
    assert body["failure_stage"] is None
    assert body["error_message"] is None
    assert body["queued_at"] is not None
    assert body["started_at"] is not None
    assert body["completed_at"] is not None
    assert body["cancelled_at"] is None


def test_the_scanner_is_given_a_cancellation_token_and_a_progress_callback(
    client, stub_scanner
):
    register(client)
    client.post("/api/scans", json={"target_url": TARGET})

    scanner = stub_scanner.instances[-1]
    assert isinstance(scanner.cancellation, CancellationToken)
    assert callable(scanner.on_module_start)


def test_progress_is_persisted_as_the_scan_moves_between_modules(client, stub_scanner):
    """Stages reach the database while the scan runs, not only at the end."""
    user_id = register(client)
    scan_id = enqueue(user_id)
    seen: list[tuple[str | None, int | None]] = []

    def report_stages(scanner: StubScanner) -> None:
        for module in ("http_probe", "crawler", "endpoint_analysis"):
            scanner.on_module_start(module)
            row = load(scan_id)
            seen.append((row.current_stage, row.progress_percent))

    stub_scanner.on_scan = report_stages
    scan_service.execute_scan(scan_id)

    assert seen == [
        ("PROBING", STAGE_PROGRESS[ScanStage.PROBING]),
        ("CRAWLING", STAGE_PROGRESS[ScanStage.CRAWLING]),
        ("ANALYZING", STAGE_PROGRESS[ScanStage.ANALYZING]),
    ]


def test_a_queued_scan_is_only_executed_once(client, stub_scanner):
    """The second caller must not re-run a scan that is no longer QUEUED."""
    user_id = register(client)
    scan_id = enqueue(user_id)

    scan_service.execute_scan(scan_id)
    assert len(stub_scanner.instances) == 1

    # Already COMPLETED: the claim fails and the scanner is never constructed.
    again = scan_service.execute_scan(scan_id)
    assert len(stub_scanner.instances) == 1
    assert again.status is ScanStatus.COMPLETED


def test_a_scan_that_raises_ends_failed_not_running(client, stub_scanner):
    """The defect this guards: an exception leaving a scan RUNNING forever."""
    stub_scanner.raises = RuntimeError("something internal went wrong")

    user_id = register(client)
    scan_id = enqueue(user_id)

    result = scan_service.execute_scan(scan_id)

    assert result.status is ScanStatus.FAILED
    assert result.completed_at is not None
    assert result.current_stage == "FAILED"
    assert result.failure_stage == ScanStage.INITIALIZING.value


def test_a_failure_message_never_carries_internals(client, stub_scanner):
    """No stack trace, no exception text, no target internals in a shown field."""
    secret = "postgresql://scanner:hunter2@10.0.0.5/db"
    stub_scanner.raises = RuntimeError(f"connect failed: {secret} token=abcdef123456")

    user_id = register(client)
    scan_id = enqueue(user_id)
    scan_service.execute_scan(scan_id)

    body = client.get(f"/api/scans/{scan_id}").json()
    message = body["error_message"]

    assert message == scan_service.UNEXPECTED_FAILURE_MESSAGE
    assert "hunter2" not in message
    assert "abcdef123456" not in message
    assert "Traceback" not in message
    assert "RuntimeError" not in message
    # The stage is safe to show; it is a name from a fixed vocabulary.
    assert body["failure_stage"] in {stage.value for stage in ScanStage}


def test_a_scanner_error_is_a_failed_scan_not_an_error_response(client, stub_scanner):
    """Phase 1 behaviour preserved: an unreachable target yields a FAILED row."""
    stub_scanner.report = make_report(
        probe=None,
        error_code=ScanErrorCode.DNS_FAILURE,
        error_message="Could not resolve host.",
    )
    register(client)

    response = client.post("/api/scans", json={"target_url": TARGET})

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "FAILED"
    assert body["error_message"] == "Could not resolve host."


# --------------------------------------------------------------------------- #
# Cancellation, end to end
# --------------------------------------------------------------------------- #


def test_a_cancelled_run_is_recorded_as_cancelled_not_failed(client, stub_scanner):
    """A stop is a normal outcome; whatever was gathered is kept."""
    stub_scanner.report = make_report(cancelled=True)

    user_id = register(client)
    scan_id = enqueue(user_id)
    result = scan_service.execute_scan(scan_id)

    assert result.status is ScanStatus.CANCELLED
    assert result.current_stage == "CANCELLED"
    assert result.error_message is None
    assert result.failure_stage is None
    assert result.cancelled_at is not None
    assert result.completed_at is not None
    # Partial results survive: the probe had already run when the stop landed.
    assert result.http_status_code == 200


def test_cancelling_a_queued_scan_stops_it_outright(client):
    user_id = register(client)
    scan_id = insert_scan(user_id, status=ScanStatus.QUEUED)

    response = client.post(f"/api/scans/{scan_id}/cancel")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "CANCELLED"
    assert body["cancel_requested"] is True
    assert body["cancelled_at"] is not None


def test_cancelling_a_running_scan_only_requests_it(client):
    """The API must not claim a stop the scan has not yet made."""
    user_id = register(client)
    scan_id = insert_scan(user_id, status=ScanStatus.RUNNING)

    body = client.post(f"/api/scans/{scan_id}/cancel").json()

    assert body["status"] == "RUNNING"
    assert body["cancel_requested"] is True
    assert load(scan_id).status is ScanStatus.RUNNING


def test_a_running_scan_observes_the_request_and_stops(client, stub_scanner):
    """The cancel flag set by another request reaches the running scan."""
    user_id = register(client)
    scan_id = enqueue(user_id)

    def cancel_midway(scanner: StubScanner) -> None:
        client.post(f"/api/scans/{scan_id}/cancel")
        # The token is read with no throttle here because the flag is already set
        # and the token has not been consulted before.
        assert scanner.cancellation.cancelled is True
        StubScanner.report = make_report(cancelled=True)

    stub_scanner.on_scan = cancel_midway
    result = scan_service.execute_scan(scan_id)

    assert result.status is ScanStatus.CANCELLED


def test_cancelling_is_idempotent(client):
    user_id = register(client)
    scan_id = insert_scan(user_id, status=ScanStatus.QUEUED)

    first = client.post(f"/api/scans/{scan_id}/cancel")
    second = client.post(f"/api/scans/{scan_id}/cancel")

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["status"] == "CANCELLED"
    assert first.json()["cancelled_at"] == second.json()["cancelled_at"]


@pytest.mark.parametrize("status", [ScanStatus.COMPLETED, ScanStatus.FAILED])
def test_a_finished_scan_cannot_be_cancelled(client, status):
    """Reporting success would let a completed scan be presented as cancelled."""
    user_id = register(client)
    scan_id = insert_scan(user_id, status=status)

    response = client.post(f"/api/scans/{scan_id}/cancel")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "invalid_scan_transition"
    assert load(scan_id).status is status


def test_another_users_scan_cannot_be_cancelled(client):
    """404, never 403 — a 403 would confirm the id is real."""
    owner_id = register(client)
    scan_id = insert_scan(owner_id, status=ScanStatus.RUNNING)

    with TestClient(app) as other:
        register(other)
        response = other.post(f"/api/scans/{scan_id}/cancel")

    assert response.status_code == 404
    assert load(scan_id).cancel_requested is False


def test_cancelling_requires_authentication(client):
    user_id = register(client)
    scan_id = insert_scan(user_id, status=ScanStatus.RUNNING)

    with TestClient(app) as anonymous:
        response = anonymous.post(f"/api/scans/{scan_id}/cancel")

    assert response.status_code == 401
    assert load(scan_id).cancel_requested is False


def test_cancelling_an_unknown_scan_is_a_404(client):
    register(client)
    assert client.post(f"/api/scans/{uuid.uuid4()}/cancel").status_code == 404


# --------------------------------------------------------------------------- #
# Reporting a scan that did not finish
# --------------------------------------------------------------------------- #


def test_a_cancelled_scan_does_not_report_as_a_clean_pass(client):
    """The whole point: partial and complete must never look the same."""
    user_id = register(client)
    scan_id = insert_scan(
        user_id,
        status=ScanStatus.CANCELLED,
        endpoints_discovered=4,
        endpoints_analyzed=4,
        endpoints_skipped=0,
        endpoints_failed=0,
    )

    body = client.get(f"/api/scans/{scan_id}/report").json()

    assert body["metadata"]["status"] == "CANCELLED"
    assert body["metadata"]["is_conclusive"] is False
    # Counters alone would say "everything discovered was analysed"; the scan
    # having stopped early overrides that.
    assert body["coverage"]["scan_completed"] is False
    assert body["coverage"]["is_complete"] is False


def test_a_completed_scan_still_reports_as_conclusive(client):
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

    assert body["metadata"]["is_conclusive"] is True
    assert body["coverage"]["is_complete"] is True


def test_a_failed_scan_is_inconclusive_and_shows_its_stage(client):
    user_id = register(client)
    scan_id = insert_scan(
        user_id,
        status=ScanStatus.FAILED,
        error_message="The scan failed.",
        failure_stage=ScanStage.CRAWLING.value,
    )

    body = client.get(f"/api/scans/{scan_id}/report").json()

    assert body["metadata"]["is_conclusive"] is False
    assert body["metadata"]["failure_stage"] == "CRAWLING"


# --------------------------------------------------------------------------- #
# Dashboard counters
# --------------------------------------------------------------------------- #


def test_stats_expose_one_counter_per_status(client):
    user_id = register(client)
    insert_scan(user_id, status=ScanStatus.QUEUED)
    insert_scan(user_id, status=ScanStatus.CANCELLED)
    insert_scan(user_id, status=ScanStatus.COMPLETED)

    body = client.get("/api/scans/stats").json()

    assert body["queued"] == 1
    assert body["cancelled"] == 1
    assert body["completed"] == 1
    assert body["total"] == 3
    assert set(body) == {
        "total", "queued", "running", "completed", "failed", "cancelled"
    }


def test_scans_can_be_filtered_by_the_cancelled_status(client):
    user_id = register(client)
    insert_scan(user_id, status=ScanStatus.CANCELLED)
    insert_scan(user_id, status=ScanStatus.COMPLETED)

    body = client.get("/api/scans", params={"status": "CANCELLED"}).json()

    assert body["total"] == 1
    assert body["items"][0]["status"] == "CANCELLED"


# --------------------------------------------------------------------------- #
# Partial results survive a stop
# --------------------------------------------------------------------------- #


def test_a_cancelled_crawl_keeps_the_pages_it_reached():
    """Work already paid for is not thrown away when a scan is stopped."""
    from app.scanner.crawler.crawler import Crawler
    from app.scanner.crawler.types import CrawlConfig, FetchedPage, SkipReason

    origin = "https://partial.test"
    links = "".join(f'<a href="{origin}/p{n}">p{n}</a>' for n in range(6))
    fetched: list[str] = []
    stop_after = 3

    async def fetch(url: str) -> FetchedPage:
        fetched.append(url)
        return FetchedPage(
            url=url,
            status_code=200,
            content_type="text/html",
            body=f"<html><head><title>t</title></head><body>{links}</body></html>".encode(),
            is_html=True,
        )

    # Cancelled once enough pages have been fetched, mid-crawl.
    token = CancellationToken(lambda: len(fetched) >= stop_after)
    result = asyncio.run(Crawler(CrawlConfig(), fetch, token).crawl(f"{origin}/"))

    assert result.cancelled is True
    assert result.limit_reached is False  # a stop is not a budget being reached
    assert result.pages_crawled == stop_after
    assert len(result.endpoints) == stop_after
    assert len(result.responses) == stop_after
    # What was still queued is recorded, so the gap in coverage is visible.
    assert result.skip_reasons.get(SkipReason.CANCELLED.value, 0) > 0


def test_a_cancelled_scan_persists_the_partial_crawl(client, stub_scanner):
    """The partial crawl reaches the database rather than being discarded."""
    from app.scanner.crawler.types import CrawlResult, DiscoveredEndpoint

    crawl = CrawlResult(
        endpoints=[
            DiscoveredEndpoint(
                url=f"https://partial.test/p{n}",
                path=f"/p{n}",
                method="GET",
                depth=1,
                status_code=200,
                content_type="text/html",
            )
            for n in range(3)
        ],
        pages_crawled=3,
        pages_skipped=7,
        max_depth_reached=1,
        cancelled=True,
    )
    stub_scanner.report = make_report(cancelled=True, crawl=crawl)

    user_id = register(client)
    scan_id = enqueue(user_id)
    result = scan_service.execute_scan(scan_id)

    assert result.status is ScanStatus.CANCELLED
    assert result.pages_crawled == 3
    assert result.endpoints_discovered == 3

    body = client.get(f"/api/scans/{scan_id}/endpoints").json()
    assert len(body["items"]) == 3
