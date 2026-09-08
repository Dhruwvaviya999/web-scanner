"""Scan management endpoints.

Every handler resolves the scan through `scan_service`, which scopes each query
to the authenticated user. A scan id supplied by the client is therefore never
sufficient on its own to read or delete a record.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Response, status

from app.core.deps import CurrentUser, DbSession
from app.models.scan import ScanStatus
from app.schemas.attack_surface import (
    AttackSurfaceSummary,
    EndpointListResponse,
    EndpointRead,
    FormListResponse,
    FormRead,
)
from app.schemas.common import (
    CONFLICT_RESPONSE,
    NOT_FOUND_RESPONSE,
    UNAUTHORIZED_RESPONSE,
)
from app.schemas.report import ScanReportRead
from app.schemas.finding import FindingListResponse, FindingRead, FindingSummary
from app.schemas.scan import ScanCreate, ScanListResponse, ScanRead, ScanStats
from app.reporting import service as reporting_service
from app.services import attack_surface_service, finding_service, scan_service

router = APIRouter(prefix="/scans", tags=["scans"], responses=UNAUTHORIZED_RESPONSE)


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create and run a scan",
)
def create_scan(payload: ScanCreate, current_user: CurrentUser, db: DbSession) -> ScanRead:
    """Run a basic HTTP probe against the target and store the result.

    The probe runs inline, so this request takes as long as the target takes to
    respond (bounded by `SCANNER_TOTAL_TIMEOUT_SECONDS`). A target that is
    unreachable produces a FAILED scan, not an error response — the scan record
    itself is the result.
    """
    scan = scan_service.create_scan(db, current_user, payload.target_url)
    return ScanRead.model_validate(scan)


@router.get("", response_model=ScanListResponse, summary="List the caller's scans")
def list_scans(
    current_user: CurrentUser,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=scan_service.MAX_PAGE_SIZE)] = scan_service.DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0)] = 0,
    status_filter: Annotated[ScanStatus | None, Query(alias="status")] = None,
) -> ScanListResponse:
    items, total = scan_service.list_scans(
        db, current_user, limit=limit, offset=offset, status=status_filter
    )
    return ScanListResponse(
        items=[ScanRead.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


# Declared before "/{scan_id}" so the literal path is matched first.
@router.get("/stats", response_model=ScanStats, summary="Scan counters for the dashboard")
def read_scan_stats(current_user: CurrentUser, db: DbSession) -> ScanStats:
    return ScanStats(**scan_service.get_scan_stats(db, current_user))


@router.get(
    "/{scan_id}",
    response_model=ScanRead,
    summary="Read one scan",
    responses=NOT_FOUND_RESPONSE,
)
def read_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession) -> ScanRead:
    scan = scan_service.get_scan(db, current_user, scan_id)
    return ScanRead.model_validate(scan)


@router.get(
    "/{scan_id}/findings",
    response_model=FindingListResponse,
    summary="Security findings for one scan",
    responses=NOT_FOUND_RESPONSE,
)
def read_scan_findings(
    scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession
) -> FindingListResponse:
    """Findings for a scan the caller owns, most severe first.

    Ownership is enforced by the same user-scoped lookup the scan endpoints
    use, so another user's scan id yields 404 rather than exposing findings.
    A scan with nothing to report returns an empty list, which is not the
    same as the target being secure.
    """
    findings = finding_service.list_findings_for_scan(db, current_user, scan_id)
    return FindingListResponse(
        items=[FindingRead.model_validate(f) for f in findings],
        summary=FindingSummary(**finding_service.summarize(findings)),
    )


@router.get(
    "/{scan_id}/endpoints",
    response_model=EndpointListResponse,
    summary="Endpoints discovered by the crawler",
    responses=NOT_FOUND_RESPONSE,
)
def read_scan_endpoints(
    scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession
) -> EndpointListResponse:
    """URLs the crawler reached, with their query parameter names.

    Stored URLs are canonical: parameter names are kept and their values
    removed, so nothing sensitive from a query string is exposed here.
    """
    endpoints = attack_surface_service.list_endpoints(db, current_user, scan_id)
    scan = scan_service.get_scan(db, current_user, scan_id)
    return EndpointListResponse(
        items=[EndpointRead.model_validate(e) for e in endpoints],
        summary=AttackSurfaceSummary(
            **attack_surface_service.summarize(db, scan),
            endpoints_analyzed=scan.endpoints_analyzed,
            endpoints_skipped=scan.endpoints_skipped,
            endpoints_failed=scan.endpoints_failed,
        ),
    )


@router.get(
    "/{scan_id}/forms",
    response_model=FormListResponse,
    summary="Forms discovered by the crawler",
    responses=NOT_FOUND_RESPONSE,
)
def read_scan_forms(
    scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession
) -> FormListResponse:
    """Forms found on crawled pages, with their field names and types.

    Discovery only — no form was ever submitted, and no field value is stored.
    """
    forms = attack_surface_service.list_forms(db, current_user, scan_id)
    return FormListResponse(
        items=[FormRead.model_validate(f) for f in forms], total=len(forms)
    )


@router.get(
    "/{scan_id}/report",
    response_model=ScanReportRead,
    summary="Canonical security report for one scan",
    responses=NOT_FOUND_RESPONSE,
)
def read_scan_report(
    scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession
) -> ScanReportRead:
    """The full report for a scan the caller owns.

    Read-only: generated from data the scan already persisted. It issues no
    requests to the target and re-runs no detector, so calling it repeatedly is
    free of side effects and yields an identical document each time.
    """
    report = reporting_service.generate_report(db, current_user, scan_id)
    return ScanReportRead.model_validate(report)


@router.get(
    "/{scan_id}/report/json",
    response_model=ScanReportRead,
    summary="The same report as a downloadable JSON file",
    responses=NOT_FOUND_RESPONSE,
)
def download_scan_report(
    scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession
) -> Response:
    """The canonical report with a Content-Disposition attachment header.

    Identical content to `/report` — the only difference is that a browser saves
    it rather than rendering it, so the two can never drift.
    """
    report = reporting_service.generate_report(db, current_user, scan_id)
    payload = ScanReportRead.model_validate(report)
    return Response(
        content=payload.model_dump_json(indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan_id}-report.json"'
        },
    )


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanRead,
    summary="Ask a running scan to stop",
    responses={**NOT_FOUND_RESPONSE, **CONFLICT_RESPONSE},
)
def cancel_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession) -> ScanRead:
    """Request cancellation of a scan the caller owns.

    Cancellation is cooperative: nothing is killed. A queued scan stops
    immediately because it has not started; a running scan is asked to stop and
    winds down at its next safe boundary, keeping whatever it has gathered.

    The response is the scan as it stands right now — a running scan comes back
    with `cancel_requested` true and status still RUNNING, so a client can never
    report a stop that has not happened yet. Cancelling an already-cancelled
    scan succeeds; cancelling one that has finished is a 409.
    """
    scan = scan_service.cancel_scan(db, current_user, scan_id)
    return ScanRead.model_validate(scan)


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete one scan",
    responses=NOT_FOUND_RESPONSE,
)
def delete_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession) -> Response:
    scan_service.delete_scan(db, current_user, scan_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
