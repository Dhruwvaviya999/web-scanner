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
from app.core.errors import UnprocessableEntityError
from app.models.scan import ScanStatus
from app.scanner.auth import AuthConfigError, AuthenticationContext, AuthMode
from app.scanner.auth.context import build_context
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
from app.schemas.scan import (
    ScanCreateWithAuth,
    ScanListResponse,
    ScanRead,
    ScanStats,
)
from app.reporting import service as reporting_service
from app.services import attack_surface_service, finding_service, scan_service

router = APIRouter(prefix="/scans", tags=["scans"], responses=UNAUTHORIZED_RESPONSE)


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create and run a scan",
)
def create_scan(
    payload: ScanCreateWithAuth, current_user: CurrentUser, db: DbSession
) -> ScanRead:
    """Run a scan against the target and store the result.

    The scan runs inline, so this request takes as long as the target takes to
    respond (bounded by `SCANNER_TOTAL_TIMEOUT_SECONDS`). A target that is
    unreachable produces a FAILED scan, not an error response — the scan record
    itself is the result.

    Optionally carries target-authentication material, which is a different
    thing from the session that authorises this request: `current_user` says who
    is asking, while `payload.authentication` is a credential that user holds
    for the application they are asking the scanner to test. It is turned into
    an in-memory context here, used for the scan, and never persisted or
    returned — `ScanRead` can only express the mode and a status.
    """
    authentication = _authentication_context(payload)
    scan = scan_service.create_scan(
        db, current_user, payload.target_url, authentication=authentication
    )
    return ScanRead.model_validate(scan)


def _authentication_context(payload: ScanCreateWithAuth) -> AuthenticationContext:
    """Turn validated request material into a scoped, in-memory auth context.

    Bound to the origin of the URL being scanned, so the credential cannot be
    sent anywhere else — including wherever the target might try to redirect the
    scan. A malformed context is a 422 on the request, not a failed scan.
    """
    auth = payload.authentication
    if auth is None or auth.mode is AuthMode.NONE:
        return AuthenticationContext.none()

    try:
        return build_context(
            auth.mode,
            payload.target_url,
            token=auth.token.get_secret_value() if auth.token else None,
            cookies=[(c.name, c.value.get_secret_value()) for c in auth.cookies],
        )
    except AuthConfigError as exc:
        # The message describes the problem with the material, never the
        # material itself — see `scanner.auth.validation`.
        raise UnprocessableEntityError(
            str(exc),
            code="invalid_authentication",
            details=[{"field": "authentication", "message": str(exc)}],
        ) from exc


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
