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
from app.schemas.common import NOT_FOUND_RESPONSE, UNAUTHORIZED_RESPONSE
from app.schemas.scan import ScanCreate, ScanListResponse, ScanRead, ScanStats
from app.services import scan_service

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


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete one scan",
    responses=NOT_FOUND_RESPONSE,
)
def delete_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession) -> Response:
    scan_service.delete_scan(db, current_user, scan_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
