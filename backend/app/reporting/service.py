"""Report generation for one scan.

Read-only. Loads the rows a report needs and hands them to the builder. It
issues no writes, makes no network requests, and never invokes a detector — a
report is a view of what a scan already concluded.

Ownership goes through `scan_service.get_scan`, the same user-scoped lookup the
scan endpoints use, so another user's scan raises the identical 404 as one that
does not exist.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.attack_surface import Endpoint, Form
from app.models.finding import Finding, FindingOccurrence
from app.models.scan import Scan
from app.models.user import User
from app.reporting.builder import build_report
from app.reporting.types import ScanReport
from app.services import scan_service


def generate_report(
    db: Session,
    user: User,
    scan_id: uuid.UUID,
    *,
    generated_at: datetime | None = None,
) -> ScanReport:
    """Build the canonical report for a scan the user owns."""
    scan = scan_service.get_scan(db, user, scan_id)
    return build_report(
        scan,
        _load_findings(db, scan),
        _load_endpoints(db, scan),
        _load_forms(db, scan),
        generated_at=generated_at,
    )


def _load_findings(db: Session, scan: Scan) -> list[Finding]:
    """Findings with their occurrences and endpoints eagerly loaded.

    Eager loading keeps report generation to a handful of queries regardless of
    how many findings a scan produced. Ordering here is incidental — the builder
    sorts deterministically rather than trusting row order.
    """
    return list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan.id)
            .options(
                selectinload(Finding.occurrences).selectinload(FindingOccurrence.endpoint),
                selectinload(Finding.endpoint),
            )
        )
    )


def _load_endpoints(db: Session, scan: Scan) -> list[Endpoint]:
    return list(
        db.scalars(
            select(Endpoint)
            .where(Endpoint.scan_id == scan.id)
            .options(selectinload(Endpoint.parameters))
        )
    )


def _load_forms(db: Session, scan: Scan) -> list[Form]:
    return list(db.scalars(select(Form).where(Form.scan_id == scan.id)))
