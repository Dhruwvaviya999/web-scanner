"""Persistence and retrieval of scan findings.

This is the only place where a detector's output becomes database rows. The
detectors themselves are pure functions with no session, no models and no
knowledge that a database exists.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.scanner.security.types import FindingData, FindingSeverity
from app.services import scan_service


def replace_findings(db: Session, scan: Scan, findings: Sequence[FindingData]) -> list[Finding]:
    """Store `findings` as the complete set of findings for `scan`.

    Existing rows for the scan are removed first, so re-running a scan cannot
    leave stale observations behind. The caller owns the transaction.
    """
    scan.findings.clear()
    db.flush()

    rows = [
        Finding(
            scan_id=scan.id,
            code=data.code,
            title=data.title,
            category=data.category,
            severity=data.severity,
            confidence=data.confidence,
            description=data.description,
            evidence=data.evidence,
            impact=data.impact,
            remediation=data.remediation,
        )
        for data in findings
    ]
    db.add_all(rows)
    return rows


def list_findings_for_scan(db: Session, user: User, scan_id: uuid.UUID) -> list[Finding]:
    """Findings for one scan the user owns, most severe first.

    Ownership is resolved through `scan_service.get_scan`, which scopes its
    query to the user — so a scan belonging to somebody else raises the same
    404 as one that does not exist, and its findings are never reachable.
    """
    scan = scan_service.get_scan(db, user, scan_id)
    return list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan.id)
            # The native enum sorts in declaration order: CRITICAL first.
            .order_by(Finding.severity, Finding.title)
        )
    )


def summarize(findings: Sequence[Finding]) -> dict[str, int]:
    """Count findings by severity, including the severities with no findings."""
    counts = {severity.value.lower(): 0 for severity in FindingSeverity}
    for finding in findings:
        counts[finding.severity.value.lower()] += 1
    counts["total"] = len(findings)
    return counts
