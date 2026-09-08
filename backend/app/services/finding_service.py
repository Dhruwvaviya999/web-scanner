"""Persistence and retrieval of scan findings.

The only place a detector's output becomes database rows. Detectors are pure
functions with no session, no models and no knowledge that a database exists.

Phase 5 persists *aggregated* findings: one row per finding identity, with a
`finding_occurrences` row for every endpoint the rule failed on.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.attack_surface import Endpoint
from app.models.finding import Finding, FindingOccurrence
from app.models.scan import Scan
from app.models.user import User
from app.scanner.analysis.types import AggregatedFinding
from app.scanner.security.types import FindingData, FindingSeverity
from app.services import scan_service


def replace_findings(
    db: Session,
    scan: Scan,
    findings: Sequence[AggregatedFinding],
    endpoints_by_url: Mapping[str, Endpoint] | None = None,
) -> list[Finding]:
    """Store `findings` as the complete set of findings for `scan`.

    Existing rows are removed first, so re-running a scan cannot leave stale
    observations behind. `endpoints_by_url` maps canonical endpoint URLs to the
    rows just persisted, which is how an occurrence gets its foreign key; a URL
    with no matching row still records its `endpoint_url` text, so the occurrence
    stays readable either way. The caller owns the transaction.
    """
    scan.findings.clear()
    db.flush()

    lookup = endpoints_by_url or {}
    rows: list[Finding] = []

    for group in findings:
        data = group.data
        primary_url = group.primary_endpoint_url
        primary = lookup.get(primary_url) if primary_url else None

        finding = Finding(
            scan_id=scan.id,
            rule_id=data.rule.value,
            subject=data.subject,
            title=data.title,
            category=data.category,
            severity=data.severity,
            confidence=data.confidence,
            description=data.description,
            evidence=data.evidence,
            impact=data.impact,
            remediation=data.remediation,
            endpoint_id=primary.id if primary is not None else None,
            occurrence_count=max(1, group.occurrence_count),
        )
        finding.occurrences = [
            FindingOccurrence(
                endpoint_id=(
                    lookup[o.endpoint_url].id
                    if o.endpoint_url and o.endpoint_url in lookup
                    else None
                ),
                endpoint_url=o.endpoint_url,
                evidence=o.evidence,
            )
            for o in group.occurrences
        ] or [
            # A finding with no recorded endpoint still gets one occurrence, so
            # the shape is uniform for every row.
            FindingOccurrence(endpoint_id=None, endpoint_url=None, evidence=data.evidence)
        ]
        db.add(finding)
        rows.append(finding)

    return rows


def replace_findings_from_data(
    db: Session, scan: Scan, findings: Sequence[FindingData]
) -> list[Finding]:
    """Persist ungrouped `FindingData`, one row each.

    Kept for callers that have no endpoint context — tests, and any future
    detector that runs before endpoints exist.
    """
    groups = [
        AggregatedFinding(data=data, occurrences=[]) for data in findings
    ]
    return replace_findings(db, scan, groups)


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
            .options(
                selectinload(Finding.occurrences),
                selectinload(Finding.endpoint),
            )
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
