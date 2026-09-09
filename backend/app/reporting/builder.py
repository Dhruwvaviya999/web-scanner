"""Builds the canonical report from persisted scan rows.

Pure assembly: rows in, `ScanReport` out. No session of its own, no network, no
detector invocation. Everything it reports was already written by an earlier
phase — building a report cannot change what a scan concluded.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from app.models.attack_surface import Endpoint, Form
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.reporting.types import (
    AttackSurfaceSummary,
    CategoryGroup,
    CoverageSummary,
    ReportAuthentication,
    ReportAuthorization,
    ReportEndpointRef,
    ReportFinding,
    ReportMetadata,
    ScanReport,
    SeveritySummary,
    _SeverityTally,
)
from app.scanner.auth import AuthMode, AuthStatus
from app.scanner.security.types import FindingCategory


def build_report(
    scan: Scan,
    findings: Sequence[Finding],
    endpoints: Sequence[Endpoint],
    forms: Sequence[Form],
    *,
    generated_at: datetime | None = None,
) -> ScanReport:
    """Assemble the canonical report for one scan.

    `generated_at` is injectable so a test can pin it; everything else is
    derived from the stored rows, which is what makes two builds of the same
    scan identical.
    """
    report_findings = tuple(
        sorted(
            (_to_report_finding(finding) for finding in findings),
            key=lambda f: f.sort_key,
        )
    )

    return ScanReport(
        metadata=_metadata(scan, generated_at or datetime.now(UTC)),
        coverage=_coverage(scan),
        severity=_severity_summary(report_findings),
        attack_surface=_attack_surface(endpoints, forms),
        findings=report_findings,
        categories=_categories(report_findings),
        parameter_names=_parameter_names(endpoints),
    )


# --------------------------------------------------------------------------- #


def _metadata(scan: Scan, generated_at: datetime) -> ReportMetadata:
    duration: float | None = None
    if scan.started_at and scan.completed_at:
        duration = round((scan.completed_at - scan.started_at).total_seconds(), 3)

    return ReportMetadata(
        scan_id=str(scan.id),
        target_url=scan.target_url,
        final_url=scan.final_url,
        status=scan.status.value,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=duration,
        generated_at=generated_at,
        error_message=scan.error_message,
        cancelled_at=scan.cancelled_at,
        failure_stage=scan.failure_stage,
        # `or` covers a row that has not been flushed yet, where the column
        # default has not been applied: an unset mode means unauthenticated,
        # never "authenticated with an unknown mode".
        authentication=ReportAuthentication(
            mode=scan.auth_mode or AuthMode.NONE.value,
            status=scan.auth_status or AuthStatus.NOT_CONFIGURED.value,
        ),
    )


def _coverage(scan: Scan) -> CoverageSummary:
    return CoverageSummary(
        endpoints_discovered=scan.endpoints_discovered,
        endpoints_analyzed=scan.endpoints_analyzed,
        endpoints_skipped=scan.endpoints_skipped,
        endpoints_failed=scan.endpoints_failed,
        forms_discovered=scan.forms_discovered,
        parameters_discovered=scan.parameters_discovered,
        pages_crawled=scan.pages_crawled,
        pages_skipped=scan.pages_skipped,
        max_depth_reached=scan.max_depth_reached,
        crawl_limit_reached=scan.crawl_limit_reached,
        scan_completed=scan.status is ScanStatus.COMPLETED,
        authentication_usable=scan.auth_status != AuthStatus.REJECTED.value,
        authorization=_authorization(scan),
    )


def _authorization(scan: Scan) -> ReportAuthorization:
    """Authorization coverage from the stored counters.

    `or 0` throughout: a NULL counter means the stage did not reach that number,
    which for a report is the same as zero. `enabled` is what distinguishes
    "tested nothing" from "was never asked to test".
    """
    labels = tuple(
        label for label in (scan.authz_context_labels or "").split("\x1f") if label
    )
    return ReportAuthorization(
        enabled=bool(scan.authz_enabled),
        contexts=scan.authz_contexts or 0,
        context_labels=labels,
        endpoints_eligible=scan.authz_endpoints_eligible or 0,
        endpoints_tested=scan.authz_endpoints_tested or 0,
        comparisons=scan.authz_comparisons or 0,
        unknown=scan.authz_unknown or 0,
        skipped=scan.authz_skipped or 0,
        failed=scan.authz_failed or 0,
    )


def _to_report_finding(finding: Finding) -> ReportFinding:
    """Flatten one finding and its occurrences.

    Only fields the earlier phases already treat as safe to surface are copied.
    Occurrence URLs are the canonical endpoint URLs — parameter names, never
    values — so nothing sensitive travels with them.
    """
    endpoints: list[ReportEndpointRef] = []
    seen: set[str] = set()

    for occurrence in finding.occurrences:
        url = occurrence.endpoint_url
        if not url or url in seen:
            continue
        seen.add(url)
        linked = occurrence.endpoint
        endpoints.append(
            ReportEndpointRef(
                url=url,
                path=linked.path if linked is not None else None,
                method=linked.method if linked is not None else None,
            )
        )

    # The finding's own endpoint may not appear among its occurrences on rows
    # written before occurrences existed; include it so nothing is lost.
    if finding.endpoint is not None and finding.endpoint.url not in seen:
        endpoints.append(
            ReportEndpointRef(
                url=finding.endpoint.url,
                path=finding.endpoint.path,
                method=finding.endpoint.method,
            )
        )

    endpoints.sort(key=lambda ref: ref.url)

    return ReportFinding(
        rule_id=finding.rule_id,
        category=finding.category,
        severity=finding.severity,
        confidence=finding.confidence,
        title=finding.title,
        description=finding.description,
        impact=finding.impact,
        remediation=finding.remediation,
        evidence=finding.evidence,
        subject=finding.subject,
        occurrence_count=finding.occurrence_count,
        endpoints=tuple(endpoints),
    )


def _severity_summary(findings: Sequence[ReportFinding]) -> SeveritySummary:
    tally = _SeverityTally()
    for finding in findings:
        tally.add(finding.severity)
    return tally.summary()


def _categories(findings: Sequence[ReportFinding]) -> tuple[CategoryGroup, ...]:
    """Per-category totals, ordered by the category enum's declaration order."""
    tallies: dict[FindingCategory, _SeverityTally] = {}
    for finding in findings:
        tallies.setdefault(finding.category, _SeverityTally()).add(finding.severity)

    ordered = sorted(tallies.items(), key=lambda item: list(FindingCategory).index(item[0]))
    return tuple(
        CategoryGroup(category=category, total=tally.summary().total, severity=tally.summary())
        for category, tally in ordered
    )


def _attack_surface(
    endpoints: Sequence[Endpoint], forms: Sequence[Form]
) -> AttackSurfaceSummary:
    names = {
        parameter.name for endpoint in endpoints for parameter in endpoint.parameters
    }
    return AttackSurfaceSummary(
        endpoints=len(endpoints), forms=len(forms), parameters=len(names)
    )


def _parameter_names(endpoints: Sequence[Endpoint]) -> tuple[str, ...]:
    """Distinct discovered parameter names, sorted. Names only — never values."""
    names = {
        parameter.name for endpoint in endpoints for parameter in endpoint.parameters
    }
    return tuple(sorted(names))
