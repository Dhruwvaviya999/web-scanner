"""Scan lifecycle: create, run, list, fetch and delete.

This module is the only bridge between the isolated `app.scanner` package and
the database. When the scanner grows a crawler and a findings pipeline, the
translation from `ScanReport` to ORM rows changes here and nowhere else.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import NotFoundError
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner import CrawlConfig, ScannerConfig, ScanReport, WebScanner
from app.scanner.security.types import FindingSeverity
from app.scanner import ActiveScanConfig, ProbeBudgetLimits
from app.scanner.vulnerabilities.sqli.detector import SqlInjectionDetector
from app.scanner.vulnerabilities.xss.detector import ReflectedXssDetector
from app.services import attack_surface_service, finding_service

logger = logging.getLogger(__name__)

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 20


def _scanner_config() -> ScannerConfig:
    return ScannerConfig(
        timeout_seconds=settings.SCANNER_TIMEOUT_SECONDS,
        total_timeout_seconds=settings.SCANNER_TOTAL_TIMEOUT_SECONDS,
        max_redirects=settings.SCANNER_MAX_REDIRECTS,
        max_response_bytes=settings.SCANNER_MAX_RESPONSE_BYTES,
        user_agent=settings.SCANNER_USER_AGENT,
        allow_private_networks=settings.SCANNER_ALLOW_PRIVATE_NETWORKS,
    )


def _crawl_config() -> CrawlConfig:
    return CrawlConfig(
        enabled=settings.CRAWLER_ENABLED,
        max_pages=settings.CRAWLER_MAX_PAGES,
        max_depth=settings.CRAWLER_MAX_DEPTH,
        time_budget_seconds=settings.CRAWLER_TIME_BUDGET_SECONDS,
        max_redirects_per_page=settings.CRAWLER_MAX_REDIRECTS_PER_PAGE,
    )


def _active_config() -> ActiveScanConfig:
    """Budgets for the active-probe stage, shared by every detector."""
    return ActiveScanConfig(
        enabled=settings.ACTIVE_SCAN_ENABLED,
        limits=ProbeBudgetLimits(
            per_parameter=settings.MAX_ACTIVE_PROBES_PER_PARAMETER,
            per_endpoint=settings.MAX_ACTIVE_PROBES_PER_ENDPOINT,
            per_scan=settings.MAX_ACTIVE_PROBES_PER_SCAN,
        ),
        max_targets=settings.ACTIVE_SCAN_MAX_TARGETS,
    )


def _active_detectors() -> list:
    """The active detectors to run, gated by their per-detector enable flags.

    The shared budget and scope come from `_active_config`; this only decides
    which detectors participate. Order is not significant — they share one
    budget and produce deterministic findings independently.
    """
    detectors: list = []
    if settings.XSS_ENABLED:
        detectors.append(
            ReflectedXssDetector(
                max_parameters_per_endpoint=settings.XSS_MAX_PARAMETERS_PER_ENDPOINT
            )
        )
    if settings.SQLI_ENABLED:
        detectors.append(
            SqlInjectionDetector(
                max_parameters_per_endpoint=settings.SQLI_MAX_PARAMETERS_PER_ENDPOINT
            )
        )
    return detectors


def create_scan(db: Session, user: User, target_url: str) -> Scan:
    """Persist a scan, run the probe, then store the outcome.

    Phase 1 runs the probe inline: the request returns once the scan has
    finished. The PENDING -> RUNNING -> COMPLETED/FAILED transitions are already
    modelled so that moving execution to a background worker later is a change
    of caller, not of schema.
    """
    scan = Scan(user_id=user.id, target_url=target_url, status=ScanStatus.PENDING)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(UTC)
    db.commit()

    report = WebScanner(
        _scanner_config(),
        crawl_config=_crawl_config(),
        active_config=_active_config(),
        detectors=_active_detectors(),
    ).scan_sync(target_url)
    _apply_report(scan, report)

    # Findings are written in the same transaction as the scan result, so a
    # scan is never left COMPLETED with its findings missing.
    # Order matters: endpoints must exist and be flushed before findings can be
    # linked to them, and the analysis outcome is recorded onto those same rows.
    endpoints_by_url = attack_surface_service.replace_attack_surface(db, scan, report.crawl)
    attack_surface_service.apply_analysis(db, endpoints_by_url, report.analysis)

    aggregated = report.analysis.findings if report.analysis else []
    finding_service.replace_findings(db, scan, aggregated, endpoints_by_url)
    _apply_summary(scan, report)

    scan.completed_at = datetime.now(UTC)
    db.commit()
    db.refresh(scan)
    return scan


def _apply_summary(scan: Scan, report: ScanReport) -> None:
    """Write the scan's denormalised coverage and severity counters.

    Deterministic: every number is derived from what the pipeline produced in
    this run, never from a previous scan or a heuristic. Counters stay NULL when
    the corresponding stage did not run, so "not attempted" remains
    distinguishable from "attempted and found nothing".
    """
    if report.crawl is not None:
        scan.endpoints_discovered = len(report.crawl.endpoints)
        scan.forms_discovered = len(report.crawl.forms)
        # Distinct names: one parameter seen on five endpoints is one input.
        scan.parameters_discovered = len(
            {name for endpoint in report.crawl.endpoints for name in endpoint.parameters}
        )

    if report.analysis is not None:
        scan.endpoints_analyzed = report.analysis.analyzed
        scan.endpoints_skipped = report.analysis.skipped
        scan.endpoints_failed = report.analysis.failed

        counts = {severity: 0 for severity in FindingSeverity}
        for group in report.analysis.findings:
            counts[group.data.severity] += 1

        scan.total_findings = len(report.analysis.findings)
        scan.critical_count = counts[FindingSeverity.CRITICAL]
        scan.high_count = counts[FindingSeverity.HIGH]
        scan.medium_count = counts[FindingSeverity.MEDIUM]
        scan.low_count = counts[FindingSeverity.LOW]
        scan.info_count = counts[FindingSeverity.INFO]


def _apply_report(scan: Scan, report: ScanReport) -> None:
    """Copy a scanner report onto the scan row."""
    if report.succeeded and report.probe is not None:
        probe = report.probe
        scan.status = ScanStatus.COMPLETED
        scan.http_status_code = probe.http_status_code
        scan.response_time_ms = probe.response_time_ms
        scan.final_url = probe.final_url
        scan.content_type = probe.content_type
        scan.server_header = probe.server_header
        scan.is_https = probe.is_https
        scan.redirect_count = probe.redirect_count
        scan.page_title = probe.page_title
        scan.content_length = probe.content_length
        scan.error_message = None
        return

    scan.status = ScanStatus.FAILED
    scan.error_message = report.error_message or "The scan failed."
    if report.target is not None:
        scan.is_https = report.target.is_https
    logger.info(
        "Scan %s failed: code=%s message=%s",
        scan.id,
        report.error_code.value if report.error_code else "unknown",
        scan.error_message,
    )


def list_scans(
    db: Session,
    user: User,
    *,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
    status: ScanStatus | None = None,
) -> tuple[list[Scan], int]:
    """Return `(page_of_scans, total_matching)` for this user only."""
    limit = max(1, min(limit, MAX_PAGE_SIZE))
    offset = max(0, offset)

    filters = [Scan.user_id == user.id]
    if status is not None:
        filters.append(Scan.status == status)

    total = db.scalar(select(func.count()).select_from(Scan).where(*filters)) or 0
    items = list(
        db.scalars(
            select(Scan)
            .where(*filters)
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    return items, total


def get_scan(db: Session, user: User, scan_id: uuid.UUID) -> Scan:
    """Fetch one scan owned by `user`.

    The owner filter is part of the query rather than a check afterwards, so a
    scan belonging to somebody else is indistinguishable from one that does not
    exist (404, never 403 — that would confirm the id is real).
    """
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if scan is None:
        raise NotFoundError("Scan not found.", code="scan_not_found")
    return scan


def delete_scan(db: Session, user: User, scan_id: uuid.UUID) -> None:
    scan = get_scan(db, user, scan_id)
    db.delete(scan)
    db.commit()


def get_scan_stats(db: Session, user: User) -> dict[str, int]:
    """Count this user's scans grouped by status, in a single query."""
    rows = db.execute(
        select(Scan.status, func.count())
        .where(Scan.user_id == user.id)
        .group_by(Scan.status)
    ).all()

    counts = {status.value.lower(): 0 for status in ScanStatus}
    for status, count in rows:
        counts[status.value.lower()] = count
    counts["total"] = sum(counts.values())
    return counts
