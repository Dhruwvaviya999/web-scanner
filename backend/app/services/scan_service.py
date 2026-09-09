"""Scan lifecycle: enqueue, execute, cancel, list, fetch and delete.

This module is the only bridge between the isolated `app.scanner` package and
the database. Two rules shape everything below.

**No transaction spans network work.** A scan issues HTTP requests for as long
as the target and the budgets allow. Holding a session open across that would
pin a pooled connection and an idle-in-transaction row lock for the whole run,
so execution is split into separate units of work:

1. *enqueue* — insert the row as QUEUED and commit (the request's session).
2. *claim* — a conditional QUEUED -> RUNNING update in its own transaction. A
   scan that is not QUEUED is not claimed, which is what stops the same scan
   being executed twice.
3. *run* — no session at all. Progress writes and cancellation checks each open
   and close their own short-lived session.
4. *finish* — one transaction that writes the report, attack surface, findings
   and summary together, so a scan is never COMPLETED with results missing.

**Every status change goes through the state machine.** `scan_lifecycle`
decides what is legal; nothing here assigns a status without it.

**Authorization identities follow the same rule.** A scan may be given
several target identities to compare; each wraps a phase-11 authentication
context, and each is carried the same way — as an argument, never as a row.
Only labels and coverage counters are persisted.

**Target-authentication secrets never touch the database.** A credential the
user supplies for their own application arrives as an `AuthenticationContext`,
is passed down the call stack into the scanner, and is released when the call
returns. Only two facts about it are persisted: which mode was used and what one
initial access check concluded. See `app.scanner.auth`.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.errors import ConflictError, NotFoundError
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanner import CrawlConfig, ScannerConfig, ScanReport, WebScanner
from app.scanner.auth import AuthenticationContext, AuthMode, AuthStatus
from app.scanner.api.types import ApiDiscoveryConfig, ApiDiscoveryLimits
from app.scanner.api_security.types import ApiSecurityConfig, ApiSecurityLimits
from app.scanner.authorization import AuthorizationConfig, AuthorizationBudgetLimits
from app.scanner.authorization.matrix import AuthorizationPlan
from app.scanner.security.types import FindingSeverity
from app.scanner import ActiveScanConfig, ProbeBudgetLimits
from app.scanner.vulnerabilities.sqli.detector import SqlInjectionDetector
from app.scanner.vulnerabilities.xss.detector import ReflectedXssDetector
from app.schemas.scan import LABEL_SEPARATOR
from app.services import api_surface_service, attack_surface_service, finding_service
from app.services.cancellation import cancellation_token_for
from app.services.scan_lifecycle import (
    STAGE_MESSAGE,
    STAGE_PROGRESS,
    TERMINAL_STAGE,
    ScanStage,
    is_terminal,
    transition,
)

logger = logging.getLogger(__name__)

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 20

#: What the caller is told when a scan ends in an unexpected way. Deliberately
#: fixed text: the exception is logged with its traceback, but nothing derived
#: from it reaches a user-visible field, where it could carry a URL, a header,
#: a query value or an internal path.
UNEXPECTED_FAILURE_MESSAGE = "The scan stopped unexpectedly and did not complete."

#: Scanner module name -> lifecycle stage. The scanner reports the module it is
#: entering; translating that into a user-facing stage belongs here, because the
#: scanner package must not know what a "stage" means to the application.
MODULE_STAGE: dict[str, ScanStage] = {
    "http_probe": ScanStage.PROBING,
    "crawler": ScanStage.CRAWLING,
    "endpoint_analysis": ScanStage.ANALYZING,
    "api_discovery": ScanStage.API_DISCOVERY,
    "api_security": ScanStage.API_SECURITY,
    "active_scan": ScanStage.ANALYZING,
    "authorization": ScanStage.AUTHORIZATION,
}


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


def _api_config() -> ApiDiscoveryConfig:
    """Bounds for API reconnaissance.

    The candidate list stays at its module default: it is a fixed set of
    conventional paths, not a wordlist, and the setting caps how many of them
    are tried rather than supplying more.
    """
    return ApiDiscoveryConfig(
        enabled=settings.API_DISCOVERY_ENABLED,
        fetch_documents=settings.API_FETCH_DOCUMENTS,
        limits=ApiDiscoveryLimits(
            max_document_candidates=settings.API_MAX_DOCUMENT_CANDIDATES,
            max_parsed_paths=settings.API_MAX_PARSED_PATHS,
            max_endpoints=settings.API_MAX_ENDPOINTS,
            max_parameters_per_endpoint=settings.API_MAX_PARAMETERS_PER_ENDPOINT,
            max_json_fields=settings.API_MAX_JSON_FIELDS,
            max_json_depth=settings.API_MAX_JSON_DEPTH,
        ),
    )


def _api_security_config() -> ApiSecurityConfig:
    """Bounds for API security analysis.

    There is no request budget to spend here: the stage reads what earlier
    phases captured. The limits bound how much of that it retains.
    """
    return ApiSecurityConfig(
        enabled=settings.API_SECURITY_ENABLED,
        limits=ApiSecurityLimits(
            max_endpoints=settings.API_SECURITY_MAX_ENDPOINTS,
            max_fields_per_endpoint=settings.API_SECURITY_MAX_FIELDS_PER_ENDPOINT,
            max_property_comparisons=settings.API_SECURITY_MAX_PROPERTY_COMPARISONS,
        ),
        flag_plaintext_http=settings.API_SECURITY_FLAG_PLAINTEXT_HTTP,
    )


def _authorization_config() -> AuthorizationConfig:
    """Budgets for the authorization stage.

    The ceiling matters more here than anywhere else: cost is identities times
    endpoints, so a careless configuration is a load test against the target.
    """
    return AuthorizationConfig(
        enabled=settings.AUTHZ_ENABLED,
        limits=AuthorizationBudgetLimits(
            max_contexts=settings.AUTHZ_MAX_CONTEXTS,
            max_endpoints=settings.AUTHZ_MAX_ENDPOINTS,
            max_comparisons_per_endpoint=settings.AUTHZ_MAX_COMPARISONS_PER_ENDPOINT,
            max_requests=settings.AUTHZ_MAX_REQUESTS,
        ),
        equivalence_threshold=settings.AUTHZ_EQUIVALENCE_THRESHOLD,
    )


def _active_detectors() -> list:
    """The active detectors to run, gated by their per-detector enable flags.

    The shared budget and scope come from the active config; this only decides
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


# --------------------------------------------------------------------------- #
# Creating and running a scan
# --------------------------------------------------------------------------- #


class _StageTracker:
    """Persists coarse progress as the scanner moves between modules.

    Each write is its own short transaction — the scan holds no session while it
    works — and is conditional on the scan still being RUNNING, so a progress
    update can never resurrect a scan that has already stopped.
    """

    __slots__ = ("_scan_id", "current")

    def __init__(self, scan_id: uuid.UUID) -> None:
        self._scan_id = scan_id
        self.current: ScanStage = ScanStage.INITIALIZING

    def enter_module(self, module_name: str) -> None:
        """Callback handed to the scanner; called as each module begins."""
        stage = MODULE_STAGE.get(module_name)
        if stage is None or stage is self.current:
            return
        self.set(stage)

    def set(self, stage: ScanStage) -> None:
        self.current = stage
        try:
            with SessionLocal.begin() as db:
                scan = db.get(Scan, self._scan_id)
                if scan is None or scan.status is not ScanStatus.RUNNING:
                    return
                _set_stage(scan, stage)
        except Exception:  # noqa: BLE001 - progress is cosmetic, never fatal
            logger.debug(
                "Could not record stage %s for scan %s", stage.value, self._scan_id
            )


def create_scan(
    db: Session,
    user: User,
    target_url: str,
    authentication: AuthenticationContext | None = None,
    authorization: AuthorizationPlan | None = None,
) -> Scan:
    """Queue a scan, run it, and return the finished row.

    Execution is still inline — the request returns once the scan has stopped —
    but the request's session is committed and left alone for the duration, so
    moving `execute_scan` onto a worker later is a change of caller only.

    `authentication` is a live credential. It is passed as an argument rather
    than stored anywhere precisely so that its lifetime is the lifetime of this
    call: nothing holds a reference once the frame returns. Moving execution to
    a worker later would break that property, which is the honest reason this
    phase keeps execution inline.
    """
    auth = authentication or AuthenticationContext.none()
    plan = authorization or AuthorizationPlan()
    scan_id = enqueue_scan(db, user, target_url, auth.mode, plan)
    return execute_scan(scan_id, authentication=auth, authorization=plan)


def enqueue_scan(
    db: Session,
    user: User,
    target_url: str,
    auth_mode: AuthMode = AuthMode.NONE,
    authorization: AuthorizationPlan | None = None,
) -> uuid.UUID:
    """Unit of work 1: record the scan as QUEUED and commit.

    Returns the id rather than the instance: everything after this point uses
    its own session, and passing an id makes it impossible to keep using the
    request's session by accident while the scan runs.
    """
    scan = Scan(
        user_id=user.id,
        target_url=target_url,
        status=ScanStatus.QUEUED,
        queued_at=datetime.now(UTC),
        current_stage=ScanStage.QUEUED.value,
        progress_percent=STAGE_PROGRESS[ScanStage.QUEUED],
        progress_message=STAGE_MESSAGE[ScanStage.QUEUED],
        # The mode is known now; whether the credentials work is not, and is
        # written only once the initial access check has actually run.
        auth_mode=auth_mode.value,
        auth_status=AuthStatus.NOT_CONFIGURED.value,
        # Whether authorization testing was asked for is known now; what it
        # found is written only once the stage has actually run.
        authz_enabled=bool(authorization and authorization.enabled),
        authz_context_labels=_context_labels(authorization),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan.id


def execute_scan(
    scan_id: uuid.UUID,
    *,
    authentication: AuthenticationContext | None = None,
    authorization: AuthorizationPlan | None = None,
) -> Scan:
    """Run a queued scan to a terminal state and return the resulting row.

    Holds no session while the scanner works. Every failure path ends in a
    terminal status: a scan is never left RUNNING because something raised.

    Any authentication context lives only in this frame and in the scanner it
    creates. Nothing here writes it, logs it, or attaches it to the row that is
    returned.
    """
    target_url = _claim(scan_id)
    if target_url is None:
        # Not ours to run: already claimed, or cancelled before it started.
        return _load(scan_id)

    stage = _StageTracker(scan_id)
    try:
        report = WebScanner(
            _scanner_config(),
            crawl_config=_crawl_config(),
            active_config=_active_config(),
            detectors=_active_detectors(),
            cancellation=cancellation_token_for(scan_id),
            on_module_start=stage.enter_module,
            authentication=authentication,
            authz_config=_authorization_config(),
            authorization=authorization,
            api_config=_api_config(),
            api_security_config=_api_security_config(),
        ).scan_sync(target_url)
    except Exception:  # noqa: BLE001 - the scan must not be left RUNNING
        logger.exception("Scan %s raised while running", scan_id)
        _mark_failed(scan_id, stage.current)
        return _load(scan_id)

    try:
        return _finish(scan_id, report, stage)
    except Exception:  # noqa: BLE001 - persistence failed; the row must settle
        logger.exception("Scan %s raised while storing its result", scan_id)
        _mark_failed(scan_id, ScanStage.FINALIZING)
        return _load(scan_id)


def _claim(scan_id: uuid.UUID) -> str | None:
    """Unit of work 2: QUEUED -> RUNNING, atomically. Returns the target URL.

    The row is locked for the length of this short transaction — no network work
    happens inside it — so two callers cannot both observe QUEUED and both start
    the same scan. `None` means the scan was not claimable.
    """
    with SessionLocal.begin() as db:
        scan = db.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())
        if scan is None:
            raise NotFoundError("Scan not found.", code="scan_not_found")
        if scan.status is not ScanStatus.QUEUED:
            logger.info(
                "Scan %s not claimed: status is already %s", scan_id, scan.status.value
            )
            return None

        scan.status = transition(scan.status, ScanStatus.RUNNING)
        scan.started_at = datetime.now(UTC)
        _set_stage(scan, ScanStage.INITIALIZING)
        return scan.target_url


def _finish(scan_id: uuid.UUID, report: ScanReport, stage: _StageTracker) -> Scan:
    """Unit of work 4: write outcome, surface, findings and summary at once.

    One transaction, so a scan is never visible as COMPLETED while its findings
    are still missing.
    """
    with SessionLocal.begin() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError("Scan not found.", code="scan_not_found")

        _apply_probe(scan, report)
        _apply_authentication(scan, report)
        _apply_authorization(scan, report)

        # Order matters: endpoints must exist and be flushed before findings can
        # be linked to them, and the analysis outcome is recorded on those rows.
        endpoints_by_url = attack_surface_service.replace_attack_surface(db, scan, report.crawl)
        attack_surface_service.apply_analysis(db, endpoints_by_url, report.analysis)

        # After the attack surface exists, so an observed API operation can be
        # linked back to the crawl row it was seen on.
        api_surface_service.replace_api_surface(
            db, scan, report.api, endpoints_by_url
        )
        _apply_api_security(scan, report)

        aggregated = report.analysis.findings if report.analysis else []
        finding_service.replace_findings(db, scan, aggregated, endpoints_by_url)
        _apply_summary(scan, report)

        _finalize(scan, _outcome_of(report), report=report, failure_stage=stage.current)
        db.flush()
        db.refresh(scan)
        return scan


def _mark_failed(scan_id: uuid.UUID, stage: ScanStage | None) -> None:
    """Best-effort: settle a scan that raised, in a session of its own.

    Its own transaction, because the one that raised cannot be trusted and a
    rollback there would not undo the already-committed RUNNING status. Nothing
    derived from the exception is written to the row.
    """
    try:
        with SessionLocal.begin() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or is_terminal(scan.status):
                return
            _finalize(
                scan,
                ScanStatus.FAILED,
                error_message=UNEXPECTED_FAILURE_MESSAGE,
                failure_stage=stage,
            )
    except Exception:  # noqa: BLE001 - nothing further can be done here
        logger.exception("Could not mark scan %s as failed", scan_id)


def _load(scan_id: uuid.UUID) -> Scan:
    """Re-read a scan in its own session, for returning to the caller."""
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise NotFoundError("Scan not found.", code="scan_not_found")
        return scan


def _set_stage(scan: Scan, stage: ScanStage) -> None:
    scan.current_stage = stage.value
    scan.progress_percent = STAGE_PROGRESS[stage]
    scan.progress_message = STAGE_MESSAGE[stage]


def _outcome_of(report: ScanReport) -> ScanStatus:
    """Which terminal status a finished run corresponds to.

    Cancellation is checked first and is not a failure: the run stopped because
    it was asked to, and whatever it gathered before stopping is valid.
    """
    if report.cancelled:
        return ScanStatus.CANCELLED
    if report.succeeded and report.probe is not None:
        return ScanStatus.COMPLETED
    return ScanStatus.FAILED


def _finalize(
    scan: Scan,
    status: ScanStatus,
    *,
    report: ScanReport | None = None,
    error_message: str | None = None,
    failure_stage: ScanStage | None = None,
) -> None:
    """Move a scan to a terminal state. The only place a scan ever ends."""
    scan.status = transition(scan.status, status)
    stage = TERMINAL_STAGE[status]
    _set_stage(scan, stage)
    scan.completed_at = datetime.now(UTC)

    if status is ScanStatus.FAILED:
        message = error_message
        if message is None and report is not None:
            message = report.error_message
        scan.error_message = message or "The scan failed."
        scan.failure_stage = failure_stage.value if failure_stage else None
        logger.info(
            "Scan %s failed at %s: %s",
            scan.id,
            scan.failure_stage or "unknown",
            scan.error_message,
        )
        return

    # A scan that finished, or was stopped on request, carries no error text.
    scan.error_message = None
    scan.failure_stage = None
    if status is ScanStatus.CANCELLED and scan.cancelled_at is None:
        scan.cancelled_at = scan.completed_at


def _apply_authentication(scan: Scan, report: ScanReport) -> None:
    """Record how the scan authenticated, and what the access check concluded.

    Two short strings. There is deliberately no branch here that could copy a
    header, a token or a cookie onto the row — the report never carried one in
    the first place.
    """
    if report.auth is None:
        return
    scan.auth_mode = report.auth.mode.value
    scan.auth_status = report.auth.status.value


def _context_labels(plan: "AuthorizationPlan | None") -> str | None:
    """The identity labels, joined for storage. Names only, never credentials."""
    if plan is None or not plan.contexts:
        return None
    labels = LABEL_SEPARATOR.join(context.display_name for context in plan.contexts)
    return labels[:512] or None


def _apply_authorization(scan: Scan, report: ScanReport) -> None:
    """Record what the authorization stage compared.

    Counters only. The observations themselves carry a status, a length and a
    digest — never a body — and the findings they produced have already gone
    into the shared aggregation, so nothing else needs copying here.
    """
    outcome = report.authorization
    if outcome is None:
        return

    scan.authz_enabled = outcome.enabled
    if not outcome.enabled:
        return

    scan.authz_contexts = outcome.contexts
    scan.authz_endpoints_eligible = outcome.endpoints_eligible
    scan.authz_endpoints_tested = outcome.endpoints_tested
    scan.authz_comparisons = outcome.comparisons
    scan.authz_unknown = outcome.unknown
    scan.authz_skipped = outcome.skipped
    scan.authz_failed = outcome.failed
    if outcome.context_labels:
        scan.authz_context_labels = LABEL_SEPARATOR.join(outcome.context_labels)[:512]


def _apply_api_security(scan: Scan, report: ScanReport) -> None:
    """Record what the API security stage read.

    Counters only. The observations themselves carry field names, header values
    and signal categories — never a value, a credential or an excerpt — and the
    findings they produced have already gone into the shared aggregation.
    """
    result = report.api_security
    if result is None:
        return

    stats = result.stats
    scan.api_sec_analyzed = bool(stats.endpoints_analyzed or stats.responses_analyzed)
    scan.api_sec_endpoints_analyzed = stats.endpoints_analyzed
    scan.api_sec_endpoints_skipped = stats.endpoints_skipped
    scan.api_sec_responses_analyzed = stats.responses_analyzed
    scan.api_sec_sensitive_fields = stats.sensitive_fields_detected
    scan.api_sec_property_comparisons = stats.property_comparisons
    scan.api_sec_verbose_errors = stats.verbose_errors
    scan.api_sec_cors_checks = stats.cors_checks
    scan.api_sec_inventory_observations = stats.inventory_observations
    scan.api_sec_contexts_analyzed = stats.contexts_analyzed
    scan.api_sec_unknown_policy = stats.unknown_policy
    scan.api_sec_findings = stats.findings_count


def _apply_probe(scan: Scan, report: ScanReport) -> None:
    """Copy whatever the HTTP probe established onto the scan row.

    Written for a cancelled run too: partial results are kept, and the status —
    set separately by `_finalize` — is what says the run did not finish.
    """
    if report.probe is not None:
        probe = report.probe
        scan.http_status_code = probe.http_status_code
        scan.response_time_ms = probe.response_time_ms
        scan.final_url = probe.final_url
        scan.content_type = probe.content_type
        scan.server_header = probe.server_header
        scan.is_https = probe.is_https
        scan.redirect_count = probe.redirect_count
        scan.page_title = probe.page_title
        scan.content_length = probe.content_length
    elif report.target is not None:
        scan.is_https = report.target.is_https


def _apply_summary(scan: Scan, report: ScanReport) -> None:
    """Write the scan's denormalised coverage and severity counters.

    Deterministic: every number is derived from what the pipeline produced in
    this run, never from a previous scan or a heuristic. Counters stay NULL when
    the corresponding stage did not run, so "not attempted" remains
    distinguishable from "attempted and found nothing" — and a cancelled scan
    keeps whatever it did reach, which is how partial coverage stays visible.
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


# --------------------------------------------------------------------------- #
# Cancellation
# --------------------------------------------------------------------------- #


def cancel_scan(db: Session, user: User, scan_id: uuid.UUID) -> Scan:
    """Ask a scan to stop. Cooperative — nothing is killed.

    A QUEUED scan has not started, so it is cancelled outright. A RUNNING scan
    is only *asked*: the flag is set, and the run observes it at its next safe
    boundary and finalises itself. The row returned is the row as it actually
    is, so a caller is never told a running scan has already stopped.

    Idempotent for a scan that is already cancelled. Cancelling a scan that
    finished is a conflict rather than a no-op: reporting success there would
    let a completed scan be presented as cancelled.
    """
    scan = get_scan(db, user, scan_id)

    if scan.status is ScanStatus.CANCELLED:
        return scan
    if is_terminal(scan.status):
        raise ConflictError(
            f"A {scan.status.value.lower()} scan cannot be cancelled.",
            code="invalid_scan_transition",
        )

    now = datetime.now(UTC)
    scan.cancel_requested = True
    scan.cancelled_at = scan.cancelled_at or now

    if scan.status is ScanStatus.QUEUED:
        # Nothing is running, so there is nobody to observe the flag.
        _finalize(scan, ScanStatus.CANCELLED)
    else:
        scan.progress_message = "Stopping the scan."

    db.commit()
    db.refresh(scan)
    return scan


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #


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
