"""Builds the canonical report from persisted scan rows.

Pure assembly: rows in, `ScanReport` out. No session of its own, no network, no
detector invocation. Everything it reports was already written by an earlier
phase — building a report cannot change what a scan concluded.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from app.models.api_surface import ApiDocument, ApiEndpointRow, split_list
from app.models.attack_surface import Endpoint, Form
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.reporting.types import (
    AttackSurfaceSummary,
    CategoryGroup,
    CoverageSummary,
    ReportApiDocument,
    ReportApiEndpoint,
    ReportApiSecurity,
    ReportApiParameter,
    ReportApiSurface,
    ReportAuthentication,
    ReportAuthorization,
    ReportEndpointRef,
    ReportFinding,
    ReportConfigSecurity,
    ReportMetadata,
    ReportSessionSecurity,
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
    api_endpoints: Sequence["ApiEndpointRow"] = (),
    api_documents: Sequence["ApiDocument"] = (),
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
        coverage=_coverage(scan, api_endpoints, api_documents),
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


def _api_surface(
    scan: Scan,
    api_endpoints: Sequence["ApiEndpointRow"],
    api_documents: Sequence["ApiDocument"],
) -> ReportApiSurface:
    """The API section, from the stored rows.

    Sorted deterministically by `(path, method)` so two builds of one scan are
    byte-identical, which is the guarantee the whole report rests on.
    """
    endpoints = tuple(
        sorted(
            (
                ReportApiEndpoint(
                    path=row.path,
                    method=row.method,
                    confidence=row.confidence,
                    sources=tuple(split_list(row.sources)),
                    auth_status=row.auth_status,
                    observed=bool(row.observed),
                    documented=bool(row.documented),
                    status_code=row.status_code,
                    request_media_type=row.request_media_type,
                    response_media_type=row.response_media_type,
                    operation_id=row.operation_id,
                    security=tuple(split_list(row.security)),
                    parameters=tuple(
                        sorted(
                            (
                                ReportApiParameter(
                                    name=parameter.name,
                                    location=parameter.location,
                                    required=parameter.required,
                                )
                                for parameter in row.parameters
                            ),
                            key=lambda p: (p.location, p.name),
                        )
                    ),
                    json_field_names=tuple(split_list(row.json_field_names)),
                    json_top_level=row.json_top_level,
                )
                for row in api_endpoints
            ),
            key=lambda e: e.sort_key,
        )
    )
    documents = tuple(
        sorted(
            (
                ReportApiDocument(
                    url=document.url,
                    version=document.version,
                    title=document.title,
                    path_count=document.path_count,
                    operation_count=document.operation_count,
                    security_schemes=tuple(split_list(document.security_schemes)),
                    truncated=bool(document.truncated),
                )
                for document in api_documents
            ),
            key=lambda d: d.url,
        )
    )

    return ReportApiSurface(
        detected=bool(scan.api_detected),
        endpoints_discovered=scan.api_endpoints_discovered or 0,
        endpoints_observed=scan.api_endpoints_observed or 0,
        endpoints_documented_only=scan.api_endpoints_documented_only or 0,
        parameters_discovered=scan.api_parameters_discovered or 0,
        authenticated_endpoints=scan.api_authenticated_endpoints or 0,
        unknown_auth_endpoints=scan.api_unknown_auth_endpoints or 0,
        openapi_documents=scan.api_document_count or 0,
        graphql_detected=bool(scan.api_graphql_detected),
        graphql_path=scan.api_graphql_path,
        graphql_introspection_tested=False,
        truncated=bool(scan.api_truncated),
        endpoints=endpoints,
        documents=documents,
    )


def _coverage(
    scan: Scan,
    api_endpoints: Sequence["ApiEndpointRow"] = (),
    api_documents: Sequence["ApiDocument"] = (),
) -> CoverageSummary:
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
        api=_api_surface(scan, api_endpoints, api_documents),
        api_security=_api_security(scan),
        session_security=_session_security(scan),
        config_security=_config_security(scan),
    )


def _api_security(scan: Scan) -> ReportApiSecurity:
    """API security coverage from the stored counters.

    `or 0` throughout: a NULL counter means the stage never reached that number,
    which for a report is the same as zero. `analyzed` is what separates "found
    nothing" from "was never asked to look".
    """
    return ReportApiSecurity(
        analyzed=bool(scan.api_sec_analyzed),
        endpoints_analyzed=scan.api_sec_endpoints_analyzed or 0,
        endpoints_skipped=scan.api_sec_endpoints_skipped or 0,
        responses_analyzed=scan.api_sec_responses_analyzed or 0,
        sensitive_fields_detected=scan.api_sec_sensitive_fields or 0,
        property_comparisons=scan.api_sec_property_comparisons or 0,
        verbose_errors=scan.api_sec_verbose_errors or 0,
        cors_checks=scan.api_sec_cors_checks or 0,
        inventory_observations=scan.api_sec_inventory_observations or 0,
        contexts_analyzed=scan.api_sec_contexts_analyzed or 0,
        unknown_policy=scan.api_sec_unknown_policy or 0,
        findings_count=scan.api_sec_findings or 0,
    )


def _session_security(scan: Scan) -> ReportSessionSecurity:
    """Session coverage from the stored counters.

    `or 0` throughout, as elsewhere: a NULL counter means the stage never
    reached that number, which for a report is the same as zero. `analyzed` is
    what separates "observed nothing" from "was never asked to look".
    """
    return ReportSessionSecurity(
        analyzed=bool(scan.session_analyzed),
        session_cookies_identified=scan.session_cookies_identified or 0,
        session_identifiers_in_urls=scan.session_identifiers_in_urls or 0,
        token_exposures=scan.session_token_exposures or 0,
        csrf_forms_analyzed=scan.session_csrf_forms_analyzed or 0,
        csrf_potential=scan.session_csrf_potential or 0,
        csrf_strong=scan.session_csrf_strong or 0,
        jwt_tokens_observed=scan.session_jwt_observed or 0,
        timeout_known=bool(scan.session_timeout_known),
        logout_endpoints_discovered=scan.session_logout_endpoints or 0,
        findings_count=scan.session_findings or 0,
    )


def _config_security(scan: Scan) -> ReportConfigSecurity:
    """Configuration coverage from the stored counters.

    `or 0` throughout, as elsewhere: a NULL counter means the stage never
    reached that number, which for a report is the same as zero. `analyzed` is
    what separates "observed nothing" from "was never asked to look".
    """
    return ReportConfigSecurity(
        analyzed=bool(scan.config_analyzed),
        https_used=bool(scan.config_https_used),
        https_redirect=bool(scan.config_https_redirect),
        hsts_observed=bool(scan.config_hsts_observed),
        method_observations=scan.config_method_observations or 0,
        debug_indicators=scan.config_debug_indicators or 0,
        sensitive_files_checked=scan.config_files_checked or 0,
        sensitive_files_exposed=scan.config_files_exposed or 0,
        admin_endpoints_discovered=scan.config_admin_endpoints or 0,
        management_endpoints_discovered=scan.config_management_endpoints or 0,
        directory_listings=scan.config_directory_listings or 0,
        source_maps=scan.config_source_maps or 0,
        technology_disclosures=scan.config_technology_disclosures or 0,
        path_normalization_observations=scan.config_path_observations or 0,
        candidates_not_tested=scan.config_candidates_not_tested or 0,
        requests_sent=scan.config_requests_sent or 0,
        findings_count=scan.config_findings or 0,
        budget_exhausted=bool(scan.config_budget_exhausted),
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
