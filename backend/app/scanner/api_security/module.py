"""The scan module that reads API security weaknesses out of what was fetched.

**It sends nothing.** Every input already exists by the time this stage runs:
the field names Phase 13 summarised, the headers the crawler kept, the error
signals computed at capture, and the per-context responses Phase 12 gathered
while comparing access. A stage that generated traffic to find these things
would be fuzzing, and this phase does not fuzz.

That constraint shapes the whole module. It cannot ask an endpoint a question;
it can only notice what the endpoint already said. Where the evidence is thin
the result is an observation and a counter, not a finding — and on a real target
most of it is thin, because whether an API *should* return a given field depends
on what the application is for.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence

from app.scanner.analysis.aggregator import aggregate_findings
from app.scanner.api.types import ApiEndpoint, ApiSurface
from app.scanner.api_security import findings as build
from app.scanner.api_security.configuration import (
    analyze_cors,
    analyze_disclosure,
    analyze_inventory,
)
from app.scanner.api_security.error_analyzer import analyze as analyze_error
from app.scanner.api_security.response_analyzer import analyze_fields, compare_properties
from app.scanner.api_security.types import (
    ApiSecurityConfig,
    ApiSecurityResult,
    ApiSecurityStats,
    CorsObservation,
    DisclosureObservation,
    ErrorObservation,
    ExposureVerdict,
    InventoryObservation,
    PropertyComparison,
    SensitiveFieldObservation,
)
from app.scanner.authorization.matrix import AuthorizationPlan
from app.scanner.authorization.types import AccessExpectation
from app.scanner.cancellation import CancellationToken
from app.scanner.crawler.types import CapturedResponse
from app.scanner.security.types import FindingData
from app.scanner.types import ScannerConfig, ScanReport, ScanTarget

logger = logging.getLogger(__name__)

#: The identity a plain scan runs as, when no authorization contexts were given.
_SCAN_CONTEXT_ID = "scan"


class ApiSecurityModule:
    """Reads API weaknesses from responses earlier stages already captured."""

    name = "api_security"

    def __init__(
        self,
        config: ScannerConfig,
        security_config: ApiSecurityConfig | None = None,
        cancellation: CancellationToken | None = None,
        authorization: AuthorizationPlan | None = None,
        authenticated: bool = False,
    ) -> None:
        self._config = config
        self._security_config = security_config or ApiSecurityConfig()
        self._cancellation = cancellation or CancellationToken.none()
        self._authorization = authorization or AuthorizationPlan()
        self._authenticated = authenticated

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        if not self._security_config.enabled or report.api is None:
            report.api_security = ApiSecurityResult()
            return

        stats = ApiSecurityStats()
        limits = self._security_config.limits

        captured = report.crawl.responses if report.crawl is not None else {}
        endpoints = list(report.api.endpoints)[: limits.max_endpoints]

        sensitive: list[SensitiveFieldObservation] = []
        errors: list[ErrorObservation] = []
        cors: list[CorsObservation] = []
        disclosures: list[DisclosureObservation] = []

        for endpoint in endpoints:
            # Between endpoints. Nothing is in flight — this stage sends no
            # request — but a cancelled scan should stop working all the same.
            self._cancellation.raise_if_cancelled(self.name)

            if not endpoint.observed or endpoint.url is None:
                # Documented only: there is no response to read, and inventing a
                # request to get one would make this an active phase.
                stats.endpoints_skipped += 1
                continue

            stats.endpoints_analyzed += 1
            response = captured.get(endpoint.url)

            sensitive.extend(self._fields_for(endpoint, stats))

            if response is not None:
                stats.responses_analyzed += 1
                errors.extend(self._errors_for(endpoint, response, stats))
                cors.append(self._cors_for(endpoint, response, stats))
                disclosures.extend(self._disclosures_for(endpoint, response, stats))

        comparisons = self._property_comparisons(report, stats)
        inventory = self._inventory(report.api, stats)

        stats.sensitive_fields_detected = len(sensitive)
        stats.property_comparisons = len(comparisons)
        stats.verbose_errors = len(errors)
        stats.unknown_policy = sum(
            1
            for observation in sensitive
            if observation.verdict is ExposureVerdict.UNKNOWN_POLICY
        ) + sum(
            1
            for comparison in comparisons
            if comparison.verdict is ExposureVerdict.UNKNOWN_POLICY
        )

        emitted = _findings_from(sensitive, comparisons, errors, cors, disclosures, inventory)
        stats.findings_count = len(emitted)

        report.api_security = ApiSecurityResult(
            sensitive_fields=tuple(sensitive),
            property_comparisons=tuple(comparisons),
            errors=tuple(errors),
            cors=tuple(observation for observation in cors if observation.unsafe),
            disclosures=tuple(disclosures),
            inventory=tuple(inventory),
            stats=stats,
        )
        _record(report, emitted)

    # ------------------------------------------------------------------ #

    def _policy(self, context_id: str, url: str) -> tuple[bool, bool]:
        """`(resource_denied, policy_declared)` from the Phase 12 matrix.

        Reusing that matrix rather than inventing a second one is the point: a
        property finding rests on the same declared policy a resource finding
        does, so the two can never disagree about what the user asked for.
        """
        matrix = self._authorization.matrix
        if not matrix.configured:
            return (False, False)
        expectation = matrix.expectation_for(context_id, url)
        return (
            expectation is AccessExpectation.DENIED,
            expectation is not AccessExpectation.UNKNOWN,
        )

    def _fields_for(
        self, endpoint: ApiEndpoint, stats: ApiSecurityStats
    ) -> Sequence[SensitiveFieldObservation]:
        """Sensitive fields in the response the scanning identity received."""
        shape = endpoint.json_shape
        if shape is None or not shape.field_names:
            return ()

        url = endpoint.url or endpoint.path
        denied, declared = self._policy(_SCAN_CONTEXT_ID, url)

        return analyze_fields(
            url=url,
            method=endpoint.method,
            context_id=_SCAN_CONTEXT_ID,
            context_label="scan identity" if self._authenticated else "anonymous",
            field_names=shape.field_names,
            anonymous=not self._authenticated,
            status_code=endpoint.status_code,
            resource_denied=denied,
            policy_declared=declared,
            limit=self._security_config.limits.max_fields_per_endpoint,
        )

    def _errors_for(
        self,
        endpoint: ApiEndpoint,
        response: CapturedResponse,
        stats: ApiSecurityStats,
    ) -> Sequence[ErrorObservation]:
        signals = getattr(response, "error_signals", ()) or ()
        if not signals:
            return ()
        observation = analyze_error(
            url=endpoint.url or endpoint.path,
            method=endpoint.method,
            status_code=response.status_code,
            content_type=response.content_type,
            signals=tuple(signals),
            body_length=0,
        )
        return (observation,) if observation is not None else ()

    def _cors_for(
        self,
        endpoint: ApiEndpoint,
        response: CapturedResponse,
        stats: ApiSecurityStats,
    ) -> CorsObservation:
        stats.cors_checks += 1
        observation = analyze_cors(endpoint.url or endpoint.path, response.headers)
        if observation.unsafe:
            stats.cors_unsafe += 1
        return observation

    def _disclosures_for(
        self,
        endpoint: ApiEndpoint,
        response: CapturedResponse,
        stats: ApiSecurityStats,
    ) -> Sequence[DisclosureObservation]:
        observations = analyze_disclosure(
            endpoint.url or endpoint.path, response.headers
        )
        stats.disclosures += len(observations)
        return observations

    def _property_comparisons(
        self, report: ScanReport, stats: ApiSecurityStats
    ) -> list[PropertyComparison]:
        """Field sets across the identities Phase 12 already exercised.

        Phase 12 fetched each resource as each identity to compare *access*.
        Those same responses answer a different question for free: what was each
        identity handed once it was let in. No request is repeated.
        """
        observations = report.authorization_observations
        if not observations:
            return []

        contexts = {context.id: context for context in self._authorization.contexts}
        stats.contexts_analyzed = len({o.context_id for o in observations})

        # Group by resource, keeping only the identities that actually received
        # a JSON body — a 403 has no properties to compare.
        by_url: dict[str, dict[str, tuple[str, ...]]] = {}
        for observation in observations:
            if not observation.json_fields:
                continue
            by_url.setdefault(observation.url, {})[observation.context_id] = (
                observation.json_fields
            )

        comparisons: list[PropertyComparison] = []
        limit = self._security_config.limits.max_property_comparisons

        for url, field_sets in by_url.items():
            if len(field_sets) < 2:
                continue

            # The reference is the least-privileged identity that got a body:
            # anything another identity has *beyond* it is the difference worth
            # examining. Comparing against the most privileged would invert the
            # question and report the admin for seeing more.
            reference_id = min(
                field_sets,
                key=lambda cid: (
                    contexts[cid].privilege_rank if cid in contexts else 0,
                    cid,
                ),
            )
            reference_fields = field_sets[reference_id]

            for context_id, fields in field_sets.items():
                if context_id == reference_id or len(comparisons) >= limit:
                    continue
                denied, declared = self._policy(context_id, url)
                comparison = compare_properties(
                    url=url,
                    reference_context_id=reference_id,
                    subject_context_id=context_id,
                    subject_context_label=(
                        contexts[context_id].display_name
                        if context_id in contexts
                        else context_id
                    ),
                    reference_fields=reference_fields,
                    subject_fields=fields,
                    resource_denied=denied,
                    policy_declared=declared,
                )
                if comparison is not None:
                    comparisons.append(comparison)

        return comparisons

    def _inventory(
        self, surface: ApiSurface, stats: ApiSecurityStats
    ) -> tuple[InventoryObservation, ...]:
        observed = tuple(e.path for e in surface.endpoints if e.observed)
        documented_only = tuple(e.path for e in surface.endpoints if e.documented_only)
        undocumented = tuple(
            e.path for e in surface.endpoints if e.observed and not e.documented
        )
        # Only meaningful when a specification existed to disagree with.
        if not surface.documents:
            undocumented = ()
            documented_only = ()

        observations = analyze_inventory(
            observed=observed,
            documented_only=documented_only,
            undocumented=undocumented,
        )
        stats.inventory_observations = len(observations)
        return observations


# --------------------------------------------------------------------------- #


def _findings_from(
    sensitive: Sequence[SensitiveFieldObservation],
    comparisons: Sequence[PropertyComparison],
    errors: Sequence[ErrorObservation],
    cors: Sequence[CorsObservation],
    disclosures: Sequence[DisclosureObservation],
    inventory: Sequence[InventoryObservation],
) -> list[tuple[str | None, FindingData]]:
    """Findings, from the observations that earned one.

    Only `UNAUTHORIZED` verdicts become findings. `UNKNOWN_POLICY` is the common
    result on a real target and stays an observation: the scanner noticed a
    sensitive-looking field and has no basis for saying it does not belong.
    """
    emitted: list[tuple[str | None, FindingData]] = []

    for observation in sensitive:
        if observation.verdict is ExposureVerdict.UNAUTHORIZED:
            emitted.append((observation.url, build.sensitive_data_finding(observation)))

    for comparison in comparisons:
        if comparison.verdict is ExposureVerdict.UNAUTHORIZED:
            emitted.append(
                (comparison.url, build.property_authorization_finding(comparison))
            )

    for error in errors:
        emitted.append((error.url, build.verbose_error_finding(error)))

    for observation in cors:
        if observation.unsafe:
            emitted.append((observation.url, build.cors_finding(observation)))

    for observation in disclosures:
        emitted.append((observation.url, build.disclosure_finding(observation)))

    for observation in inventory:
        emitted.append((None, build.inventory_finding(observation)))

    return emitted


def _record(report: ScanReport, emitted: Sequence[tuple[str | None, FindingData]]) -> None:
    """Merge into the shared aggregation. No separate findings pipeline."""
    if report.api_security is not None:
        stats = report.api_security.stats
        report.metadata["api_security_findings"] = stats.findings_count
        report.metadata["api_security_endpoints_analyzed"] = stats.endpoints_analyzed

    if not emitted or report.analysis is None:
        return

    report.analysis.observations.extend(emitted)
    report.analysis.findings = aggregate_findings(report.analysis.observations)
