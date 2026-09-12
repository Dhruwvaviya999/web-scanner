"""The scan stage that tests file/path parameters for directory traversal.

It runs one detector — `PathTraversalDetector` — through the existing Phase 7
`ProbeEngine`, so every request inherits the scope, SSRF revalidation, redirect
bounds and credential scoping the rest of the scanner already enforces. There is
no second HTTP client here.

It owns its own `ProbeBudget`, separate from the general active-scan budget,
because path testing has its own ceiling (200 probes by default) and its own
coverage story to tell. The budget fails closed: a parameter the budget cannot
cover is skipped and recorded, never half-tested.

Findings merge into the shared Phase 5 aggregation like any other detector's, so
they deduplicate, associate with endpoints and reach the summary. The coverage
counters — considered, tested, skipped, canary matches — are this stage's own,
and a parameter that was never tested is recorded as such, never as safe.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from app.scanner.active.budget import ProbeBudget, ProbeBudgetLimits
from app.scanner.active.engine import ProbeEngine
from app.scanner.active.types import ActiveScanStats, DetectorObservation, ProbeTarget
from app.scanner.analysis.aggregator import aggregate_findings
from app.scanner.auth.types import AuthenticationContext
from app.scanner.cancellation import CancellationToken, ScanCancelled
from app.scanner.crawler.url_normalizer import is_same_origin, origin_of
from app.scanner.http_scanner import HttpFetcher, build_client
from app.scanner.path_security.detector import PathTraversalDetector
from app.scanner.path_security.parameter_classifier import classify
from app.scanner.path_security.types import (
    ParameterAssessment,
    PathSecurityConfig,
    PathSecurityResult,
    PathSecurityStats,
)
from app.scanner.types import ScannerConfig, ScanReport, ScanTarget

logger = logging.getLogger(__name__)


class PathSecurityModule:
    """Runs the traversal detector against the discovered file/path surface."""

    name = "path_security"

    def __init__(
        self,
        config: ScannerConfig,
        path_config: PathSecurityConfig | None = None,
        cancellation: CancellationToken | None = None,
        authentication: AuthenticationContext | None = None,
    ) -> None:
        self._config = config
        self._settings = path_config or PathSecurityConfig()
        self._cancellation = cancellation or CancellationToken.none()
        self._authentication = authentication or AuthenticationContext.none()

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        if not self._settings.enabled:
            report.path_security = PathSecurityResult()
            return
        if report.crawl is None or report.raw is None:
            report.path_security = PathSecurityResult()
            return

        origin = origin_of(report.raw.final_url)
        if origin is None:
            report.path_security = PathSecurityResult()
            return

        targets = self._targets(report)[: self._settings.limits.max_targets]
        assessments = self._assess(targets)

        if not targets:
            report.path_security = PathSecurityResult(assessments=assessments)
            return

        stats = PathSecurityStats()
        limits = self._settings.limits
        detector = PathTraversalDetector(
            limits=limits,
            stats=stats,
            authenticated=self._authentication.configured,
            context_label=self._context_label(),
        )

        budget = ProbeBudget(
            limits=ProbeBudgetLimits(
                per_parameter=limits.per_parameter_budget,
                per_endpoint=limits.per_endpoint_budget,
                per_scan=limits.max_probes_per_scan,
            )
        )
        engine_stats = ActiveScanStats()
        observations: list[DetectorObservation] = []
        cancelled = False

        async with build_client(self._config) as client:
            fetcher = HttpFetcher(
                self._config,
                client,
                # A redirect leaving the origin is refused, not followed.
                allow_url=lambda url: is_same_origin(url, origin),
                max_redirects=self._config.max_redirects,
                # One fetcher for the stage: the detector's baseline and its
                # probes are always sent with the same authentication context,
                # so an authenticated baseline is never compared with an
                # unauthenticated probe.
                authentication=self._authentication,
            )
            engine = ProbeEngine(fetcher, origin, budget, engine_stats, self._cancellation)

            for probe_target in targets:
                if self._cancellation.cancelled:
                    cancelled = True
                    break
                if budget.exhausted():
                    stats.budget_exhausted = True
                    break

                decision = detector.eligible(probe_target)
                if not decision.eligible:
                    continue
                try:
                    observations.extend(await detector.probe(probe_target, engine))
                except ScanCancelled:
                    cancelled = True
                    break
                except Exception:  # noqa: BLE001 - one target must not end the scan
                    stats.failed_probes += 1
                    stats.note("detector_error")
                    logger.exception("Path-security detector failed on a target")

        stats.requests_sent = engine_stats.requests_sent
        if budget.exhausted():
            stats.budget_exhausted = True

        report.path_security = PathSecurityResult(
            assessments=assessments,
            observations=detector.observations,
            stats=stats,
        )
        _record(report, observations)

        if cancelled:
            raise ScanCancelled(self.name)

    # ------------------------------------------------------------------ #

    def _context_label(self) -> str | None:
        """A safe identity label for authenticated runs. Never a credential.

        The authentication mode name (`BEARER_TOKEN`, `SESSION_COOKIE`) is a
        category, not a secret — the credential itself is only ever read inside
        `headers_for` and is never rendered anywhere.
        """
        if not self._authentication.configured:
            return None
        return self._authentication.mode.value

    def _targets(self, report: ScanReport) -> list[ProbeTarget]:
        """GET targets with parameters, from the crawl and any observed API.

        Crawl endpoints are the richest input surface. Observed GET API
        endpoints with query parameters are folded in — reusing the Phase 13
        surface rather than building a second one — deduplicated by URL so a
        parameter is never probed twice.
        """
        seen: dict[str, ProbeTarget] = {}

        assert report.crawl is not None
        for endpoint in report.crawl.endpoints:
            if endpoint.method.upper() != "GET" or not endpoint.parameters:
                continue
            seen[endpoint.url] = ProbeTarget(
                url=endpoint.url,
                parameters=endpoint.parameters,
                content_type=endpoint.content_type,
                method="GET",
            )

        if report.api is not None:
            for api_endpoint in report.api.endpoints:
                if (
                    not api_endpoint.observed
                    or api_endpoint.url is None
                    or api_endpoint.method.upper() != "GET"
                ):
                    continue
                query_params = tuple(
                    p.name
                    for p in api_endpoint.parameters
                    if p.location.value == "QUERY"
                )
                if not query_params or api_endpoint.url in seen:
                    continue
                seen[api_endpoint.url] = ProbeTarget(
                    url=api_endpoint.url,
                    parameters=query_params,
                    content_type=api_endpoint.response_media_type,
                    method="GET",
                )

        targets = list(seen.values())
        # Richest input surface first, matching the active-scan ordering.
        targets.sort(key=lambda t: (-len(t.parameters), t.url))
        return targets

    def _assess(self, targets: Sequence[ProbeTarget]) -> tuple[ParameterAssessment, ...]:
        """Classify every parameter on every target, for the coverage block.

        Pure, and computed even for parameters the budget never reaches, so the
        report can show the full file/path surface that was considered.
        """
        assessments: list[ParameterAssessment] = []
        for target in targets:
            for parameter in target.parameters:
                assessments.append(
                    classify(
                        parameter,
                        endpoint=target.url,
                        content_type=target.content_type,
                    )
                )
        return tuple(assessments)


def _record(
    report: ScanReport, observations: Sequence[DetectorObservation]
) -> None:
    """Merge findings into the shared aggregation. No separate findings store."""
    if report.path_security is not None:
        stats = report.path_security.stats
        report.metadata["path_security_findings"] = stats.findings_count
        report.metadata["path_security_probes"] = stats.traversal_probes
        report.metadata["path_security_requests"] = stats.requests_sent

    if not observations or report.analysis is None:
        return

    report.analysis.observations.extend(observations)
    report.analysis.findings = aggregate_findings(report.analysis.observations)
