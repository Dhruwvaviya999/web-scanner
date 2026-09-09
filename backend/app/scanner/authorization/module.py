"""The scan module that compares access across supplied identities.

Runs after the crawl and the active detectors, because it works from the attack
surface they discovered rather than from anything it invents. It does not brute
force paths, enumerate identifiers, or create accounts: the resources it tests
are the ones the crawler already reached plus the ones the authorized user named
in the policy.

Every request goes through the same `HttpFetcher` as the rest of the scanner, so
URL validation, the SSRF guard, the same-origin lock, redirect limits, timeouts
and the response cap all apply unchanged. There is no authorization transport.

Requests are read-only. Only GET is sent, and only to URLs already in scope.
Nothing here writes to the target, so a scan cannot change the state of the
application it is measuring.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import httpx

from app.scanner.analysis.aggregator import aggregate_findings
from app.scanner.authorization.budget import AuthorizationBudget
from app.scanner.authorization.detector import analyze_resource
from app.scanner.authorization.findings import build_finding
from app.scanner.authorization.matrix import AuthorizationPlan, path_of
from app.scanner.authorization.types import (
    AuthorizationConfig,
    AuthorizationContext,
    AuthorizationObservation,
    AuthorizationOutcome,
    AuthorizationStats,
    AuthorizationTestKind,
    ComparisonVerdict,
)
from app.scanner.cancellation import CancellationToken, ScanCancelled
from app.scanner.crawler.url_normalizer import Origin, is_same_origin, origin_of
from app.scanner.http_scanner import HttpFetcher, build_client
from app.scanner.security.types import FindingData
from app.scanner.types import ScannerConfig, ScannerError, ScanReport, ScanTarget
from app.scanner.url_validator import parse_target_url

logger = logging.getLogger(__name__)


class AuthorizationModule:
    """Compares what each supplied identity can reach."""

    name = "authorization"

    def __init__(
        self,
        config: ScannerConfig,
        authz_config: AuthorizationConfig,
        plan: AuthorizationPlan | None = None,
        cancellation: CancellationToken | None = None,
    ) -> None:
        self._config = config
        self._authz_config = authz_config
        self._plan = plan or AuthorizationPlan()
        self._cancellation = cancellation or CancellationToken.none()

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        if not self._authz_config.enabled or not self._plan.enabled:
            # Not configured. Recorded explicitly so a report can say
            # "authorization was not tested" rather than staying silent.
            report.authorization = AuthorizationOutcome(enabled=False)
            return
        if report.raw is None:
            report.authorization = AuthorizationOutcome(enabled=False)
            return

        origin = origin_of(report.raw.final_url)
        if origin is None:
            report.authorization = AuthorizationOutcome(enabled=False)
            return

        contexts = list(self._plan.contexts)[: self._authz_config.limits.max_contexts]
        stats = AuthorizationStats(contexts=len(contexts))
        budget = AuthorizationBudget(limits=self._authz_config.limits)
        observations: list[AuthorizationObservation] = []
        cancelled = False

        resources = self._resources(report, origin)
        stats.endpoints_eligible = len(resources)

        try:
            observations = await self._test_all(resources, contexts, stats, budget)
        except ScanCancelled:
            # Partial comparisons are still valid, so they are kept and the
            # stage unwinds after the results below are attached.
            cancelled = True

        findings = _findings_from(observations)
        _record(report, stats, observations, findings, contexts)

        if cancelled:
            raise ScanCancelled(self.name)

    # ------------------------------------------------------------------ #

    def _resources(self, report: ScanReport, origin: Origin) -> list[str]:
        """The URLs to test: what the crawler found, plus what the user named.

        Discovered endpoints come first so that a site's own surface is covered
        before the budget is spent on declared resources. Declared resources are
        included even when the crawl never saw them — an object belonging to
        another identity is usually invisible to the identity doing the
        crawling, and that is exactly the case object-level testing exists for.
        """
        urls: dict[str, None] = {}

        if report.crawl is not None:
            for endpoint in report.crawl.endpoints:
                if endpoint.method.upper() != "GET":
                    # Read-only by design: this phase never sends a request that
                    # could change the application's state.
                    continue
                urls.setdefault(endpoint.url, None)

        for pattern in self._plan.matrix.declared_resources():
            candidate = f"{origin.base_url}{pattern}"
            if is_same_origin(candidate, origin):
                urls.setdefault(candidate, None)

        return list(urls)[: self._authz_config.limits.max_endpoints]

    async def _test_all(
        self,
        resources: Sequence[str],
        contexts: Sequence[AuthorizationContext],
        stats: AuthorizationStats,
        budget: AuthorizationBudget,
    ) -> list[AuthorizationObservation]:
        observations: list[AuthorizationObservation] = []

        # One client per identity. Sharing one would share its cookie jar, and a
        # Set-Cookie from the target could then be replayed as another
        # identity's request — silently invalidating every comparison drawn
        # afterwards.
        clients: dict[str, httpx.AsyncClient] = {}
        try:
            for context in contexts:
                clients[context.id] = build_client(self._config)

            for url in resources:
                # Between resources: nothing is in flight and the observations
                # gathered so far are complete.
                self._cancellation.raise_if_cancelled(self.name)

                if not budget.start_endpoint():
                    stats.budget_exhausted = True
                    stats.note("endpoint_limit")
                    break
                if budget.exhausted():
                    stats.budget_exhausted = True
                    stats.note("request_limit")
                    break

                responses = await self._fetch_all(url, contexts, clients, stats, budget)
                if not any(response is not None for response in responses.values()):
                    stats.skipped += 1
                    stats.note("no_usable_response")
                    continue

                stats.endpoints_tested += 1
                for observation in analyze_resource(
                    url, contexts, responses, self._plan.matrix, self._authz_config
                ):
                    if not budget.reserve_comparison(url):
                        stats.note("comparison_limit")
                        break
                    stats.comparisons += 1
                    if observation.verdict is ComparisonVerdict.UNKNOWN:
                        stats.unknown += 1
                    observations.append(observation)
        finally:
            for client in clients.values():
                await client.aclose()

        return observations

    async def _fetch_all(
        self,
        url: str,
        contexts: Sequence[AuthorizationContext],
        clients: dict[str, httpx.AsyncClient],
        stats: AuthorizationStats,
        budget: AuthorizationBudget,
    ) -> dict[str, object]:
        responses: dict[str, object] = {}

        try:
            probe_target = parse_target_url(url)
        except ScannerError:
            stats.note("invalid_url")
            return responses

        origin = origin_of(probe_target.normalized_url)
        if origin is None:  # pragma: no cover - a parsed target always has one
            return responses

        for context in contexts:
            # Before switching identity, and before every request.
            self._cancellation.raise_if_cancelled(self.name)

            if not budget.reserve_request():
                stats.budget_exhausted = True
                stats.note("request_limit")
                break

            client = clients[context.id]
            # The jar is cleared even though each identity has its own client:
            # a cookie the target sets during one request must not silently
            # join the next one and change what is being measured.
            client.cookies.clear()

            fetcher = HttpFetcher(
                self._config,
                client,
                allow_url=lambda candidate: is_same_origin(candidate, origin),
                max_redirects=self._config.max_redirects,
                authentication=context.authentication,
            )
            try:
                responses[context.id] = await fetcher.fetch(probe_target)
            except ScannerError as exc:
                stats.failed += 1
                stats.note(f"request_failed:{exc.code.value}")
                logger.debug(
                    "Authorization request failed: context=%s path=%s reason=%s",
                    context.id,
                    path_of(url),
                    exc.code.value,
                )
                responses[context.id] = None
            except ScanCancelled:
                raise
            except Exception:  # noqa: BLE001 - one request must not end the scan
                stats.failed += 1
                stats.note("request_failed:unexpected")
                logger.exception("Unexpected failure during an authorization request")
                responses[context.id] = None

        return responses


def _findings_from(
    observations: Sequence[AuthorizationObservation],
) -> list[tuple[str | None, FindingData]]:
    """Findings for violations, with one deliberate suppression.

    When an anonymous request already reached a resource, every authenticated
    identity reaching it too is the same defect seen again: the resource is not
    protected at all. Reporting each identity separately would turn one missing
    check into a pile of findings that all resolve together. The anonymous
    finding is kept, because "no credential was needed" is the most useful way
    to state it, and the rest are left as observations.
    """
    anonymous_urls = {
        observation.url
        for observation in observations
        if observation.verdict is ComparisonVerdict.VIOLATION
        and observation.kind is AuthorizationTestKind.ANONYMOUS
    }

    findings: list[tuple[str | None, FindingData]] = []
    for observation in observations:
        if observation.verdict is not ComparisonVerdict.VIOLATION:
            continue
        if (
            observation.kind is not AuthorizationTestKind.ANONYMOUS
            and observation.url in anonymous_urls
        ):
            continue
        findings.append((observation.url, build_finding(observation)))
    return findings


def _record(
    report: ScanReport,
    stats: AuthorizationStats,
    observations: Sequence[AuthorizationObservation],
    findings: Sequence[tuple[str | None, FindingData]],
    contexts: Sequence[AuthorizationContext],
) -> None:
    """Attach results to the report, merging findings into the shared pipeline."""
    report.authorization = AuthorizationOutcome.from_stats(
        stats, [context.display_name for context in contexts]
    )
    report.metadata["authorization_requests_sent"] = stats.requests_sent
    report.metadata["authorization_comparisons"] = stats.comparisons
    if stats.budget_exhausted:
        report.metadata["authorization_budget_exhausted"] = True

    if not findings or report.analysis is None:
        return

    # The same aggregation every other detector feeds, so authorization findings
    # deduplicate, associate with endpoints and reach the summary identically.
    report.analysis.observations.extend(findings)
    report.analysis.findings = aggregate_findings(report.analysis.observations)
