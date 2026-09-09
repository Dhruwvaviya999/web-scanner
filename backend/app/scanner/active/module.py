"""The scan module that runs registered active detectors.

Generic: it knows about detectors, not about any particular vulnerability. A new
detector is added by appending it to the registry — no change is needed here, in
the pipeline, or in the persistence layer.

Ordering of concerns:

1. Build probe targets from what the crawler discovered.
2. Ask each detector which targets it wants (`eligible`) — pure, no requests.
3. Run the eligible ones through a single shared engine and budget.
4. Merge whatever they found into the phase-5 aggregation.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field

from app.scanner.active.budget import ProbeBudget, ProbeBudgetLimits
from app.scanner.active.engine import ProbeEngine
from app.scanner.active.types import (
    ActiveDetector,
    ActiveScanStats,
    DetectorObservation,
    ProbeTarget,
)
from app.scanner.analysis.aggregator import aggregate_findings
from app.scanner.auth.types import AuthenticationContext
from app.scanner.cancellation import CancellationToken, ScanCancelled
from app.scanner.crawler.url_normalizer import is_same_origin, origin_of
from app.scanner.http_scanner import HttpFetcher, build_client
from app.scanner.types import ScannerConfig, ScanReport, ScanTarget

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ActiveScanConfig:
    """Configuration for the active-probe stage as a whole."""

    enabled: bool = True
    limits: ProbeBudgetLimits = field(default_factory=ProbeBudgetLimits)
    #: Endpoints considered per scan, before per-detector eligibility.
    max_targets: int = 25


class ActiveScanModule:
    """Runs every registered active detector against the discovered surface."""

    name = "active_scan"

    def __init__(
        self,
        config: ScannerConfig,
        active_config: ActiveScanConfig,
        detectors: Sequence[ActiveDetector],
        cancellation: CancellationToken | None = None,
        authentication: AuthenticationContext | None = None,
    ) -> None:
        self._config = config
        self._active_config = active_config
        self._detectors = list(detectors)
        self._cancellation = cancellation or CancellationToken.none()
        self._authentication = authentication

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        if not self._active_config.enabled or not self._detectors:
            return
        if report.crawl is None or report.raw is None:
            # Nothing was discovered, so there is no input surface to probe.
            return

        origin = origin_of(report.raw.final_url)
        if origin is None:
            return

        targets = _targets_from(report)[: self._active_config.max_targets]
        if not targets:
            return

        budget = ProbeBudget(limits=self._active_config.limits)
        stats = ActiveScanStats()
        observations: list[DetectorObservation] = []

        cancelled = False

        async with build_client(self._config) as client:
            fetcher = HttpFetcher(
                self._config,
                client,
                # A redirect leaving the origin is refused, not followed.
                allow_url=lambda url: is_same_origin(url, origin),
                max_redirects=self._config.max_redirects,
                # One fetcher for the whole active stage, so a detector's
                # baseline and its probes are always sent with the same
                # authentication context. Comparing an authenticated baseline
                # against an unauthenticated probe would manufacture findings.
                authentication=self._authentication,
            )
            engine = ProbeEngine(fetcher, origin, budget, stats, self._cancellation)

            for probe_target in targets:
                # Between targets. The engine additionally refuses to send once
                # cancellation is observed, so no probe escapes mid-detector.
                if self._cancellation.cancelled:
                    cancelled = True
                    break

                stats.targets_considered += 1
                if budget.exhausted():
                    stats.budget_exhausted = True
                    break
                try:
                    observations.extend(await self._run_detectors(probe_target, engine))
                except ScanCancelled:
                    # Raised by the engine mid-detector. Whatever earlier targets
                    # produced is already in `observations` and is kept.
                    cancelled = True
                    break

        _record_metadata(report, stats, budget)

        if observations and report.analysis is not None:
            # Merge into the phase-5 aggregation so active findings deduplicate,
            # associate with endpoints and reach the summary like any other
            # finding.
            report.analysis.observations.extend(observations)
            report.analysis.findings = aggregate_findings(report.analysis.observations)

        if cancelled:
            raise ScanCancelled("ANALYZING")

    async def _run_detectors(
        self, target: ProbeTarget, engine: ProbeEngine
    ) -> list[DetectorObservation]:
        found: list[DetectorObservation] = []

        for detector in self._detectors:
            decision = detector.eligible(target)
            if not decision.eligible:
                engine.stats.targets_skipped += 1
                engine.stats.note(f"skipped:{decision.reason or 'ineligible'}")
                continue

            engine.stats.targets_probed += 1
            try:
                found.extend(await detector.probe(target, engine))
            except ScanCancelled:
                # Not a detector fault. Re-raised so the stop is not mistaken
                # for a failure and swallowed by the guard below.
                raise
            except Exception:  # noqa: BLE001 - one detector must not end the scan
                engine.stats.failures += 1
                engine.stats.note(f"detector_error:{detector.name}")
                logger.exception("Active detector %s failed", detector.name)

        return found


def _targets_from(report: ScanReport) -> list[ProbeTarget]:
    """Probe targets from the crawler's endpoints, richest input surface first."""
    assert report.crawl is not None
    targets = [
        ProbeTarget(
            url=endpoint.url,
            parameters=endpoint.parameters,
            content_type=endpoint.content_type,
            method=endpoint.method,
        )
        for endpoint in report.crawl.endpoints
    ]
    targets.sort(key=lambda t: (-len(t.parameters), t.url))
    return targets


def _record_metadata(report: ScanReport, stats: ActiveScanStats, budget: ProbeBudget) -> None:
    report.metadata["active_requests_sent"] = stats.requests_sent
    report.metadata["active_targets_probed"] = stats.targets_probed
    if stats.failures:
        report.metadata["active_probe_failures"] = stats.failures
    if stats.budget_exhausted or budget.exhausted():
        report.metadata["active_budget_exhausted"] = True
