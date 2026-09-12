"""The scan stage that examines how a target is deployed.

This is the only file in the package that touches the network, and everything
it sends is a `GET`, `HEAD` or `OPTIONS` through the existing `HttpFetcher` —
so every request inherits the SSRF revalidation, the origin lock, the redirect
bounds and the credential scoping that the rest of the scanner already has.
There is no second HTTP client here, and adding one would bypass all of that.

Three constraints shape the design.

**Bounded, and honest when the bound bites.** Candidate lists are constants,
`max_requests` is a hard stop, and a candidate the budget never reached is
recorded as `NOT_TESTED` rather than dropped. A scan that ran out of budget
reports reduced coverage; it never reports a clean result it did not earn.

**Passive first.** Most of what this stage concludes — debug markers, directory
listings, technology headers, CSP quality, path normalization — comes from
responses earlier phases already fetched. Setting `probe_candidates=False`
turns off every request and still produces all of that.

**Nothing read is kept.** Candidate bodies are examined to decide whether the
response is really the file that was asked for, then discarded inside the
function that read them. Nothing downstream of `_probe` has access to a body.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence

from app.scanner.analysis.aggregator import aggregate_findings
from app.scanner.auth.types import AuthenticationContext
from app.scanner.authorization.matrix import AuthorizationPlan
from app.scanner.authorization.types import AccessExpectation
from app.scanner.cancellation import CancellationToken, ScanCancelled
from app.scanner.config_security import deployment, discovery, findings as build
from app.scanner.config_security import headers as header_analysis
from app.scanner.config_security import methods as method_analysis
from app.scanner.config_security import path_confusion, transport as transport_analysis
from app.scanner.config_security.types import (
    AccessVisibility,
    CandidateKind,
    CandidateObservation,
    CandidateOutcome,
    ConfigSecurityConfig,
    ConfigSecurityResult,
    ConfigSecurityStats,
    CspObservation,
    DebugObservation,
    HeaderDefectObservation,
    ListingObservation,
    MethodObservation,
    NormalizationObservation,
    SourceMapObservation,
    TechnologyObservation,
    TransportObservation,
)
from app.scanner.crawler.types import CapturedResponse
from app.scanner.crawler.url_normalizer import Origin, is_same_origin, origin_of
from app.scanner.http_scanner import HttpFetcher, build_client
from app.scanner.security.types import FindingData
from app.scanner.types import (
    RawHttpResponse,
    ScannerConfig,
    ScannerError,
    ScanReport,
    ScanTarget,
)
from app.scanner.url_validator import parse_target_url

logger = logging.getLogger(__name__)

#: Anonymous identity label, matching the convention the other stages use.
_ANONYMOUS = "anonymous"


class ConfigSecurityModule:
    """Examines transport, deployment and configuration. Bounded and safe."""

    name = "config_security"

    def __init__(
        self,
        config: ScannerConfig,
        config_security: ConfigSecurityConfig | None = None,
        cancellation: CancellationToken | None = None,
        authentication: AuthenticationContext | None = None,
        authorization: AuthorizationPlan | None = None,
    ) -> None:
        self._config = config
        self._settings = config_security or ConfigSecurityConfig()
        self._cancellation = cancellation or CancellationToken.none()
        self._authentication = authentication or AuthenticationContext.none()
        self._authorization = authorization or AuthorizationPlan()

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        if not self._settings.enabled:
            report.config_security = ConfigSecurityResult()
            return

        stats = ConfigSecurityStats()
        responses = self._responses(report)

        transport = self._transport(target, report)
        passive = self._passive(responses, report, stats)

        self._cancellation.raise_if_cancelled(self.name)

        candidates: list[CandidateObservation] = []
        method_observations: list[MethodObservation] = []
        source_maps: list[SourceMapObservation] = []

        if self._settings.probe_candidates:
            origin = origin_of(target.normalized_url)
            if origin is not None:
                probed = await self._probe(origin, responses, stats)
                candidates, method_observations, source_maps = probed

        normalization = self._normalization(report, responses)
        stats.path_normalization_observations = len(normalization)

        result = ConfigSecurityResult(
            transport=transport,
            methods=method_analysis.merge(method_observations),
            candidates=tuple(candidates),
            debug=passive.debug,
            listings=passive.listings,
            source_maps=tuple(source_maps),
            technologies=passive.technologies,
            header_defects=passive.header_defects,
            csp=passive.csp,
            normalization=normalization,
            stats=stats,
        )

        emitted = self._findings(result, stats)
        stats.findings_count = len(emitted)

        report.config_security = result
        _record(report, emitted)

    # ------------------------------------------------------------------ #
    # Inputs the scan already has
    # ------------------------------------------------------------------ #

    def _responses(self, report: ScanReport) -> list[CapturedResponse]:
        """Every response earlier phases captured. Nothing is fetched here."""
        captured: list[CapturedResponse] = []
        if report.crawl is not None:
            captured.extend(report.crawl.responses.values())

        raw = report.raw
        if raw is not None:
            captured.append(
                CapturedResponse(
                    url=raw.final_url,
                    status_code=raw.status_code,
                    content_type=raw.headers.get("content-type"),
                    is_https=raw.is_https,
                    headers=raw.headers,
                    set_cookie=raw.set_cookie,
                )
            )
        return captured

    def _transport(
        self, target: ScanTarget, report: ScanReport
    ) -> TransportObservation:
        """Transport from the probe the scan already made."""
        raw = report.raw
        return transport_analysis.analyze(
            host=target.host,
            requested_https=target.is_https,
            final_url=raw.final_url if raw else (report.probe.final_url if report.probe else None),
            redirect_count=raw.redirect_count if raw else 0,
            headers=raw.headers if raw else {},
            reached=raw is not None,
            error_code=report.error_code,
        )

    # ------------------------------------------------------------------ #
    # Passive analysis over captured responses
    # ------------------------------------------------------------------ #

    def _passive(
        self,
        responses: Sequence[CapturedResponse],
        report: ScanReport,
        stats: ConfigSecurityStats,
    ) -> "_PassiveResult":
        """Debug, listings, technology, header defects and CSP.

        Bodies are gone by the time this runs — the crawler discards them at
        capture — so the body-derived half comes from `ConfigSignals`, which the
        crawler computed at that same moment. Headers are still present in full,
        so header-derived analysis runs directly here.
        """
        limits = self._settings.limits
        debug: list[DebugObservation] = []
        listings: list[ListingObservation] = []
        technologies: list[TechnologyObservation] = []
        defects: list[HeaderDefectObservation] = []
        csp: list[CspObservation] = []

        error_urls = self._error_signal_urls(report)

        for response in responses[: limits.max_responses_analyzed]:
            stats.responses_analyzed += 1

            signals = response.config_signals

            observation = self._debug_for(response, signals, error_urls)
            if observation is not None:
                debug.append(observation)

            if signals is not None and signals.directory_listing:
                listings.append(
                    ListingObservation(
                        url=response.url,
                        entry_count=signals.listing_entry_count,
                        server_style=signals.listing_style,
                        detail=(
                            "the server returned a generated directory index rather "
                            "than a page"
                        ),
                    )
                )

            technologies.extend(deployment.detect_technology(response.url, response.headers))
            defects.extend(header_analysis.analyze_header_defects(response.url, response.headers))

            policy = header_analysis.analyze_csp(response.url, response.headers)
            if policy.reportable or policy.duplicated:
                csp.append(policy)

        stats.debug_indicators = len(debug)
        stats.directory_listings = len(listings)

        merged_technologies = deployment.merge_technologies(technologies)
        stats.technology_disclosures = len(merged_technologies)

        return _PassiveResult(
            debug=tuple(debug),
            listings=tuple(listings),
            technologies=merged_technologies,
            header_defects=header_analysis.merge_defects(defects),
            csp=tuple(csp),
        )

    def _debug_for(
        self,
        response: CapturedResponse,
        signals,
        error_urls: frozenset[str],
    ) -> DebugObservation | None:
        """Combine the body markers found at capture with header markers now.

        The two halves are deliberately separate: body evidence had to be taken
        while the body existed, header evidence can be taken at any time, and
        `DebugObservation.conclusive` needs both to decide whether one marker or
        two were seen.
        """
        header_only = deployment.detect_debug(
            response.url,
            headers=response.headers,
            status_code=response.status_code,
            corroborated=response.url in error_urls,
        )
        body_signals = signals.debug_signals if signals is not None else ()

        if header_only is None and not body_signals:
            return None

        combined = tuple(
            dict.fromkeys((*body_signals, *(header_only.signals if header_only else ())))
        )
        return DebugObservation(
            url=response.url,
            signals=combined,
            status_code=response.status_code,
            corroborated_by_error_analysis=response.url in error_urls,
            detail=(
                "development-mode markers were present in the response; the text that "
                "matched is not recorded"
            ),
        )

    def _error_signal_urls(self, report: ScanReport) -> frozenset[str]:
        """URLs where Phase 14 already found a diagnostic leak.

        Reused rather than re-derived: a debug page and a verbose error are
        often the same response, and this is how the two phases correlate
        instead of both reporting it.
        """
        api_security = report.api_security
        if api_security is None:
            return frozenset()
        return frozenset(observation.url for observation in api_security.errors)

    def _normalization(
        self, report: ScanReport, responses: Sequence[CapturedResponse]
    ) -> tuple[NormalizationObservation, ...]:
        """Path-handling disagreements, from what the crawl already saw."""
        statuses = {
            response.url: response.status_code for response in responses
        }
        redirects = {
            response.url: location
            for response in responses
            if (location := response.headers.get("location"))
        }
        observed = list(path_confusion.analyze(statuses, redirects=redirects))
        observed.extend(path_confusion.duplicate_representations(list(statuses)))
        return tuple(observed)

    # ------------------------------------------------------------------ #
    # The only traffic this stage generates
    # ------------------------------------------------------------------ #

    async def _probe(
        self,
        origin: Origin,
        responses: Sequence[CapturedResponse],
        stats: ConfigSecurityStats,
    ) -> tuple[
        list[CandidateObservation], list[MethodObservation], list[SourceMapObservation]
    ]:
        """Request the bounded candidate lists. Every request is GET/HEAD/OPTIONS."""
        limits = self._settings.limits
        candidates: list[CandidateObservation] = []
        method_observations: list[MethodObservation] = []
        source_maps: list[SourceMapObservation] = []

        async with build_client(self._config) as client:
            fetcher = HttpFetcher(
                self._config,
                client,
                # Locked to the origin being scanned, exactly as Phase 13 does.
                # A redirect leaving it is refused rather than followed, so
                # neither a request nor the configured credential travels
                # off-origin.
                allow_url=lambda url: is_same_origin(url, origin),
                max_redirects=self._config.max_redirects,
                authentication=self._authentication,
            )

            plan: list[tuple[CandidateKind, tuple[str, ...]]] = [
                (CandidateKind.REPOSITORY, discovery.REPOSITORY_CANDIDATES),
                (CandidateKind.SENSITIVE_FILE, discovery.SENSITIVE_FILE_CANDIDATES),
                (CandidateKind.ADMIN, discovery.ADMIN_CANDIDATES),
                (CandidateKind.MANAGEMENT, discovery.MANAGEMENT_CANDIDATES),
                (CandidateKind.DEBUG, discovery.DEBUG_CANDIDATES),
                (CandidateKind.HEALTH, discovery.HEALTH_CANDIDATES),
                (CandidateKind.SAMPLE, discovery.SAMPLE_CANDIDATES),
            ]

            # Deduplicated across the whole plan: two lists naming the same
            # path would otherwise spend two requests to learn one thing.
            already: set[str] = set()

            for kind, paths in plan:
                bounded = tuple(
                    p for p in self._bound(kind, paths, limits) if p not in already
                )
                already.update(bounded)
                for index, path in enumerate(bounded):
                    if not self._may_request(stats, limits):
                        # Budget reached. Everything left is recorded as
                        # untested so coverage stays honest.
                        candidates.extend(discovery.not_tested(bounded[index:], kind))
                        stats.candidates_not_tested += len(bounded) - index
                        stats.budget_exhausted = True
                        break
                    observation = await self._check(fetcher, origin, path, kind, stats)
                    candidates.append(observation)
                else:
                    continue
                break

            # Backups derive from what was actually found, never from a list.
            candidates.extend(
                await self._backups(fetcher, origin, candidates, responses, stats, limits)
            )

            method_observations.extend(
                await self._methods(fetcher, origin, responses, stats, limits)
            )
            source_maps.extend(
                await self._source_maps(fetcher, origin, responses, stats, limits)
            )

        self._tally(candidates, stats)
        return candidates, method_observations, source_maps

    def _bound(
        self, kind: CandidateKind, paths: Sequence[str], limits
    ) -> tuple[str, ...]:
        ceiling = {
            CandidateKind.ADMIN: limits.max_admin_candidates,
            CandidateKind.MANAGEMENT: limits.max_admin_candidates,
            CandidateKind.DEBUG: limits.max_admin_candidates,
            CandidateKind.SENSITIVE_FILE: limits.max_sensitive_file_candidates,
            CandidateKind.REPOSITORY: limits.max_sensitive_file_candidates,
        }.get(kind, limits.max_admin_candidates)
        return tuple(paths[:ceiling])

    def _may_request(self, stats: ConfigSecurityStats, limits) -> bool:
        return stats.requests_sent < limits.max_requests

    async def _check(
        self,
        fetcher: HttpFetcher,
        origin: Origin,
        path: str,
        kind: CandidateKind,
        stats: ConfigSecurityStats,
    ) -> CandidateObservation:
        """One candidate. The body is read to classify, then dropped here."""
        # Before every candidate request, as the lifecycle contract requires.
        self._cancellation.raise_if_cancelled(self.name)

        url = f"{origin.base_url}{path}"
        response = await self._fetch(fetcher, url, stats)
        stats.candidates_checked += 1

        if kind is CandidateKind.SENSITIVE_FILE:
            stats.sensitive_file_candidates_checked += 1
        elif kind in (CandidateKind.ADMIN, CandidateKind.MANAGEMENT):
            stats.admin_candidates_checked += 1

        if response is None:
            return CandidateObservation(
                path=path,
                kind=kind,
                outcome=CandidateOutcome.ERROR,
                authenticated=self._authentication.configured,
                detail="the request did not complete",
            )

        # `body` exists only inside this call. `classify` returns an
        # observation with no body field, and the bytes go out of scope here.
        return discovery.classify(
            path=path,
            kind=kind,
            status_code=response.status_code,
            headers=response.headers,
            body=response.body[: self._settings.limits.max_candidate_bytes],
            authenticated=self._authentication.configured,
        )

    async def _backups(
        self,
        fetcher: HttpFetcher,
        origin: Origin,
        found: Sequence[CandidateObservation],
        responses: Sequence[CapturedResponse],
        stats: ConfigSecurityStats,
        limits,
    ) -> list[CandidateObservation]:
        """Backup spellings of files this scan actually found.

        Derived from evidence, not generated. The source paths are candidates
        that came back `EXPOSED` plus configuration-shaped URLs the crawler
        reached, three suffixes each, capped for the whole scan.
        """
        sources: list[str] = [c.path for c in found if c.exposed]
        sources.extend(discovery.discovered_file_paths([r.url for r in responses]))

        observations: list[CandidateObservation] = []
        seen: set[str] = set()

        for source in dict.fromkeys(sources):
            for variant in discovery.backup_variants(
                source, limit=limits.max_backup_variants_per_file
            ):
                if variant in seen or len(observations) >= limits.max_backup_candidates:
                    continue
                seen.add(variant)
                if not self._may_request(stats, limits):
                    stats.budget_exhausted = True
                    stats.candidates_not_tested += 1
                    observations.append(
                        discovery.not_tested((variant,), CandidateKind.BACKUP)[0]
                    )
                    continue
                stats.backup_candidates_checked += 1
                observations.append(
                    await self._check(fetcher, origin, variant, CandidateKind.BACKUP, stats)
                )
        return observations

    async def _methods(
        self,
        fetcher: HttpFetcher,
        origin: Origin,
        responses: Sequence[CapturedResponse],
        stats: ConfigSecurityStats,
        limits,
    ) -> list[MethodObservation]:
        """Ask a bounded set of endpoints what they support, via OPTIONS.

        OPTIONS and nothing else. The answer is documentation, and this stage
        does not send a PUT, PATCH or DELETE to find out whether the
        documentation is accurate — see `config_security.methods`.
        """
        observations: list[MethodObservation] = []
        urls = [response.url for response in responses][: limits.max_method_checks]

        for url in urls:
            self._cancellation.raise_if_cancelled(self.name)
            if not self._may_request(stats, limits):
                stats.budget_exhausted = True
                break
            response = await self._fetch(fetcher, url, stats, method="OPTIONS")
            stats.method_checks += 1
            if response is None:
                continue
            observations.append(
                method_analysis.analyze_options(
                    url,
                    response.headers,
                    status_code=response.status_code,
                    # GET is what every one of these was already reached with.
                    observed=("GET",),
                )
            )
        return observations

    async def _source_maps(
        self,
        fetcher: HttpFetcher,
        origin: Origin,
        responses: Sequence[CapturedResponse],
        stats: ConfigSecurityStats,
        limits,
    ) -> list[SourceMapObservation]:
        """Follow source-map references the assets themselves publish.

        Reference-driven only, and the reference comes from the crawl: the
        crawler read each asset's trailing `sourceMappingURL` comment at capture
        and kept the resolved URL. So a map is fetched only when an asset named
        it — guessing `app.js.map` and its neighbours would be exactly the
        filename enumeration this phase refuses to do, and there is no code path
        here that could.

        One request per map, and none at all for an asset that publishes none.
        """
        observations: list[SourceMapObservation] = []
        referenced = [
            (response.url, response.config_signals.source_map_reference)
            for response in responses
            if response.config_signals is not None
            and response.config_signals.source_map_reference
        ][: limits.max_source_maps]

        for asset, map_url in referenced:
            self._cancellation.raise_if_cancelled(self.name)
            if map_url is None or not is_same_origin(map_url, origin):
                continue
            if not self._may_request(stats, limits):
                stats.budget_exhausted = True
                break

            stats.source_maps_checked += 1
            map_response = await self._fetch(fetcher, map_url, stats)
            reachable = map_response is not None and 200 <= map_response.status_code < 300
            observations.append(
                deployment.source_map_observation(
                    asset_url=asset,
                    map_url=map_url,
                    reachable=reachable,
                    body=map_response.body if reachable and map_response else b"",
                )
            )

        stats.source_maps_exposed = sum(1 for o in observations if o.reachable)
        return observations

    async def _fetch(
        self,
        fetcher: HttpFetcher,
        url: str,
        stats: ConfigSecurityStats,
        *,
        method: str = "GET",
    ) -> RawHttpResponse | None:
        """One safe request. Never raises: a failed candidate is not a failed scan."""
        try:
            probe_target = parse_target_url(url)
        except ScannerError:
            stats.note("invalid_candidate_url")
            return None

        try:
            stats.requests_sent += 1
            return await fetcher.fetch(probe_target, method=method)
        except ScannerError as exc:
            stats.note(f"candidate_unavailable:{exc.code.value}")
            return None
        except ScanCancelled:
            raise
        except Exception:  # noqa: BLE001 - one candidate must not end the scan
            logger.exception("Unexpected failure fetching a configuration candidate")
            stats.note("candidate_unavailable:unexpected")
            return None

    def _tally(
        self, candidates: Sequence[CandidateObservation], stats: ConfigSecurityStats
    ) -> None:
        stats.admin_endpoints_discovered = sum(
            1 for c in candidates if c.kind is CandidateKind.ADMIN and c.exposed
        )
        stats.management_endpoints_discovered = sum(
            1 for c in candidates if c.kind is CandidateKind.MANAGEMENT and c.exposed
        )
        stats.sensitive_files_exposed = sum(
            1
            for c in candidates
            if c.kind in (CandidateKind.SENSITIVE_FILE, CandidateKind.REPOSITORY, CandidateKind.BACKUP)
            and c.exposed
            and not c.path.lower().endswith("robots.txt")
        )

    # ------------------------------------------------------------------ #
    # Findings
    # ------------------------------------------------------------------ #

    def _policy_denies_anonymous(self, path: str) -> bool:
        """Whether the Phase 12 policy says an anonymous request should fail.

        Reused rather than reinvented. With no declared policy this is False,
        and the admin finding stays informational — an admin panel behind a
        login the scan was not given looks identical to one left open, and only
        the person who wrote the policy knows which it is.
        """
        matrix = self._authorization.matrix
        if not matrix.configured:
            return False
        expectation = matrix.explicit_expectation_for(_ANONYMOUS, path)
        return expectation is AccessExpectation.DENIED

    def _findings(
        self, result: ConfigSecurityResult, stats: ConfigSecurityStats
    ) -> list[tuple[str | None, FindingData]]:
        emitted: list[tuple[str | None, FindingData]] = []

        def add(url: str | None, finding: FindingData | None) -> None:
            if finding is not None:
                emitted.append((url, finding))

        transport = result.transport
        add(
            transport.final_url,
            build.insecure_http_finding(
                transport, require_https=self._settings.require_https
            ),
        )
        add(transport.final_url, build.weak_hsts_finding(transport))
        add(transport.final_url, build.tls_failure_finding(transport))

        for observation in result.methods:
            add(observation.url, build.unsafe_methods_finding(observation))

        for debug_observation in result.debug:
            add(debug_observation.url, build.debug_finding(debug_observation))

        for candidate in result.candidates:
            add(None, build.sensitive_file_finding(candidate))
            add(None, build.repository_metadata_finding(candidate))
            add(None, build.default_content_finding(candidate))
            add(
                None,
                build.admin_interface_finding(
                    candidate, policy_denies=self._policy_denies_anonymous(candidate.path)
                ),
            )
            add(
                None,
                build.management_interface_finding(
                    candidate, sensitive=_management_looks_sensitive(candidate)
                ),
            )

        for listing in result.listings:
            add(listing.url, build.directory_listing_finding(listing))

        for source_map in result.source_maps:
            add(source_map.asset_url, build.source_map_finding(source_map))

        for technology in result.technologies:
            add(technology.url, build.technology_finding(technology))

        for policy in result.csp:
            add(policy.url, build.weak_csp_finding(policy))

        for defect in result.header_defects:
            add(defect.url, build.header_defect_finding(defect))

        for observation in result.normalization:
            add(None, build.path_normalization_finding(observation))

        return emitted


# --------------------------------------------------------------------------- #


class _PassiveResult:
    """What passive analysis produced. A plain carrier, not part of the API."""

    __slots__ = ("debug", "listings", "technologies", "header_defects", "csp")

    def __init__(
        self,
        *,
        debug: tuple[DebugObservation, ...],
        listings: tuple[ListingObservation, ...],
        technologies: tuple[TechnologyObservation, ...],
        header_defects: tuple[HeaderDefectObservation, ...],
        csp: tuple[CspObservation, ...],
    ) -> None:
        self.debug = debug
        self.listings = listings
        self.technologies = technologies
        self.header_defects = header_defects
        self.csp = csp


#: Management paths whose *name* says they return configuration rather than a
#: status. `/actuator/env` dumps the environment; `/actuator/health` does not.
_SENSITIVE_MANAGEMENT_PATHS = ("/env", "/configprops", "/heapdump", "/threaddump", "/beans")


def _management_looks_sensitive(candidate: CandidateObservation) -> bool:
    """Whether a management endpoint returned more than its own liveness.

    Path-based, and narrow. A health check answering `{"status":"UP"}` is a
    correctly built health check and must not become a finding — so only the
    endpoints that exist to dump configuration qualify, plus a response large
    enough that it plainly is not a status object.
    """
    if candidate.kind is not CandidateKind.MANAGEMENT:
        return False
    lowered = candidate.path.lower()
    if any(lowered.endswith(marker) for marker in _SENSITIVE_MANAGEMENT_PATHS):
        return True
    # A bare /actuator index lists every management endpoint it exposes, which
    # is itself the map an operator surface should not be handing out.
    return lowered.rstrip("/") in ("/actuator", "/management") and bool(
        candidate.size and candidate.size > 512
    )


def _record(
    report: ScanReport, emitted: Sequence[tuple[str | None, FindingData]]
) -> None:
    """Merge into the shared aggregation. No separate findings pipeline."""
    if report.config_security is not None:
        stats = report.config_security.stats
        report.metadata["config_security_findings"] = stats.findings_count
        report.metadata["config_security_requests"] = stats.requests_sent
        report.metadata["config_candidates_checked"] = stats.candidates_checked

    if not emitted or report.analysis is None:
        return

    report.analysis.observations.extend(emitted)
    report.analysis.findings = aggregate_findings(report.analysis.observations)
