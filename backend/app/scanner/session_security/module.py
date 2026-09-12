"""The scan stage that reasons about session handling.

**It sends nothing.** Every input already exists when this runs: the
`Set-Cookie` headers the crawler kept, the canonical URLs it recorded (with
query *values* already stripped), the forms it found and never submitted, the
JWT metadata computed at capture while the body was still in hand, and the
response headers. `SessionSecurityLimits.max_requests` defaults to 0 and this
module never consults it, because it issues no request at all.

That is not a limitation to apologise for — it is what makes the stage safe to
run against a target somebody else owns. Every question this phase could answer
more confidently requires attacking a session: forging a request to test CSRF,
replaying a cookie to test binding, holding a session open to test expiry. None
of that happens. Where the evidence stops, the verdict is `UNKNOWN` and the
report says so.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence

from app.scanner.analysis.aggregator import aggregate_findings
from app.scanner.cancellation import CancellationToken
from app.scanner.crawler.types import CapturedResponse, DiscoveredForm
from app.scanner.security.types import FindingData
from app.scanner.session_security import findings as build
from app.scanner.session_security.cookie_analyzer import (
    collect_cookies,
    infer_timeout,
    plaintext_exposed,
    session_cookies,
)
from app.scanner.session_security.csrf_analyzer import (
    analyze_forms,
    find_logout_endpoints,
)
from app.scanner.session_security.exposure_analyzer import (
    analyze_json_fields,
    analyze_location_header,
    analyze_url,
)
from app.scanner.session_security.session_classifier import weakest_same_site
from app.scanner.session_security.token_analyzer import safe_find_tokens
from app.scanner.session_security.types import (
    CsrfVerdict,
    ExposureLocation,
    JwtMetadata,
    JwtObservation,
    SessionSecurityConfig,
    SessionSecurityResult,
    SessionSecurityStats,
    SessionSignals,
    UrlExposure,
)
from app.scanner.types import RawHttpResponse, ScannerConfig, ScanReport, ScanTarget

logger = logging.getLogger(__name__)

#: Framework-default session cookie names. Keeping the default tells an attacker
#: which stack is running and which identifier format to expect. Low severity,
#: and only worth saying at all as defence in depth.
_FRAMEWORK_DEFAULT_NAMES = {
    "jsessionid": "a Java servlet container",
    "phpsessid": "PHP",
    "asp.net_sessionid": "ASP.NET",
    "aspsessionid": "classic ASP",
    "connect.sid": "Express with connect-session",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "_rails_session": "Ruby on Rails",
}


class SessionSecurityModule:
    """Correlates session evidence the earlier stages already gathered."""

    name = "session_security"

    def __init__(
        self,
        config: ScannerConfig,
        session_config: SessionSecurityConfig | None = None,
        cancellation: CancellationToken | None = None,
        authenticated: bool = False,
    ) -> None:
        self._config = config
        self._session_config = session_config or SessionSecurityConfig()
        self._cancellation = cancellation or CancellationToken.none()
        self._authenticated = authenticated

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        if not self._session_config.enabled:
            report.session_security = SessionSecurityResult()
            return

        stats = SessionSecurityStats()
        limits = self._session_config.limits

        responses = self._responses(report)

        cookies = collect_cookies(
            (
                (response.url, response.is_https, response.set_cookie)
                for response in responses
            ),
            authenticated_scan=self._authenticated,
            limit=limits.max_cookies,
        )
        stats.cookies_analyzed = len(cookies)
        relevant = session_cookies(cookies)
        stats.session_cookies_identified = len(relevant)

        self._cancellation.raise_if_cancelled(self.name)

        exposures = self._exposures(report, responses, stats, limits.max_urls)
        jwts = self._jwts(responses, stats, limits.max_jwts)

        self._cancellation.raise_if_cancelled(self.name)

        forms = self._forms(report)
        csrf = analyze_forms(
            forms,
            session_cookie_present=bool(relevant),
            session_same_site=weakest_same_site(relevant),
            authenticated=self._authenticated,
            limit=limits.max_forms,
        )
        stats.forms_analyzed = len(csrf)
        stats.state_changing_forms = sum(1 for o in csrf if o.state_changing)
        stats.csrf_protected_forms = sum(
            1 for o in csrf if o.verdict is CsrfVerdict.NONE and o.token_fields
        )
        stats.csrf_potential = sum(1 for o in csrf if o.verdict is CsrfVerdict.POTENTIAL)
        stats.csrf_strong = sum(1 for o in csrf if o.verdict is CsrfVerdict.STRONG)
        stats.csrf_unknown = sum(1 for o in csrf if o.verdict is CsrfVerdict.UNKNOWN)

        timeout = infer_timeout(relevant, jwts)
        if timeout.known:
            stats.timeout_metadata_available = 1

        logout = find_logout_endpoints(
            [response.url for response in responses], forms
        )
        stats.logout_endpoints_discovered = len(logout)

        emitted = self._findings(
            exposures=exposures,
            exposed_cookies=plaintext_exposed(relevant),
            csrf=csrf,
            jwts=jwts,
            timeout=timeout,
            cookies=relevant,
            stats=stats,
        )
        stats.findings_count = len(emitted)

        report.session_security = SessionSecurityResult(
            cookies=cookies,
            url_exposures=exposures,
            csrf=csrf,
            jwts=jwts,
            timeout=timeout,
            logout=logout,
            stats=stats,
        )
        _record(report, emitted)

    # ------------------------------------------------------------------ #

    def _responses(self, report: ScanReport) -> list[CapturedResponse]:
        """Every response the scan already has. Nothing is fetched here."""
        captured: list[CapturedResponse] = []
        if report.crawl is not None:
            captured.extend(report.crawl.responses.values())

        # The initial probe response is not in the crawl map, and it is often
        # the one that sets the session cookie. Adapting it here beats
        # re-fetching, and it is the *only* response when crawling is off.
        raw = report.raw
        if raw is not None:
            captured.append(
                CapturedResponse(
                    url=raw.final_url,
                    status_code=raw.status_code,
                    content_type=None,
                    is_https=raw.is_https,
                    headers=raw.headers,
                    set_cookie=raw.set_cookie,
                    # The crawler computes this at capture; the probe does not,
                    # so it is derived here from what the probe already holds.
                    # Cookies deduplicate by name against the crawl's sighting,
                    # and JWT metadata deduplicates by algorithm and claim names,
                    # so the overlap costs nothing.
                    session_signals=_signals_from_probe(raw),
                )
            )
        return captured

    def _forms(self, report: ScanReport) -> tuple[DiscoveredForm, ...]:
        if report.crawl is None:
            return ()
        return tuple(report.crawl.forms)

    def _exposures(
        self,
        report: ScanReport,
        responses: Sequence[CapturedResponse],
        stats: SessionSecurityStats,
        limit: int,
    ) -> tuple[UrlExposure, ...]:
        """Session-like identifiers in URLs, redirects and response fields."""
        found: dict[tuple[str, str, str], UrlExposure] = {}

        def add(items: Iterable[UrlExposure]) -> None:
            for exposure in items:
                key = (exposure.url, exposure.name, exposure.location.value)
                found.setdefault(key, exposure)

        endpoints = list(report.crawl.endpoints) if report.crawl is not None else []
        for endpoint in endpoints[:limit]:
            stats.urls_analyzed += 1
            add(
                analyze_url(
                    endpoint.url,
                    parameter_names=endpoint.parameters,
                    authenticated=self._authenticated,
                )
            )

        for response in responses:
            location = response.headers.get("location") or response.headers.get(
                "Location"
            )
            add(
                analyze_location_header(
                    response.url, location, authenticated=self._authenticated
                )
            )
            shape = response.json_shape
            if shape is not None and shape.field_names:
                add(
                    analyze_json_fields(
                        response.url,
                        shape.field_names,
                        authenticated=self._authenticated,
                    )
                )

        exposures = tuple(found.values())
        stats.session_identifiers_in_urls = sum(
            1
            for exposure in exposures
            if exposure.location
            in (
                ExposureLocation.QUERY_PARAMETER,
                ExposureLocation.PATH_PARAMETER,
                ExposureLocation.LOCATION_HEADER,
            )
        )
        stats.token_exposures = len(exposures)
        return exposures

    def _jwts(
        self,
        responses: Sequence[CapturedResponse],
        stats: SessionSecurityStats,
        limit: int,
    ) -> tuple[JwtObservation, ...]:
        """JWTs recognised at capture time, placed where they were seen.

        The tokens themselves were reduced to metadata while the body was still
        in hand and discarded with it; this only rehouses what survived.
        """
        observations: list[JwtObservation] = []
        seen: set[tuple[str, str, tuple[str, ...]]] = set()

        for response in responses:
            signals = response.session_signals
            if signals is None:
                continue

            for name, metadata in signals.cookie_jwts:
                key = (name, metadata.algorithm or "", metadata.claim_names)
                if key in seen:
                    continue
                seen.add(key)
                observations.append(
                    JwtObservation(
                        location=ExposureLocation.COOKIE,
                        name=name,
                        url=response.url,
                        metadata=metadata,
                        over_https=response.is_https,
                        detail="a JSON Web Token was set as a cookie",
                    )
                )
                if len(observations) >= limit:
                    break

            for metadata in signals.body_jwts:
                key = ("body", metadata.algorithm or "", metadata.claim_names)
                if key in seen:
                    continue
                seen.add(key)
                observations.append(
                    JwtObservation(
                        location=ExposureLocation.JSON_FIELD,
                        name="response body",
                        url=response.url,
                        metadata=metadata,
                        over_https=response.is_https,
                        detail="a JSON Web Token appeared in a response body",
                    )
                )
                if len(observations) >= limit:
                    break

            if len(observations) >= limit:
                break

        stats.jwt_tokens_observed = len(observations)
        stats.jwt_metadata_observations = sum(
            1 for observation in observations if observation.metadata.decoded
        )
        return tuple(observations)

    def _findings(
        self,
        *,
        exposures: Sequence[UrlExposure],
        exposed_cookies: Sequence,
        csrf: Sequence,
        jwts: Sequence[JwtObservation],
        timeout,
        cookies: Sequence,
        stats: SessionSecurityStats,
    ) -> list[tuple[str | None, FindingData]]:
        emitted: list[tuple[str | None, FindingData]] = []

        for exposure in exposures:
            emitted.append((exposure.url, build.url_exposure_finding(exposure)))

        for cookie in exposed_cookies:
            if not self._session_config.flag_plaintext_http:
                # Counted and shown, not raised. Every local fixture and
                # development target is plain HTTP, and reporting each one as a
                # transport failure would be wrong far more often than right —
                # the same trade-off Phase 14 makes for the same reason.
                stats.note("plaintext_cookie_not_reported")
                continue
            emitted.append((cookie.set_on, build.cookie_transport_finding(cookie)))

        for observation in csrf:
            finding = build.csrf_finding(observation)
            if finding is not None:
                emitted.append((observation.page_url, finding))
            elif observation.verdict is CsrfVerdict.POTENTIAL:
                # Recorded as a counter and shown in the report, deliberately
                # not as a finding — see `csrf_finding`.
                stats.note("csrf_potential_not_reported")

        for observation in jwts:
            finding = build.jwt_finding(observation)
            if finding is not None:
                emitted.append((observation.url, finding))

        timeout_finding = build.timeout_finding(timeout)
        if timeout_finding is not None:
            emitted.append((None, timeout_finding))

        for cookie in cookies:
            stack = _FRAMEWORK_DEFAULT_NAMES.get(cookie.name.strip().lower())
            if stack is None:
                continue
            emitted.append(
                (
                    cookie.set_on,
                    build.information_disclosure_finding(
                        url=cookie.set_on or "",
                        detail=(
                            f'The session cookie is named "{cookie.name}", the default '
                            f"for {stack}, which identifies the server-side stack."
                        ),
                        subject=cookie.name,
                    ),
                )
            )

        return emitted


# --------------------------------------------------------------------------- #


def _signals_from_probe(raw: "RawHttpResponse") -> SessionSignals | None:
    """Session metadata from the probe response, computed the same way.

    The crawler does this at capture, while the body is in hand. The probe keeps
    a bounded body prefix on the report, so the equivalent is derived here rather
    than leaving the crawl-disabled case blind. As everywhere else, what survives
    is the algorithm label and the claim names — never the token.
    """
    body_jwts = safe_find_tokens(raw.body) if raw.body else ()

    cookie_jwts: list[tuple[str, JwtMetadata]] = []
    for header in raw.set_cookie:
        name, _, value = header.partition("=")
        if not value:
            continue
        for metadata in safe_find_tokens(value.split(";", 1)[0], limit=1):
            cookie_jwts.append((name.strip(), metadata))

    if not body_jwts and not cookie_jwts:
        return None
    return SessionSignals(body_jwts=body_jwts, cookie_jwts=tuple(cookie_jwts))


def _record(
    report: ScanReport, emitted: Sequence[tuple[str | None, FindingData]]
) -> None:
    """Merge into the shared aggregation. No separate findings pipeline."""
    if report.session_security is not None:
        stats = report.session_security.stats
        report.metadata["session_security_findings"] = stats.findings_count
        report.metadata["session_cookies_identified"] = stats.session_cookies_identified
        report.metadata["session_csrf_potential"] = stats.csrf_potential

    if not emitted or report.analysis is None:
        return

    report.analysis.observations.extend(emitted)
    report.analysis.findings = aggregate_findings(report.analysis.observations)
