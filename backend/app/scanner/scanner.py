"""Scan orchestrator.

`WebScanner` validates the target, then runs each registered module in order,
letting every module contribute to a shared `ScanReport`. Phase 1 registers a
single module; the crawler, header analyser, TLS analyser and the active
XSS/SQLi checks planned for later phases slot into the same list without any
change to the service or API layers.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from app.scanner.analysis.module import EndpointAnalysisModule
from app.scanner.api.module import ApiDiscoveryModule
from app.scanner.api.types import ApiDiscoveryConfig
from app.scanner.api_security.module import ApiSecurityModule
from app.scanner.api_security.types import ApiSecurityConfig
from app.scanner.auth.health import AuthenticationCheckModule
from app.scanner.auth.types import AuthenticationContext
from app.scanner.authorization.matrix import AuthorizationPlan
from app.scanner.authorization.module import AuthorizationModule
from app.scanner.authorization.types import AuthorizationConfig
from app.scanner.cancellation import CancellationToken, ScanCancelled
from app.scanner.active.module import ActiveScanConfig, ActiveScanModule
from app.scanner.active.types import ActiveDetector
from app.scanner.vulnerabilities.xss.detector import ReflectedXssDetector
from app.scanner.crawler.module import CrawlModule
from app.scanner.crawler.types import CrawlConfig
from app.scanner.http_scanner import HttpProbeModule
from app.scanner.types import (
    ScanErrorCode,
    ScannerConfig,
    ScannerError,
    ScanModule,
    ScanReport,
)
from app.scanner.config_security.module import ConfigSecurityModule
from app.scanner.config_security.types import ConfigSecurityConfig
from app.scanner.session_security.module import SessionSecurityModule
from app.scanner.session_security.types import SessionSecurityConfig
from app.scanner.url_validator import parse_target_url

logger = logging.getLogger(__name__)


class WebScanner:
    def __init__(
        self,
        config: ScannerConfig | None = None,
        modules: list[ScanModule] | None = None,
        crawl_config: CrawlConfig | None = None,
        active_config: ActiveScanConfig | None = None,
        detectors: list[ActiveDetector] | None = None,
        cancellation: CancellationToken | None = None,
        on_module_start: "Callable[[str], None] | None" = None,
        authentication: AuthenticationContext | None = None,
        authz_config: AuthorizationConfig | None = None,
        authorization: AuthorizationPlan | None = None,
        api_config: ApiDiscoveryConfig | None = None,
        api_security_config: ApiSecurityConfig | None = None,
        session_config: SessionSecurityConfig | None = None,
        config_security: ConfigSecurityConfig | None = None,
    ) -> None:
        # Configuration and deployment analysis. Bounded GET/HEAD/OPTIONS
        # against fixed candidate lists; no enumeration of any kind.
        self._config_security = config_security or ConfigSecurityConfig()
        # Session analysis. Correlates cookies, URLs, forms and token metadata
        # the earlier stages already captured; sends nothing.
        self._session_config = session_config or SessionSecurityConfig()
        # API security analysis. Reads what the other stages captured; sends
        # nothing of its own.
        self._api_security_config = api_security_config or ApiSecurityConfig()
        # API reconnaissance. Classifies the discovered surface and reads any
        # specification the target publishes; exploits nothing.
        self._api_config = api_config or ApiDiscoveryConfig()
        # Authorization testing: identities and the policy they are measured
        # against, both supplied by the authorized user. Disabled unless at
        # least two identities were given, since a comparison needs two sides.
        self._authz_config = authz_config or AuthorizationConfig()
        self._authorization = authorization or AuthorizationPlan()
        # Target authentication, supplied by the authorized user for their own
        # application. Held once, at the top, and handed down to the transport
        # each module builds — never to a detector.
        self._authentication = authentication or AuthenticationContext.none()
        # Cooperative cancellation. The scanner never learns how the flag is
        # stored — it is handed a predicate and asks at safe boundaries.
        self._cancellation = cancellation or CancellationToken.none()
        # Coarse progress: called with each module's name as it begins, so the
        # caller can persist a stage without the scanner knowing what a
        # "stage" means in the application.
        self._on_module_start = on_module_start
        self._config = config or ScannerConfig()
        self._crawl_config = crawl_config or CrawlConfig()
        self._active_config = active_config or ActiveScanConfig()
        # Which active detectors run. Kept a caller-supplied list so the scanner
        # package needs no knowledge of application settings.
        self._detectors: list[ActiveDetector] = (
            detectors if detectors is not None else [ReflectedXssDetector()]
        )
        # Order matters: the probe fetches, then the detectors interpret what it
        # fetched. Later phases append further modules to this list.
        self._modules: list[ScanModule] = (
            modules
            if modules is not None
            else [
                # Probe the seed, crawl from where it landed, then assess every
                # endpoint the crawl captured. Analysis runs last because it
                # consumes what the earlier stages produced.
                # Confirms the supplied credentials before a crawl is spent
                # on them. Issues no request at all when none were supplied.
                AuthenticationCheckModule(
                    self._config, self._authentication, self._cancellation
                ),
                HttpProbeModule(self._config, self._authentication),
                CrawlModule(
                    self._config,
                    self._crawl_config,
                    self._cancellation,
                    self._authentication,
                ),
                EndpointAnalysisModule(self._cancellation),
                # After the crawl, before active probing: the classification it
                # produces describes the same surface the detectors go on to
                # test, and it must be available to whatever reads the report.
                ApiDiscoveryModule(
                    self._config,
                    self._api_config,
                    self._cancellation,
                    self._authentication,
                ),
                # Active probing runs last: it needs the discovered parameters,
                # and its findings join the same aggregation. Adding a detector
                # later means extending this list, nothing more.
                ActiveScanModule(
                    self._config,
                    self._active_config,
                    self._detectors,
                    self._cancellation,
                    self._authentication,
                ),
                # Last: it compares identities against the surface every earlier
                # stage discovered, and adds no surface of its own.
                AuthorizationModule(
                    self._config,
                    self._authz_config,
                    self._authorization,
                    self._cancellation,
                ),
                # Last of all: it reads the API surface, the captured responses
                # and the authorization observations that every stage before it
                # produced, and issues no request of its own.
                ApiSecurityModule(
                    self._config,
                    self._api_security_config,
                    self._cancellation,
                    self._authorization,
                    self._authentication.configured,
                ),
                # After everything else, because it correlates across all of it:
                # the cookies the probe and crawl collected, the URLs the crawl
                # recorded, the forms it never submitted, and the token metadata
                # computed at capture. It issues no request either.
                SessionSecurityModule(
                    self._config,
                    self._session_config,
                    self._cancellation,
                    self._authentication.configured,
                ),
                # Last, and the only late stage that sends anything: it reads
                # the transport and the captured responses every earlier stage
                # produced, then requests a small fixed list of deployment
                # paths through the same fetcher, origin lock and credential
                # scoping as everything before it.
                ConfigSecurityModule(
                    self._config,
                    self._config_security,
                    self._cancellation,
                    self._authentication,
                    self._authorization,
                ),
            ]
        )

    async def scan(self, raw_url: str) -> ScanReport:
        """Run every module against `raw_url`. Never raises: failures land in the report."""
        report = ScanReport(target=None)
        try:
            target = parse_target_url(raw_url)
            report.target = target
            async with asyncio.timeout(self._config.total_timeout_seconds):
                for module in self._modules:
                    # Between modules is the cheapest safe boundary there is:
                    # nothing is in flight and the report is consistent.
                    self._cancellation.raise_if_cancelled(module.name)
                    if self._on_module_start is not None:
                        self._on_module_start(module.name)
                    await module.run(target, report)
        except ScanCancelled:
            # Not a failure. Everything gathered before the stop stands.
            report.cancelled = True
            logger.info("Scan cancelled for target %r", raw_url)
        except ScannerError as exc:
            report.error_code = exc.code
            report.error_message = exc.message
        except TimeoutError:
            report.error_code = ScanErrorCode.TIMEOUT
            report.error_message = (
                f"The scan exceeded the {self._config.total_timeout_seconds:.0f} second limit."
            )
        except Exception:  # noqa: BLE001 - the report must never leak internals
            # Log the real cause server-side; the client sees a generic message.
            logger.exception("Unhandled scanner failure for target %r", raw_url)
            report.error_code = ScanErrorCode.UNEXPECTED
            report.error_message = "The scan failed because of an unexpected error."
        return report

    def scan_sync(self, raw_url: str) -> ScanReport:
        """Blocking wrapper for callers running in a worker thread.

        FastAPI executes the synchronous scan endpoints in a threadpool, so each
        call gets its own event loop here. The scanner itself stays async, which
        is what will let the phase-2 crawler fetch pages concurrently.
        """
        return asyncio.run(self.scan(raw_url))
