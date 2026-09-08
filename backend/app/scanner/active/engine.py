"""The probe engine: the only way a detector reaches the network.

Every active request funnels through `send`, and that is where scope, budget and
error handling are enforced. A detector cannot open a connection of its own —
it is handed an engine, not a transport — so there is exactly one place where
the scanner's safety rules can be applied, and no detector can be written that
bypasses them.

What the engine owns:

* **Scope.** The URL is rebuilt from an already-validated endpoint, revalidated
  through `parse_target_url`, and checked against the scan's origin. The
  underlying `HttpFetcher` re-checks every redirect hop and runs the SSRF guard
  before each connection.
* **Budget.** Every request is reserved first. An exhausted budget fails closed.
* **Errors.** Nothing raises out of `send`; a failure becomes a `ProbeOutcome`
  carrying a reason, so one bad probe can never end a scan.
* **Logging.** Endpoint path and parameter name only — never a probe value, a
  full probe URL, or a request header.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from app.scanner.active.budget import ProbeBudget
from app.scanner.cancellation import CancellationToken
from app.scanner.active.requests import build_probe_url
from app.scanner.active.types import (
    ActiveScanStats,
    ProbeFailure,
    ProbeOutcome,
    ProbeRequest,
)
from app.scanner.crawler.url_normalizer import Origin, is_same_origin
from app.scanner.http_scanner import HttpFetcher
from app.scanner.types import RawHttpResponse, ScannerError
from app.scanner.url_validator import parse_target_url

logger = logging.getLogger(__name__)


class ProbeEngine:
    """Sends detector probes within the scan's scope and budget."""

    def __init__(
        self,
        fetcher: HttpFetcher,
        origin: Origin,
        budget: ProbeBudget,
        stats: ActiveScanStats | None = None,
        cancellation: CancellationToken | None = None,
    ) -> None:
        self._fetcher = fetcher
        self._origin = origin
        self._budget = budget
        self.stats = stats or ActiveScanStats()
        self._cancellation = cancellation or CancellationToken.none()

    @property
    def budget(self) -> ProbeBudget:
        return self._budget

    def can_send(self, request: ProbeRequest) -> bool:
        """Whether the budget currently permits this probe."""
        return self._budget.can_spend(request.target.url, request.parameter)

    async def send(self, request: ProbeRequest) -> ProbeOutcome:
        """Send one probe. Never raises."""
        endpoint = request.target.url

        # --- cancellation: no new traffic once the scan is stopped -------- #
        # Checked before the budget so a cancelled scan spends nothing further.
        self._cancellation.raise_if_cancelled("ANALYZING")

        # --- budget: fail closed ------------------------------------------ #
        if not self._budget.reserve(endpoint, request.parameter):
            self.stats.budget_exhausted = True
            self.stats.note("budget_exhausted")
            return ProbeOutcome(request=request, failure=ProbeFailure.BUDGET_EXHAUSTED)

        url = build_probe_url(endpoint, request.parameter, request.value)

        # --- scope: revalidate before connecting -------------------------- #
        try:
            probe_target = parse_target_url(url)
        except ScannerError:
            self.stats.note("invalid_probe_url")
            return ProbeOutcome(request=request, failure=ProbeFailure.INVALID_URL)

        if not is_same_origin(probe_target.normalized_url, self._origin):
            self.stats.note("out_of_scope")
            return ProbeOutcome(request=request, failure=ProbeFailure.OUT_OF_SCOPE)

        # --- transport ---------------------------------------------------- #
        self.stats.requests_sent += 1
        try:
            response: RawHttpResponse = await self._fetcher.fetch(probe_target)
        except ScannerError as exc:
            self.stats.failures += 1
            self.stats.note(f"request_failed:{exc.code.value}")
            logger.debug(
                "Active probe failed: %s parameter=%s purpose=%s reason=%s",
                _safe_path(endpoint),
                request.parameter,
                request.purpose.value,
                exc.code.value,
            )
            return ProbeOutcome(request=request, failure=ProbeFailure.REQUEST_FAILED)
        except Exception:  # noqa: BLE001 - a probe must never end the scan
            self.stats.failures += 1
            self.stats.note("request_failed:unexpected")
            logger.exception("Unexpected failure sending an active probe")
            return ProbeOutcome(request=request, failure=ProbeFailure.REQUEST_FAILED)

        # A redirect chain may have ended elsewhere despite the per-hop check.
        if not is_same_origin(response.final_url, self._origin):
            self.stats.note("redirected_out_of_scope")
            return ProbeOutcome(request=request, failure=ProbeFailure.OUT_OF_SCOPE)

        logger.debug(
            "Active probe completed: %s parameter=%s purpose=%s status=%s",
            _safe_path(endpoint),
            request.parameter,
            request.purpose.value,
            response.status_code,
        )
        return ProbeOutcome(request=request, response=response)


def _safe_path(url: str) -> str:
    """The path of a URL, for logs.

    Query values are dropped: a stored endpoint URL carries only parameter
    names, but a log line should not depend on that remaining true.
    """
    try:
        return urlsplit(url).path or "/"
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return "?"
