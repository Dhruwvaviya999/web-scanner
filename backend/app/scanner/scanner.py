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

from app.scanner.http_scanner import HttpProbeModule
from app.scanner.types import (
    ScanErrorCode,
    ScannerConfig,
    ScannerError,
    ScanModule,
    ScanReport,
)
from app.scanner.url_validator import parse_target_url

logger = logging.getLogger(__name__)


class WebScanner:
    def __init__(self, config: ScannerConfig | None = None, modules: list[ScanModule] | None = None) -> None:
        self._config = config or ScannerConfig()
        self._modules: list[ScanModule] = modules if modules is not None else [HttpProbeModule(self._config)]

    async def scan(self, raw_url: str) -> ScanReport:
        """Run every module against `raw_url`. Never raises: failures land in the report."""
        report = ScanReport(target=None)
        try:
            target = parse_target_url(raw_url)
            report.target = target
            async with asyncio.timeout(self._config.total_timeout_seconds):
                for module in self._modules:
                    await module.run(target, report)
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
