"""The single HTTP probe that makes up a phase-1 scan.

Redirects are followed manually rather than by httpx so that every hop is
re-validated against the SSRF rules — a public URL that redirects to
`http://169.254.169.254/` must not be followed.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from urllib.parse import urljoin

import httpx

from app.scanner.types import (
    HttpProbeResult,
    ScanErrorCode,
    ScannerConfig,
    ScannerError,
    ScanReport,
    ScanTarget,
)
from app.scanner.url_validator import assert_target_allowed, parse_target_url

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_MAX_HEADER_VALUE_LENGTH = 255


class HttpProbeModule:
    """Issues one GET request to the target and records the response metadata."""

    name = "http_probe"

    def __init__(self, config: ScannerConfig) -> None:
        self._config = config

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        report.probe = await self._probe(target)

    async def _probe(self, target: ScanTarget) -> HttpProbeResult:
        headers = {
            "User-Agent": self._config.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        }
        timeout = httpx.Timeout(self._config.timeout_seconds)
        started = time.perf_counter()

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers=headers,
            verify=True,
        ) as client:
            current = target
            redirect_count = 0

            while True:
                await self._ensure_allowed(current)
                response = await self._send(client, current.normalized_url)
                try:
                    location = response.headers.get("location")
                    is_redirect = response.status_code in _REDIRECT_STATUSES and location

                    if not is_redirect:
                        elapsed_ms = int((time.perf_counter() - started) * 1000)
                        return HttpProbeResult(
                            http_status_code=response.status_code,
                            response_time_ms=elapsed_ms,
                            final_url=current.normalized_url,
                            is_https=current.is_https,
                            redirect_count=redirect_count,
                            content_type=_clean_header(response.headers.get("content-type")),
                            server_header=_clean_header(response.headers.get("server")),
                        )

                    if redirect_count >= self._config.max_redirects:
                        raise ScannerError(
                            ScanErrorCode.TOO_MANY_REDIRECTS,
                            f"The target exceeded the redirect limit of {self._config.max_redirects}.",
                        )

                    next_url = urljoin(current.normalized_url, location)
                    current = parse_target_url(next_url)
                    redirect_count += 1
                finally:
                    await response.aclose()

    async def _ensure_allowed(self, target: ScanTarget) -> None:
        """Run the blocking DNS/SSRF check without stalling the event loop."""
        await asyncio.to_thread(
            assert_target_allowed,
            target.host,
            target.port,
            allow_private_networks=self._config.allow_private_networks,
        )

    async def _send(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        """Send a GET and return the response with its body still unread.

        Streaming means we pay for headers only; a multi-gigabyte target body is
        never pulled into memory.
        """
        request = client.build_request("GET", url)
        try:
            return await client.send(request, stream=True)
        except httpx.TooManyRedirects as exc:
            raise ScannerError(ScanErrorCode.TOO_MANY_REDIRECTS, "The target redirected too many times.") from exc
        except httpx.TimeoutException as exc:
            raise ScannerError(
                ScanErrorCode.TIMEOUT,
                f"The target did not respond within {self._config.timeout_seconds:.0f} seconds.",
            ) from exc
        except httpx.ConnectError as exc:
            if _is_tls_error(exc):
                raise ScannerError(
                    ScanErrorCode.TLS_ERROR,
                    "The target's TLS certificate could not be verified.",
                ) from exc
            raise ScannerError(ScanErrorCode.CONNECTION_FAILED, "Could not connect to the target.") from exc
        except httpx.HTTPError as exc:
            raise ScannerError(ScanErrorCode.CONNECTION_FAILED, "The request to the target failed.") from exc


def _is_tls_error(exc: BaseException) -> bool:
    seen = exc
    while seen is not None:
        if isinstance(seen, ssl.SSLError):
            return True
        seen = seen.__cause__ or seen.__context__
    return False


def _clean_header(value: str | None) -> str | None:
    """Trim a response header to something safe to store and display."""
    if not value:
        return None
    collapsed = " ".join(value.split())
    if not collapsed:
        return None
    return collapsed[:_MAX_HEADER_VALUE_LENGTH]
