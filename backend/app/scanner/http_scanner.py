"""HTTP transport for a scan.

This module only fetches: it issues the request, follows redirects and reads a
bounded slice of the body. Deciding what any of it means is the job of
`response_analyzer`.

Redirects are followed manually rather than by httpx so that every hop is
re-validated against the SSRF rules — a public URL that redirects to
`http://169.254.169.254/` must not be followed.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from urllib.parse import urljoin

import httpx

from app.scanner.response_analyzer import analyze_response, is_html_response
from app.scanner.types import (
    RawHttpResponse,
    ScanErrorCode,
    ScannerConfig,
    ScannerError,
    ScanReport,
    ScanTarget,
)
from app.scanner.url_validator import assert_target_allowed, parse_target_url

logger = logging.getLogger(__name__)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class HttpProbeModule:
    """Issues one GET request to the target and records the response metadata."""

    name = "http_probe"

    def __init__(self, config: ScannerConfig) -> None:
        self._config = config

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        raw = await self._fetch(target)
        report.probe = analyze_response(raw)

    async def _fetch(self, target: ScanTarget) -> RawHttpResponse:
        headers = {
            "User-Agent": self._config.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        }
        started = time.perf_counter()

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(self._config.timeout_seconds),
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

                    if response.status_code in _REDIRECT_STATUSES and location:
                        if redirect_count >= self._config.max_redirects:
                            raise ScannerError(
                                ScanErrorCode.TOO_MANY_REDIRECTS,
                                "The target exceeded the redirect limit of "
                                f"{self._config.max_redirects}.",
                            )
                        current = parse_target_url(urljoin(current.normalized_url, location))
                        redirect_count += 1
                        continue

                    # Timed at headers-received, so a slow body download is not
                    # counted as the target's response time.
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    body, truncated = await self._read_body(response)

                    return RawHttpResponse(
                        status_code=response.status_code,
                        headers=response.headers,
                        final_url=current.normalized_url,
                        is_https=current.is_https,
                        redirect_count=redirect_count,
                        elapsed_ms=elapsed_ms,
                        body=body,
                        body_truncated=truncated,
                    )
                finally:
                    await response.aclose()

    async def _read_body(self, response: httpx.Response) -> tuple[bytes, bool]:
        """Read at most `max_response_bytes` of an HTML body.

        Non-HTML responses are never downloaded — the only reason phase 2 reads a
        body at all is to recover the page title. A read that fails partway is
        tolerated: the status and headers already gathered are worth keeping.
        """
        if not is_html_response(response.headers.get("content-type")):
            return b"", False

        limit = self._config.max_response_bytes
        chunks: list[bytes] = []
        size = 0
        truncated = False

        try:
            async for chunk in response.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= limit:
                    truncated = True
                    break
        except httpx.HTTPError as exc:
            logger.info("Body read interrupted for %s: %s", response.url, type(exc).__name__)

        return b"".join(chunks)[:limit], truncated

    async def _ensure_allowed(self, target: ScanTarget) -> None:
        """Run the blocking DNS/SSRF check without stalling the event loop."""
        await asyncio.to_thread(
            assert_target_allowed,
            target.host,
            target.port,
            allow_private_networks=self._config.allow_private_networks,
        )

    async def _send(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        """Send a GET and return the response with its body still unread."""
        request = client.build_request("GET", url)
        try:
            return await client.send(request, stream=True)
        except httpx.TooManyRedirects as exc:
            raise ScannerError(
                ScanErrorCode.TOO_MANY_REDIRECTS, "The target redirected too many times."
            ) from exc
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
            raise ScannerError(
                ScanErrorCode.CONNECTION_FAILED, "Could not connect to the target."
            ) from exc
        except httpx.HTTPError as exc:
            raise ScannerError(
                ScanErrorCode.CONNECTION_FAILED, "The request to the target failed."
            ) from exc


def _is_tls_error(exc: BaseException) -> bool:
    seen: BaseException | None = exc
    while seen is not None:
        if isinstance(seen, ssl.SSLError):
            return True
        seen = seen.__cause__ or seen.__context__
    return False
