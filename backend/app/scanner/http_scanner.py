"""HTTP transport for a scan.

This module only fetches: it issues requests, follows redirects and reads a
bounded slice of the body. Deciding what any of it means is the job of
`response_analyzer`.

Redirects are followed manually rather than by httpx so that every hop is
re-validated against the SSRF rules — a public URL that redirects to
`http://169.254.169.254/` must not be followed.

`HttpFetcher` is shared by the single-page probe and the crawler, so both get
identical redirect, SSRF and body-size behaviour from one implementation.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from collections.abc import Callable
from urllib.parse import urljoin

import httpx

from app.scanner.auth.types import AuthenticationContext
from app.scanner.response_analyzer import analyze_response, is_textual_response
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

#: Decides whether a redirect hop may be followed. Used by the crawler to keep a
#: redirect from carrying it onto another origin. Taking a plain callable avoids
#: importing the crawler package here, which would be circular.
UrlPredicate = Callable[[str], bool]


def build_client(config: ScannerConfig) -> httpx.AsyncClient:
    """An httpx client configured for scanning.

    Redirects are disabled at the client level on purpose: this module follows
    them by hand so each hop can be re-validated.
    """
    return httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(config.timeout_seconds),
        headers={
            "User-Agent": config.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        },
        verify=True,
    )


class HttpFetcher:
    """Fetches one URL, following redirects within the configured bounds."""

    def __init__(
        self,
        config: ScannerConfig,
        client: httpx.AsyncClient,
        *,
        allow_url: UrlPredicate | None = None,
        max_redirects: int | None = None,
        authentication: AuthenticationContext | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._allow_url = allow_url
        # Target authentication, not the scanner's own login. Held here so the
        # crawler, the probe engine and every detector inherit it from the one
        # transport they all share, and none of them builds an auth header.
        self._authentication = authentication or AuthenticationContext.none()
        self._max_redirects = (
            max_redirects if max_redirects is not None else config.max_redirects
        )

    async def fetch(self, target: ScanTarget, *, read_body: bool = True) -> RawHttpResponse:
        started = time.perf_counter()
        current = target
        redirect_count = 0

        while True:
            await self._ensure_allowed(current)
            response = await self._send(current.normalized_url)
            try:
                location = response.headers.get("location")

                if response.status_code in _REDIRECT_STATUSES and location:
                    if redirect_count >= self._max_redirects:
                        raise ScannerError(
                            ScanErrorCode.TOO_MANY_REDIRECTS,
                            f"The target exceeded the redirect limit of {self._max_redirects}.",
                        )

                    next_url = urljoin(current.normalized_url, location)
                    if self._allow_url is not None and not self._allow_url(next_url):
                        raise ScannerError(
                            ScanErrorCode.EXTERNAL_REDIRECT,
                            "The target redirected outside the origin being scanned.",
                        )

                    current = parse_target_url(next_url)
                    redirect_count += 1
                    continue

                # Timed at headers-received, so a slow body download is not
                # counted as the target's response time.
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                body, truncated = (
                    await self._read_body(response) if read_body else (b"", False)
                )

                return RawHttpResponse(
                    status_code=response.status_code,
                    headers=response.headers,
                    final_url=current.normalized_url,
                    is_https=current.is_https,
                    redirect_count=redirect_count,
                    elapsed_ms=elapsed_ms,
                    body=body,
                    body_truncated=truncated,
                    # get_list keeps each Set-Cookie separate; indexing the
                    # mapping would join them with commas and corrupt parsing.
                    set_cookie=tuple(response.headers.get_list("set-cookie")),
                )
            finally:
                await response.aclose()

    async def _read_body(self, response: httpx.Response) -> tuple[bytes, bool]:
        """Read at most `max_response_bytes` of an HTML body.

        Only textual bodies are downloaded — HTML for the crawler and title
        extraction, plus JSON/XML/text so the active detectors can inspect them.
        Binary responses are skipped. A read that fails partway is tolerated:
        the status and headers already gathered are worth keeping.
        """
        if not is_textual_response(response.headers.get("content-type")):
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

    async def _send(self, url: str) -> httpx.Response:
        """Send a GET and return the response with its body still unread.

        Authentication is attached per request rather than on the client, and
        only for a URL inside the authorized origin. That ordering is what stops
        a credential riding a redirect off-origin: by the time a hop is sent, it
        has already been re-parsed and re-checked, and `headers_for` refuses any
        URL the user did not authorize.
        """
        request = self._client.build_request(
            "GET", url, headers=self._authentication.headers_for(url)
        )
        try:
            return await self._client.send(request, stream=True)
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


class HttpProbeModule:
    """Issues one GET request to the target and records the response metadata."""

    name = "http_probe"

    def __init__(
        self,
        config: ScannerConfig,
        authentication: AuthenticationContext | None = None,
    ) -> None:
        self._config = config
        self._authentication = authentication

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        async with build_client(self._config) as client:
            raw = await HttpFetcher(
                self._config, client, authentication=self._authentication
            ).fetch(target)

        # Kept on the report so the security detectors can read the headers and
        # cookies without a second request to the target.
        report.raw = raw
        report.probe = analyze_response(raw)


def _is_tls_error(exc: BaseException) -> bool:
    seen: BaseException | None = exc
    while seen is not None:
        if isinstance(seen, ssl.SSLError):
            return True
        seen = seen.__cause__ or seen.__context__
    return False
