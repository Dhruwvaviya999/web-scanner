"""One initial access check for supplied target credentials.

This is **not** an attack on authentication. It is a single GET to the URL the
user asked to scan, carrying the material they supplied, so the scan can say
whether that material looked usable before spending a crawl on it. There is one
request, to one URL the user already named. Nothing is guessed, no other
authentication endpoint is touched, nothing is retried, nothing is refreshed,
and no target state is modified.

What the result means is deliberately narrow: the origin either rejected the
credentials at that moment or it did not. It is not a claim that they are valid
for every path, for every role, or for the rest of the scan — an authenticated
session can expire while a scan is still running, and the report says so rather
than pretending otherwise.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from app.scanner.auth.types import AuthenticationContext, AuthMode, AuthOutcome, AuthStatus
from app.scanner.cancellation import CancellationToken
from app.scanner.crawler.url_normalizer import is_same_origin
from app.scanner.http_scanner import HttpFetcher, build_client
from app.scanner.types import RawHttpResponse, ScannerConfig, ScannerError, ScanReport, ScanTarget

logger = logging.getLogger(__name__)

#: Redirected *to* one of these after presenting credentials is the target
#: saying "sign in first". Recognising where the target sent us is not the same
#: as guessing where a login page might live — no URL here is ever requested.
_SIGN_IN_MARKERS = ("login", "signin", "sign-in", "sign_in", "sso", "session/new")

#: Status codes that are an explicit refusal. Nothing else is read as one.
_REFUSED_STATUSES = frozenset({401, 403})


def classify(response: RawHttpResponse, *, seed_url: str) -> AuthStatus:
    """Turn one response into an auth status. Pure, so it is fully testable."""
    if response.status_code in _REFUSED_STATUSES:
        return AuthStatus.REJECTED

    # A redirect that lands on a sign-in page is a refusal expressed as a
    # redirect. Only counted when a redirect actually happened: an application
    # whose home page simply *is* /login says nothing about the credentials.
    if response.redirect_count > 0 and _looks_like_sign_in(response.final_url):
        if not _looks_like_sign_in(seed_url):
            return AuthStatus.REJECTED

    if 200 <= response.status_code < 400:
        return AuthStatus.AVAILABLE

    # 5xx and anything else: the target's problem, not a verdict on the
    # credentials. Saying UNKNOWN keeps the report honest.
    return AuthStatus.UNKNOWN


def _looks_like_sign_in(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower()
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return False
    return any(marker in path for marker in _SIGN_IN_MARKERS)


class AuthenticationCheckModule:
    """Records whether the supplied credentials were accepted by the origin.

    Runs first, and only when credentials were supplied: an unauthenticated
    scan issues no request here at all, so Phase 1-10 behaviour is byte for byte
    unchanged when no authentication is configured.
    """

    name = "auth_check"

    def __init__(
        self,
        config: ScannerConfig,
        authentication: AuthenticationContext | None = None,
        cancellation: CancellationToken | None = None,
    ) -> None:
        self._config = config
        self._authentication = authentication or AuthenticationContext.none()
        self._cancellation = cancellation or CancellationToken.none()

    async def run(self, target: ScanTarget, report: ScanReport) -> None:
        auth = self._authentication

        if not auth.configured:
            report.auth = AuthOutcome(mode=AuthMode.NONE, status=AuthStatus.NOT_CONFIGURED)
            return

        # Cancellation is honoured before the request, so a cancelled scan never
        # sends a credential merely to find out whether it works.
        self._cancellation.raise_if_cancelled(self.name)

        status = await self._check(target)
        report.auth = AuthOutcome(mode=auth.mode, status=status)
        report.metadata["auth_mode"] = auth.mode.value
        report.metadata["auth_status"] = status.value
        logger.info(
            "Authentication check for %s: mode=%s status=%s",
            _safe_origin(target),
            auth.mode.value,
            status.value,
        )

    async def _check(self, target: ScanTarget) -> AuthStatus:
        origin = self._authentication.origin
        if origin is None:  # pragma: no cover - a configured context always has one
            return AuthStatus.UNKNOWN

        # The URL the user asked to scan, not the bare origin. It is the same
        # single request either way, and no URL is guessed — but an application
        # with a public home page would answer 200 to anything, which would let
        # a dead credential be reported as usable. Asking for the page the user
        # actually named is what makes the answer mean something.
        check_target = target

        try:
            async with build_client(self._config) as client:
                fetcher = HttpFetcher(
                    self._config,
                    client,
                    # Locked to the authorized origin: a redirect that leaves it
                    # is refused rather than followed, so the credentials cannot
                    # travel off-origin even during this check.
                    allow_url=lambda url: is_same_origin(url, origin),
                    max_redirects=self._config.max_redirects,
                    authentication=self._authentication,
                )
                response = await fetcher.fetch(check_target, read_body=False)
        except ScannerError as exc:
            # Unreachable, timed out, or redirected off-origin. None of those
            # says anything about the credentials themselves.
            logger.info(
                "Authentication check inconclusive for %s: %s",
                _safe_origin(target),
                exc.code.value,
            )
            return AuthStatus.UNKNOWN
        except Exception:  # noqa: BLE001 - a check must never end a scan
            logger.exception("Authentication check failed unexpectedly")
            return AuthStatus.UNKNOWN

        return classify(response, seed_url=check_target.normalized_url)


def _safe_origin(target: ScanTarget) -> str:
    """Origin only, for logs. Never a query string, and never a credential."""
    return f"{target.scheme}://{target.host}:{target.port}"
