"""Transport security: scheme, redirect behaviour, HSTS quality, TLS outcome.

The boundary with Phase 3 is the thing to keep straight. Phase 3 looks at one
response's headers in isolation and reports HSTS *missing*, *disabled*
(`max-age=0`) and *short*. It cannot see anything else, because it is handed a
header map and nothing else.

This module has the whole scan. So it grades the two things that only make
sense with that context:

* **`includeSubDomains`** — Phase 3 never looks at the directive. A policy
  scoped to the bare host leaves every subdomain reachable over plaintext.
* **HSTS over plain HTTP** — a header every browser discards. Phase 3 skips
  HSTS entirely on an HTTP response, correctly, so nobody reports it today.

Neither overlaps a Phase 3 rule, and `hsts_findings_suppressed` below states
which cases are deliberately left to Phase 3.

TLS lives here rather than in a file of its own because there is so little of
it. This phase runs no TLS scanner: no cipher enumeration, no downgrade, no
renegotiation, no certificate exploitation. The existing HTTP client already
verifies certificates as a side effect of connecting, and the single bit it
produces — did a verified handshake complete — is all that is recorded.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlsplit

from app.scanner.config_security.types import (
    HstsQuality,
    RedirectBehaviour,
    TlsObservation,
    TransportObservation,
    TransportScheme,
)
from app.scanner.types import ScanErrorCode

_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)\"?", re.IGNORECASE)

#: Below this an HSTS policy expires too soon to protect a returning visitor.
#: Phase 3 already reports it, using the same constant, so this module reads it
#: only to decide whether a policy is STRONG — never to report it again.
MIN_MAX_AGE_SECONDS = 15_552_000

#: Hosts where demanding HTTPS would be wrong. A development server on loopback
#: is not a production transport failure, and grading it as one trains people to
#: ignore the whole category.
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"})

_LOCAL_SUFFIXES = (".localhost", ".local", ".test", ".internal", ".invalid")


def _header(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive lookup that treats a blank header as absent."""
    for key, value in headers.items():
        if key.lower() == name:
            stripped = value.strip()
            return stripped or None
    return None


def is_local_target(host: str) -> bool:
    """Whether HTTPS expectations should be relaxed for this host.

    Name-based only, and deliberately so: the SSRF validator already decides
    what may be *reached*, and this decides only what may be *reported*. A
    private IP that resolves publicly is still exempted here, because the far
    more common case by orders of magnitude is a developer scanning their own
    machine.
    """
    lowered = (host or "").strip().lower().rstrip(".")
    if not lowered:
        return False
    if lowered in _LOCAL_HOSTS:
        return True
    if lowered.startswith("192.168.") or lowered.startswith("10."):
        return True
    if lowered.startswith("172."):
        # 172.16.0.0/12 — the second octet decides, and only 16-31 is private.
        parts = lowered.split(".")
        if len(parts) == 4 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return lowered.endswith(_LOCAL_SUFFIXES)


def parse_hsts(value: str | None) -> tuple[int | None, bool, bool]:
    """`(max_age, includeSubDomains, preload)` from a header value."""
    if not value:
        return (None, False, False)
    lowered = value.lower()
    match = _MAX_AGE.search(value)
    return (
        int(match.group(1)) if match else None,
        "includesubdomains" in lowered,
        "preload" in lowered,
    )


def grade_hsts(
    value: str | None, *, is_https: bool, max_age: int | None, include_subdomains: bool
) -> HstsQuality:
    """Grade an HSTS policy on the axes Phase 3 does not examine."""
    if value is None:
        return HstsQuality.ABSENT
    if not is_https:
        # Present, and inert: browsers ignore HSTS delivered over plaintext.
        return HstsQuality.INEFFECTIVE_OVER_HTTP
    if max_age is None or max_age == 0:
        # Malformed or explicitly disabled. Phase 3 reports max-age=0; a header
        # with no parseable max-age is not this module's to grade either.
        return HstsQuality.UNKNOWN
    if max_age < MIN_MAX_AGE_SECONDS:
        # Short. Phase 3 already says so, and saying it twice helps nobody.
        return HstsQuality.UNKNOWN
    return HstsQuality.STRONG if include_subdomains else HstsQuality.HOST_ONLY


def classify_tls(
    *, is_https: bool, reached: bool, error_code: ScanErrorCode | None
) -> TlsObservation:
    """What the transport established. Never more specific than the evidence.

    A rejected certificate is reported as rejected. Which defect it had —
    expired, self-signed, wrong host, untrusted issuer — is not determined,
    because the client does not tell us and guessing would put a specific claim
    into a report on no evidence.
    """
    if not is_https:
        return TlsObservation.NOT_ATTEMPTED
    if error_code is ScanErrorCode.TLS_ERROR:
        return TlsObservation.CERTIFICATE_REJECTED
    if error_code in (
        ScanErrorCode.CONNECTION_FAILED,
        ScanErrorCode.DNS_FAILURE,
        ScanErrorCode.TIMEOUT,
    ):
        return TlsObservation.UNREACHABLE
    return TlsObservation.VERIFIED if reached else TlsObservation.UNKNOWN


def classify_redirect(
    *, requested_https: bool, final_url: str | None, redirect_count: int
) -> RedirectBehaviour:
    """What a plaintext request did about upgrading itself."""
    if requested_https:
        # There was no plaintext request. "No redirect" would be a lie.
        return RedirectBehaviour.NOT_APPLICABLE
    if not final_url:
        return RedirectBehaviour.UNKNOWN

    scheme = urlsplit(final_url).scheme.lower()
    if scheme == "https":
        return RedirectBehaviour.REDIRECTS_TO_HTTPS
    if redirect_count > 0:
        return RedirectBehaviour.REDIRECTS_TO_HTTP
    return RedirectBehaviour.SERVES_OVER_HTTP


def analyze(
    *,
    host: str,
    requested_https: bool,
    final_url: str | None,
    redirect_count: int,
    headers: Mapping[str, str],
    reached: bool = True,
    error_code: ScanErrorCode | None = None,
) -> TransportObservation:
    """The whole transport picture for one target. Pure."""
    final_scheme = urlsplit(final_url).scheme.lower() if final_url else ""
    is_https = final_scheme == "https" if final_url else requested_https

    raw = _header(headers, "strict-transport-security")
    max_age, include_subdomains, preload = parse_hsts(raw)

    redirect = classify_redirect(
        requested_https=requested_https,
        final_url=final_url,
        redirect_count=redirect_count,
    )
    quality = grade_hsts(
        raw,
        is_https=is_https,
        max_age=max_age,
        include_subdomains=include_subdomains,
    )

    if is_https:
        scheme = TransportScheme.HTTPS
    elif final_url or requested_https is False:
        scheme = TransportScheme.HTTP
    else:  # pragma: no cover - defensive
        scheme = TransportScheme.UNKNOWN

    return TransportObservation(
        scheme=scheme,
        redirect=redirect,
        tls=classify_tls(is_https=is_https, reached=reached, error_code=error_code),
        hsts_present=raw is not None,
        hsts_quality=quality,
        hsts_max_age=max_age,
        hsts_include_subdomains=include_subdomains,
        hsts_preload=preload,
        local_target=is_local_target(host),
        final_url=final_url,
        detail=_describe(scheme, redirect, quality),
    )


def _describe(
    scheme: TransportScheme, redirect: RedirectBehaviour, quality: HstsQuality
) -> str:
    if scheme is TransportScheme.HTTPS:
        base = "the target was reached over HTTPS"
    elif scheme is TransportScheme.HTTP:
        base = "the target was reached over plain HTTP"
    else:
        base = "the transport used could not be established"

    if redirect is RedirectBehaviour.REDIRECTS_TO_HTTPS:
        base += ", after a plaintext request was redirected to HTTPS"
    elif redirect is RedirectBehaviour.SERVES_OVER_HTTP:
        base += ", and no redirect to HTTPS was offered"

    if quality is HstsQuality.HOST_ONLY:
        base += "; HSTS covers this host but not its subdomains"
    elif quality is HstsQuality.INEFFECTIVE_OVER_HTTP:
        base += "; an HSTS header was sent that browsers will ignore"
    return base


def hsts_findings_suppressed(observation: TransportObservation) -> tuple[str, ...]:
    """Which HSTS conclusions this module deliberately leaves to Phase 3.

    Exists so the boundary is documented in code rather than in a comment
    somebody has to trust. Anything named here must not become a Phase 16
    finding, because a Phase 3 rule already covers it.
    """
    suppressed: list[str] = []
    if observation.hsts_quality is HstsQuality.ABSENT and observation.secure_transport:
        suppressed.append("SECURITY_HEADER_HSTS_MISSING")
    if observation.hsts_max_age == 0:
        suppressed.append("SECURITY_HEADER_HSTS_DISABLED")
    if (
        observation.hsts_max_age is not None
        and 0 < observation.hsts_max_age < MIN_MAX_AGE_SECONDS
    ):
        suppressed.append("SECURITY_HEADER_HSTS_SHORT_MAX_AGE")
    return tuple(suppressed)
