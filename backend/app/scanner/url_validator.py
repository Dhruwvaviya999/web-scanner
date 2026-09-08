"""Target URL parsing and SSRF protection.

Two separate steps, because they have different costs:

* `parse_target_url` — pure syntax. Cheap, so the API layer runs it during
  request validation and rejects malformed input with a 422.
* `assert_target_allowed` — resolves DNS and checks the resulting addresses.
  Blocking, so the scanner runs it in a worker thread just before connecting.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit

from app.scanner.types import ScanErrorCode, ScannerError, ScanTarget

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}
_SCHEME_RE = re.compile(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*):")


def _fail(code: ScanErrorCode, message: str) -> ScannerError:
    return ScannerError(code, message)


def parse_target_url(raw_url: str) -> ScanTarget:
    """Normalise and syntactically validate a user-supplied target URL."""
    candidate = (raw_url or "").strip()
    if not candidate:
        raise _fail(ScanErrorCode.INVALID_URL, "Target URL is required.")
    if len(candidate) > MAX_URL_LENGTH:
        raise _fail(ScanErrorCode.INVALID_URL, f"Target URL must be at most {MAX_URL_LENGTH} characters.")
    if any(ch.isspace() for ch in candidate):
        raise _fail(ScanErrorCode.INVALID_URL, "Target URL must not contain whitespace.")

    # Reject non-web schemes (javascript:, file:, data:, ...) before any parsing,
    # and accept "example.com" as shorthand for "https://example.com".
    scheme_match = _SCHEME_RE.match(candidate)
    if scheme_match:
        if scheme_match.group("scheme").lower() not in ALLOWED_SCHEMES:
            raise _fail(ScanErrorCode.INVALID_URL, "Only http:// and https:// URLs can be scanned.")
    else:
        candidate = f"https://{candidate}"

    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise _fail(ScanErrorCode.INVALID_URL, "Target URL could not be parsed.") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise _fail(ScanErrorCode.INVALID_URL, "Only http:// and https:// URLs can be scanned.")

    if parts.username or parts.password:
        raise _fail(ScanErrorCode.INVALID_URL, "Credentials in the URL are not supported.")

    hostname = parts.hostname
    if not hostname:
        raise _fail(ScanErrorCode.INVALID_URL, "Target URL must include a hostname.")

    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError as exc:  # urlsplit raises for a non-numeric / out-of-range port
        raise _fail(ScanErrorCode.INVALID_URL, "Target URL contains an invalid port.") from exc
    if not 1 <= port <= 65535:
        raise _fail(ScanErrorCode.INVALID_URL, "Target URL contains an invalid port.")

    host = _encode_hostname(hostname)
    netloc = f"{host}:{port}" if parts.port else host
    # Drop the fragment: it is never sent to the server.
    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))

    return ScanTarget(
        raw_url=raw_url.strip(),
        normalized_url=normalized,
        scheme=scheme,
        host=host,
        port=port,
        is_https=scheme == "https",
    )


def _encode_hostname(hostname: str) -> str:
    """Lower-case the host and punycode-encode internationalised domain names."""
    host = hostname.strip(".").lower()
    if not host:
        raise _fail(ScanErrorCode.INVALID_URL, "Target URL must include a hostname.")
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise _fail(ScanErrorCode.INVALID_URL, "Target hostname is not a valid domain name.") from exc


def _is_blocked_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for any address that is not a routable public host."""
    # Unwrap ::ffff:127.0.0.1 style addresses before classifying them.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_host(host: str, port: int) -> list[str]:
    """Resolve `host` to every address it maps to. Blocking."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise _fail(ScanErrorCode.DNS_FAILURE, f"Could not resolve host '{host}'.") from exc
    except UnicodeError as exc:
        raise _fail(ScanErrorCode.INVALID_URL, f"Invalid hostname '{host}'.") from exc

    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise _fail(ScanErrorCode.DNS_FAILURE, f"Could not resolve host '{host}'.")
    return addresses


def assert_target_allowed(host: str, port: int, *, allow_private_networks: bool) -> None:
    """Raise unless every address `host` resolves to is safe to connect to.

    Every resolved address is checked, not just the first, so a domain with a
    mixed public/private record set cannot be used to reach internal hosts.

    Known limitation: a DNS record that changes between this check and the
    connection (DNS rebinding) is not defended against here. Closing that gap
    requires pinning the resolved IP into the connection, which is planned
    alongside the phase-2 crawler.
    """
    if allow_private_networks:
        return

    for address in resolve_host(host, port):
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:  # pragma: no cover - getaddrinfo returns valid literals
            continue
        if _is_blocked_address(ip):
            raise _fail(
                ScanErrorCode.BLOCKED_TARGET,
                "This target resolves to a private or reserved network address and cannot be scanned.",
            )
