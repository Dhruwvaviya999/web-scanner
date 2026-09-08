"""Deterministic probe-request construction and generic marker generation.

Pure functions. Building a probe URL is a security-relevant operation — it is
what decides where a request goes — so it lives here, in the framework, rather
than in any detector.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

#: Placed in the parameters not under test, so the application still receives a
#: complete query. Inert and alphanumeric.
FILLER_VALUE = "1"

#: Prefix for framework-generated markers. Recognisable in a response, and
#: unlikely to collide with anything an application produces on its own.
MARKER_PREFIX = "ws"


def generate_unique_marker(length: int = 12, prefix: str = MARKER_PREFIX) -> str:
    """A fresh alphanumeric marker.

    Alphanumeric by design: it survives validation, escaping and URL-encoding
    unchanged, so a marker that fails to appear in a response was genuinely not
    reflected rather than merely mangled.

    Deliberately format-free. A detector that needs structure — brackets,
    metacharacters, a specific shape — builds it from this, because those
    requirements are vulnerability-specific and do not belong in the framework.
    """
    if length < 4:
        raise ValueError("marker length must be at least 4")
    return f"{prefix}{secrets.token_hex((length + 1) // 2)[:length]}"


def build_probe_url(endpoint_url: str, parameter: str | None, value: str) -> str:
    """`endpoint_url` with `parameter` set to `value`.

    Scheme, host, port and path are taken from the endpoint and never altered,
    so a probe cannot be aimed somewhere else by construction. Parameters other
    than the one under test keep their position and receive an inert filler —
    the crawler stores names only, so their real values are not available and
    are never needed.

    The fragment is dropped: it is not sent to a server.
    """
    parts = urlsplit(endpoint_url)
    existing = parse_qsl(parts.query, keep_blank_values=True)

    if parameter is None:
        # Nothing to vary; reissue the endpoint as discovered.
        query = [(name, val or FILLER_VALUE) for name, val in existing]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))

    names = [name for name, _ in existing]
    if parameter not in names:
        names.append(parameter)

    # Ordering is preserved so probe URLs are reproducible across runs.
    query = [(name, value if name == parameter else FILLER_VALUE) for name in names]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
