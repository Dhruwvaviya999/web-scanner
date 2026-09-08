"""URL normalisation and same-origin scoping.

Pure functions, independently testable. Two distinct forms of a URL matter here:

* **fetch form** — what the crawler actually requests, query values intact,
  because `/search?q=phone` and `/search?q=` return different pages.
* **canonical form** — what gets stored and de-duplicated on, with query
  *values* stripped and parameter names sorted.

The split is what lets the crawler store `https://example.com/search?category&q`
instead of a URL that might carry a session token, while still fetching real
pages. See `canonical_url`.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

#: Only web schemes are crawled. Anything else — mailto:, javascript:, tel:,
#: data:, ftp: — is discarded during link extraction.
CRAWLABLE_SCHEMES = frozenset({"http", "https"})

DEFAULT_PORTS = {"http": 80, "https": 443}

MAX_URL_LENGTH = 2048


@dataclass(frozen=True, slots=True)
class Origin:
    """A scheme/host/port triple. Equality here is the same-origin rule."""

    scheme: str
    host: str
    port: int

    @property
    def base_url(self) -> str:
        if self.port == DEFAULT_PORTS.get(self.scheme):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.base_url


def origin_of(url: str) -> Origin | None:
    """The origin of an absolute http(s) URL, or None if it has none."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in CRAWLABLE_SCHEMES or not parts.hostname:
        return None

    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError:
        return None

    return Origin(scheme=scheme, host=parts.hostname.lower(), port=port)


def is_same_origin(url: str, origin: Origin) -> bool:
    """True only for an exact scheme/host/port match.

    Deliberately strict: `http://` and `https://` on the same host are different
    origins, and a subdomain is a different host. The crawler never widens its
    scope on its own.
    """
    return origin_of(url) == origin


def normalize_url(raw: str, base: str | None = None) -> str | None:
    """Resolve `raw` against `base` and return a canonicalised absolute URL.

    Returns None when the link is not something to crawl: an unsupported
    scheme, a bare fragment, or an unparseable value. Normalisation strips the
    fragment, lower-cases scheme and host, drops a redundant default port and
    supplies a "/" path — so `https://EXAMPLE.com:443` and
    `https://example.com/#top` both collapse to `https://example.com/`.
    """
    if raw is None:
        return None

    candidate = raw.strip()
    if not candidate:
        return None

    # A pure fragment refers to the current page, so there is nothing new to fetch.
    if candidate.startswith("#"):
        return None

    if base:
        try:
            candidate = urljoin(base, candidate)
        except ValueError:
            return None

    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in CRAWLABLE_SCHEMES:
        return None
    if not parts.hostname:
        return None

    try:
        port = parts.port
    except ValueError:
        return None

    host = parts.hostname.lower()
    netloc = host if port in (None, DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    path = parts.path or "/"

    # Fragments are never sent to the server and never crawled.
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))
    if len(normalized) > MAX_URL_LENGTH:
        return None
    return normalized


def query_parameter_names(url: str) -> tuple[str, ...]:
    """Sorted, de-duplicated query parameter names. Values are discarded."""
    try:
        query = urlsplit(url).query
    except ValueError:
        return ()
    if not query:
        return ()

    names = {name for name, _value in parse_qsl(query, keep_blank_values=True) if name}
    return tuple(sorted(names))


def canonical_url(url: str) -> str:
    """The storable, de-duplicating form of a URL.

    Query *values* are removed and parameter names sorted, so
    `/search?q=phone&category=shoes` and `/search?category=hats&q=laptop` both
    become `/search?category&q`. Two benefits: the crawler treats them as one
    endpoint rather than crawling every variant, and no query value — which
    might be a token or an email address — is ever persisted.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return url

    names = query_parameter_names(url)
    query = "&".join(names)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))


def path_of(url: str) -> str:
    """The path component, defaulting to "/"."""
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return "/"
