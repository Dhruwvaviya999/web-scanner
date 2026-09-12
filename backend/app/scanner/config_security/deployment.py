"""Deployment signals read out of responses the scan already has.

Four questions, all answered from bodies and headers earlier phases fetched:
is this running in debug mode, is a directory index being served, is a source
map published, and what does the stack say about itself.

Every one of them has the same failure mode — matching a word instead of a
configuration. The word "debug" appears in production pages; a blog index is
not a directory listing; `Server: nginx` is not a weakness. So each classifier
below wants *structural* evidence, and the debug detector in particular demands
two independent markers before it will call something a debug deployment.

Nothing read here is retained. A framework debug page contains stack frames,
local variables and settings — precisely the material this module exists to
report as exposed. Quoting any of it into a finding would make the report the
disclosure, so what leaves this module is a category name and a count.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from urllib.parse import urljoin

from app.scanner.config_security.types import (
    ConfigSignals,
    DebugObservation,
    DebugSignal,
    ListingObservation,
    SourceMapObservation,
    TechnologyObservation,
)

logger = logging.getLogger(__name__)

#: How much of a body is examined. A debug page announces itself in its first
#: screenful, and scanning megabytes buys nothing but memory.
_MAX_SCAN_BYTES = 65_536


def _text(body: bytes) -> str:
    return body[:_MAX_SCAN_BYTES].decode("utf-8", "replace").lower()


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            stripped = value.strip()
            return stripped or None
    return None


# --------------------------------------------------------------------------- #
# Debug and development configuration
# --------------------------------------------------------------------------- #

#: Markers that a specific framework's debug handler rendered the page. Each is
#: a string that framework emits and a production page does not.
_FRAMEWORK_DEBUG_MARKERS = (
    "werkzeug debugger",
    "django_settings_module",
    "you're seeing this error because you have <code>debug=true",
    "whoops\\exception",
    "whoops! there was an error",
    "symfony exception",
    "laravel debugbar",
    "rails.application.config",
    "action_dispatch",
    "traceback (most recent call last)",
    "<title>internal server error</title><h1>internal server error</h1>",
    "org.springframework.boot.diagnostics",
)

#: Interactive consoles. A debugger that accepts input from the page is worse
#: than one that merely shows a trace, and is called out separately.
_CONSOLE_MARKERS = (
    "werkzeug console",
    "console locked",
    "the console is locked",
    "evalex",
    "debugger pin",
)

#: Debug toolbars injected into an otherwise normal page.
_TOOLBAR_MARKERS = (
    "djdt",
    "django-debug-toolbar",
    "debug-toolbar",
    "phpdebugbar",
    "laravel-debugbar",
)

#: Development servers announcing themselves in the Server header.
_DEV_SERVER_BANNERS = (
    "werkzeug/",
    "development server",
    "webpack-dev-server",
    "vite",
    "php/",
    "rack",
)

#: Headers whose presence indicates diagnostics are switched on. Value-free
#: matching: only the header's name is used to decide.
_DEBUG_HEADERS = (
    "x-debug",
    "x-debug-token",
    "x-debug-token-link",
    "x-symfony-cache",
    "x-drupal-cache",
    "x-runtime",
    "x-django-debug",
    "server-timing",
)

#: Explicit statements of a non-production environment.
_ENVIRONMENT_MARKERS = (
    'environment": "development"',
    'environment":"development"',
    '"env": "dev"',
    '"env":"dev"',
    "app_env=local",
    "app_debug=true",
    "flask_env=development",
    "node_env=development",
)

#: Configuration dumped into a response — an env listing, a settings page.
_CONFIG_DUMP_MARKERS = (
    "<h1>phpinfo()",
    "phpinfo()</title>",
    "configuration file (php.ini)",
    '"activeprofiles"',
    "apache server status for",
    "apache server information",
)


def detect_debug(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes = b"",
    status_code: int | None = None,
    corroborated: bool = False,
) -> DebugObservation | None:
    """Recognise development configuration. Two markers, or one plus Phase 14.

    `corroborated` is set when Phase 14's error analysis already found a
    diagnostic leak on this response. That is independent evidence, so it
    substitutes for a second marker here rather than producing a second finding
    about the same page — `DebugObservation.conclusive` is where the two meet.
    """
    headers = headers or {}
    signals: list[DebugSignal] = []
    content = _text(body) if body else ""

    if content:
        if any(marker in content for marker in _FRAMEWORK_DEBUG_MARKERS):
            signals.append(DebugSignal.FRAMEWORK_DEBUG_PAGE)
        if any(marker in content for marker in _CONSOLE_MARKERS):
            signals.append(DebugSignal.INTERACTIVE_CONSOLE)
        if any(marker in content for marker in _TOOLBAR_MARKERS):
            signals.append(DebugSignal.DEBUG_TOOLBAR)
        if any(marker in content for marker in _ENVIRONMENT_MARKERS):
            signals.append(DebugSignal.ENVIRONMENT_INDICATOR)
        if any(marker in content for marker in _CONFIG_DUMP_MARKERS):
            signals.append(DebugSignal.CONFIGURATION_DUMP)

    server = (_header(headers, "server") or "").lower()
    if server and any(banner in server for banner in _DEV_SERVER_BANNERS):
        signals.append(DebugSignal.DEVELOPMENT_SERVER_BANNER)

    if any(_header(headers, name) for name in _DEBUG_HEADERS):
        signals.append(DebugSignal.DEBUG_HEADER)

    if not signals:
        return None

    unique = tuple(dict.fromkeys(signals))
    return DebugObservation(
        url=url,
        signals=unique,
        status_code=status_code,
        corroborated_by_error_analysis=corroborated,
        detail=(
            "development-mode markers were present in the response; the text that "
            "matched is not recorded"
        ),
    )


# --------------------------------------------------------------------------- #
# Directory listings
# --------------------------------------------------------------------------- #

#: Server-generated index titles. These are emitted by the server itself, not
#: by an application, which is what separates a listing from a normal page.
_LISTING_TITLES = (
    "<title>index of /",
    "<h1>index of /",
)

_NGINX_LISTING = "<h1>index of /"
_APACHE_LISTING = 'name="c"'  # Apache's sortable-column links.

#: A parent-directory link is the giveaway: no hand-written page has one.
_PARENT_LINK = re.compile(rb'<a\s+href="(?:\.\./|/[^"]*/)?"?\s*>?\s*(?:parent directory|\.\.)', re.IGNORECASE)

_LINK = re.compile(rb'<a\s+href="[^"]+"', re.IGNORECASE)


def detect_directory_listing(
    url: str, *, headers: Mapping[str, str] | None = None, body: bytes = b""
) -> ListingObservation | None:
    """Recognise a server-generated directory index.

    Requires a structural marker — an "Index of /" heading or a parent-directory
    link — not merely a page with links on it. A site's own index page is a page,
    and calling it a directory listing would be wrong on most home pages.
    """
    if not body:
        return None

    headers = headers or {}
    head = body[:_MAX_SCAN_BYTES]
    lowered = head.decode("utf-8", "replace").lower()

    style: str | None = None
    if any(marker in lowered for marker in _LISTING_TITLES):
        server = (_header(headers, "server") or "").lower()
        style = "nginx" if "nginx" in server else "apache" if "apache" in server else None
        if style is None and _APACHE_LISTING in lowered:
            style = "apache"
        if style is None and _NGINX_LISTING in lowered:
            style = "nginx"
    elif _PARENT_LINK.search(head):
        style = "generic"

    if style is None:
        return None

    return ListingObservation(
        url=url,
        entry_count=len(_LINK.findall(head)) or None,
        server_style=style,
        detail="the server returned a generated directory index rather than a page",
    )


# --------------------------------------------------------------------------- #
# Source maps
# --------------------------------------------------------------------------- #

#: The comment a bundler appends to a built asset. This is the only way a map
#: is discovered: the asset says where it is. No map name is ever guessed.
_SOURCE_MAP_REF = re.compile(
    rb"//[#@]\s*sourceMappingURL\s*=\s*([^\s*'\"]+)", re.IGNORECASE
)

#: `"sources":[ ... ]` in a source map document. Counted, never read.
_MAP_SOURCES = re.compile(rb'"sources"\s*:\s*\[(.*?)\]', re.DOTALL)


def find_source_map_reference(asset_url: str, body: bytes) -> str | None:
    """The map URL a JavaScript asset points at, if it points at one.

    Discovery is strictly by reference. A map whose name is not published by
    the asset is not looked for — guessing `app.js.map`, `main.js.map`, `…`
    would be the filename enumeration this phase refuses to do.
    """
    if not body:
        return None
    match = _SOURCE_MAP_REF.search(body[:_MAX_SCAN_BYTES])
    if match is None:
        return None
    reference = match.group(1).decode("utf-8", "replace").strip()
    if not reference or reference.startswith("data:"):
        # An inlined map is already in the asset the browser downloads. Nothing
        # is separately exposed, so there is nothing to report.
        return None
    return urljoin(asset_url, reference)


def count_map_sources(body: bytes) -> int | None:
    """How many original files a source map lists.

    A count. The file *names* are not returned and the sources array's contents
    are never read out — a map's `sourcesContent` is the application's original
    code, and this module exists to say it is reachable, not to reproduce it.
    """
    if not body:
        return None
    match = _MAP_SOURCES.search(body[:_MAX_SCAN_BYTES])
    if match is None:
        return None
    body_slice = match.group(1)
    return body_slice.count(b'"') // 2 or None


def source_map_observation(
    *,
    asset_url: str,
    map_url: str,
    reachable: bool,
    body: bytes = b"",
) -> SourceMapObservation:
    return SourceMapObservation(
        asset_url=asset_url,
        map_url=map_url,
        reachable=reachable,
        source_count=count_map_sources(body) if reachable else None,
        detail=(
            "the asset publishes a source map URL and the map answered"
            if reachable
            else "the asset publishes a source map URL that did not answer"
        ),
    )


# --------------------------------------------------------------------------- #
# Technology disclosure
# --------------------------------------------------------------------------- #

#: Headers that name software. Vetted: every one carries a product string, and
#: none of them can carry a credential, a cookie or a token.
_TECHNOLOGY_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-version",
)

#: Headers that must never be read into an observation, whatever else changes.
#: A belt-and-braces guard so a future edit to the list above cannot leak one.
_FORBIDDEN_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "www-authenticate",
    }
)

_VERSION = re.compile(r"\d+\.\d+")

#: Longest product string kept. Enough for "Apache/2.4.58 (Ubuntu)".
_MAX_VALUE = 80


def detect_technology(
    url: str, headers: Mapping[str, str] | None = None
) -> tuple[TechnologyObservation, ...]:
    """Headers naming the stack. Informational, and normal.

    Almost every web server sends one of these. The observation exists so a
    reader can see the inventory, not so the scanner can grade a default
    configuration as a weakness.
    """
    headers = headers or {}
    found: list[TechnologyObservation] = []

    for key, raw in headers.items():
        name = key.lower()
        if name in _FORBIDDEN_HEADERS or name not in _TECHNOLOGY_HEADERS:
            continue
        value = (raw or "").strip()
        if not value:
            continue
        found.append(
            TechnologyObservation(
                url=url,
                header=key,
                value=value[:_MAX_VALUE],
                versioned=bool(_VERSION.search(value)),
                detail=(
                    "the response names the software serving it, and its version"
                    if _VERSION.search(value)
                    else "the response names the software serving it"
                ),
            )
        )
    return tuple(found)


def merge_technologies(
    observations: Iterable[TechnologyObservation],
) -> tuple[TechnologyObservation, ...]:
    """One row per distinct header-and-value pair across the whole scan."""
    best: dict[tuple[str, str], TechnologyObservation] = {}
    for observation in observations:
        best.setdefault((observation.header.lower(), observation.value), observation)
    return tuple(best.values())


# --------------------------------------------------------------------------- #
# Default and sample content
# --------------------------------------------------------------------------- #

#: Default landing pages shipped by servers and frameworks. Structural strings
#: from the pages themselves, so a site that merely mentions nginx is not caught.
_DEFAULT_PAGE_MARKERS = (
    "welcome to nginx!",
    "apache2 ubuntu default page",
    "apache2 debian default page",
    "it works!",
    "iis windows server",
    "welcome to caddy",
    "test page for the apache http server",
    "this is the default welcome page",
)


def is_default_content(body: bytes) -> bool:
    """Whether a body is a server or framework default page."""
    if not body:
        return False
    return any(marker in _text(body) for marker in _DEFAULT_PAGE_MARKERS)


def javascript_assets(urls: Sequence[str], *, limit: int = 10) -> tuple[str, ...]:
    """Same-origin JavaScript the crawl already fetched."""
    found: dict[str, None] = {}
    for url in urls:
        if url.lower().split("?", 1)[0].endswith(".js"):
            found.setdefault(url, None)
        if len(found) >= limit:
            break
    return tuple(found)


# --------------------------------------------------------------------------- #
# Capture-time summary
# --------------------------------------------------------------------------- #


def signals_for(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes = b"",
    status_code: int | None = None,
) -> ConfigSignals | None:
    """Reduce a response to its deployment metadata while the body is in hand.

    Called from the crawler's capture step, at the one moment the body exists
    and is about to be discarded. Everything that survives is a boolean, a
    count, a category name or a URL the asset itself printed.

    Returns None when there is nothing notable, so the common case costs one
    attribute rather than an object per crawled page.
    """
    headers = headers or {}

    listing = detect_directory_listing(url, headers=headers, body=body)
    debug = detect_debug(url, headers=headers, body=body, status_code=status_code)
    default_page = is_default_content(body)
    map_reference = (
        find_source_map_reference(url, body)
        if url.lower().split("?", 1)[0].endswith(".js")
        else None
    )

    signals = ConfigSignals(
        directory_listing=listing is not None,
        listing_entry_count=listing.entry_count if listing else None,
        listing_style=listing.server_style if listing else None,
        debug_signals=debug.signals if debug else (),
        default_content=default_page,
        source_map_reference=map_reference,
    )
    return signals if signals.notable else None


def safe_signals_for(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes = b"",
    status_code: int | None = None,
) -> ConfigSignals | None:
    """`signals_for`, guaranteed not to raise.

    Called from the crawl loop, which has no guard of its own: an exception
    here would unwind a crawl that already gathered fifty pages, and a
    deployment summary is never worth that.
    """
    try:
        return signals_for(url, headers=headers, body=body, status_code=status_code)
    except Exception:  # noqa: BLE001 - one bad page must not end the crawl
        logger.debug("Could not summarise deployment signals", exc_info=True)
        return None
