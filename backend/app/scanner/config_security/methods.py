"""HTTP method analysis: what a target advertises versus what it demonstrates.

The distinction those two words draw is the whole module. An `Allow` header is
**documentation**. It says a server would accept `DELETE`; it does not say the
handler exists, that authorization permits it, or that anything would happen.
Finding out would mean sending a `DELETE` to somebody's endpoint, and no output
from a scanner is worth that.

So this phase sends `OPTIONS` and reads the answer, and stops. `GET`, `HEAD` and
`OPTIONS` are the only methods it will put on the wire — enforced by
`SAFE_METHODS` at the transport call site, not merely intended here.

The second discipline is refusing the obvious wrong inference. `DELETE` on a
REST resource is not a vulnerability; it is REST. `PUT` on an object-storage
endpoint is the product. What is worth reporting is a *surprise*: a method
advertised somewhere it makes no sense, or `TRACE`, which exists to echo a
request back and has no legitimate use in a deployed application.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence

from app.scanner.config_security.types import MethodObservation

_SPLIT = re.compile(r"[,\s]+")

#: Methods that change server state. Advertising one is ordinary; it is the
#: *context* that makes it worth a sentence, and never worth a request.
STATE_CHANGING = frozenset({"PUT", "PATCH", "DELETE", "POST"})

#: Methods with no place in a deployed application. TRACE and TRACK echo the
#: request, including headers a browser attached; CONNECT asks the server to
#: proxy. None is part of a normal web application's surface.
DIAGNOSTIC_METHODS = frozenset({"TRACE", "TRACK", "CONNECT"})

#: Paths where a state-changing method is unremarkable, because that is what
#: the endpoint is for. Used to keep REST out of the findings list.
_API_MARKERS = ("/api/", "/api", "/v1/", "/v2/", "/graphql", "/rest/")


def parse_methods(value: str | None) -> tuple[str, ...]:
    """Method names from an `Allow` or `Access-Control-Allow-Methods` header."""
    if not value:
        return ()
    seen: dict[str, None] = {}
    for token in _SPLIT.split(value.strip()):
        name = token.strip().upper()
        if name and name.isalpha():
            seen.setdefault(name, None)
    return tuple(seen)


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            stripped = value.strip()
            return stripped or None
    return None


def analyze_options(
    url: str,
    headers: Mapping[str, str],
    *,
    status_code: int | None = None,
    observed: Iterable[str] = (),
) -> MethodObservation:
    """Read an `OPTIONS` response. Nothing here sends anything.

    Both `Allow` and `Access-Control-Allow-Methods` are read: a CORS preflight
    answer often advertises more than the plain `Allow` does, and a method
    advertised to cross-origin callers is advertised.
    """
    allow = _header(headers, "allow")
    cors = _header(headers, "access-control-allow-methods")

    advertised: dict[str, None] = {}
    for name in parse_methods(allow) + parse_methods(cors):
        advertised.setdefault(name, None)

    seen = tuple(dict.fromkeys(m.upper() for m in observed))
    untested = tuple(m for m in advertised if m not in seen)

    return MethodObservation(
        url=url,
        advertised=tuple(advertised),
        observed=seen,
        untested=untested,
        trace_advertised="TRACE" in advertised or "TRACK" in advertised,
        allow_header=allow,
        status_code=status_code,
        detail=(
            "methods read from the response's Allow and CORS headers; none was "
            "invoked to confirm it"
        ),
    )


def looks_like_api(url: str) -> bool:
    """Whether a state-changing method here is ordinary rather than surprising."""
    lowered = url.lower()
    return any(marker in lowered for marker in _API_MARKERS)


def surprising_methods(observation: MethodObservation) -> tuple[str, ...]:
    """Advertised methods that are worth a reader's attention.

    Diagnostic methods always qualify: `TRACE` reflects request headers and has
    no application use. State-changing methods qualify only away from an API
    path — a `DELETE` on `/api/orders/1` is the design, and reporting it would
    be reporting REST.
    """
    surprising = [m for m in observation.advertised if m in DIAGNOSTIC_METHODS]
    if not looks_like_api(observation.url):
        surprising.extend(
            m
            for m in observation.advertised
            if m in STATE_CHANGING and m != "POST"
        )
    return tuple(dict.fromkeys(surprising))


def reportable(observation: MethodObservation) -> bool:
    """Whether this observation should become a finding.

    Diagnostic methods are enough on their own. Everything else needs the
    endpoint to be somewhere a state-changing method does not belong, which
    `surprising_methods` has already decided.
    """
    return bool(surprising_methods(observation))


def merge(observations: Sequence[MethodObservation]) -> tuple[MethodObservation, ...]:
    """Collapse repeated observations of one URL, keeping the fullest."""
    best: dict[str, MethodObservation] = {}
    for observation in observations:
        existing = best.get(observation.url)
        if existing is None or len(observation.advertised) > len(existing.advertised):
            best[observation.url] = observation
    return tuple(best.values())
