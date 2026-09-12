"""Path normalization: noticing that two layers disagree about a URL.

When a proxy and an application resolve the same URL differently, access rules
written for one spelling can be bypassed with another. That is a real class of
configuration bug, and it is the reason OWASP lists path confusion under
configuration testing.

**This module detects the disagreement; it does not try to exploit it.** No
traversal payload is sent, no encoded path is fuzzed, no `..%2f` variant is
constructed. Everything below is computed from endpoints the crawl already
reached — the evidence is that two spellings both answered, which is something
the scan learned while doing something else.

That restraint costs sensitivity, and it should. Sending a few hundred encoded
paths at somebody's server to see which get through is an attack, and it is
what this phase exists to stay on the right side of.

The false-positive risk is the mirror image. Most frameworks serve `/about` and
`/about/` identically and that is entirely normal, so a divergence is only worth
recording when the two spellings answered *differently* — different status, or
one redirecting where the other did not. Two identical 200s are a router being
tolerant, not a misconfiguration.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

from app.scanner.config_security.types import (
    NormalizationObservation,
    NormalizationSignal,
)


def _path(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return url


def _canonical(path: str) -> str:
    """A path reduced to the form that ignores a trailing slash."""
    stripped = path.rstrip("/")
    return stripped or "/"


def analyze(
    responses: Mapping[str, int],
    *,
    redirects: Mapping[str, str] | None = None,
    limit: int = 20,
) -> tuple[NormalizationObservation, ...]:
    """Normalization disagreements across what the crawl already fetched.

    `responses` maps URL to status code; `redirects` maps a URL to where it
    pointed. Both come from responses the scan holds, so this adds no traffic.
    """
    redirects = redirects or {}
    observed: list[NormalizationObservation] = []

    # --- trailing-slash divergence ------------------------------------- #
    #
    # Group the URLs by their slash-insensitive path. A group with more than
    # one spelling is only interesting when the spellings behaved differently.
    by_canonical: dict[str, dict[str, int]] = {}
    for url, status in responses.items():
        path = _path(url)
        by_canonical.setdefault(_canonical(path), {})[path] = status

    for canonical, spellings in by_canonical.items():
        if len(spellings) < 2:
            continue
        statuses = set(spellings.values())
        if len(statuses) == 1 and 200 <= next(iter(statuses)) < 300:
            # Both worked and agreed. A tolerant router, not a defect.
            continue
        observed.append(
            NormalizationObservation(
                signal=NormalizationSignal.TRAILING_SLASH_DIVERGENCE,
                paths=tuple(sorted(spellings)),
                detail=(
                    f"the same resource ({canonical}) answered differently depending on "
                    "the trailing slash; access rules written for one spelling may not "
                    "cover the other"
                ),
            )
        )
        if len(observed) >= limit:
            return tuple(observed)

    # --- a redirect that changes what the path addresses ---------------- #
    for url, location in redirects.items():
        source = _path(url)
        target = _path(location)
        if not target or source == target:
            continue
        if _canonical(source) == _canonical(target):
            # Adding or removing a trailing slash is the normal, correct
            # redirect. It is the opposite of a problem.
            continue
        if target.startswith(source.rstrip("/") + "/"):
            # Redirecting deeper into the same tree is ordinary routing.
            continue
        observed.append(
            NormalizationObservation(
                signal=NormalizationSignal.REDIRECT_REWRITES_PATH,
                paths=(source, target),
                detail=(
                    "a redirect rewrote the path to something outside the tree it was "
                    "requested under, so the URL a rule matches is not the URL that "
                    "eventually serves the content"
                ),
            )
        )
        if len(observed) >= limit:
            break

    return tuple(observed)


def duplicate_representations(
    urls: Sequence[str], *, limit: int = 20
) -> tuple[NormalizationObservation, ...]:
    """One resource reachable under two different spellings.

    Case and percent-encoding only, and only among URLs the crawl already
    fetched. Nothing is constructed: if the scan never saw both spellings, this
    reports nothing rather than going looking.
    """
    by_key: dict[str, set[str]] = {}
    for url in urls:
        path = _path(url)
        key = path.lower().replace("%2f", "/").replace("%2e", ".")
        by_key.setdefault(key, set()).add(path)

    observed: list[NormalizationObservation] = []
    for spellings in by_key.values():
        if len(spellings) < 2:
            continue
        observed.append(
            NormalizationObservation(
                signal=NormalizationSignal.DUPLICATE_REPRESENTATION,
                paths=tuple(sorted(spellings)),
                detail=(
                    "the same resource answered under more than one spelling; a rule "
                    "matching one form does not necessarily match the others"
                ),
            )
        )
        if len(observed) >= limit:
            break
    return tuple(observed)
