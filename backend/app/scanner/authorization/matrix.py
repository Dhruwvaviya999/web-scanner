"""The declared authorization policy: who is supposed to reach what.

This is the part a black-box scanner cannot work out for itself. Whether
`/reports/2024` should be readable by a manager is a business rule; nothing in
an HTTP response reveals it, and a scanner that guesses produces confident
nonsense. So the policy is supplied by the authorized user, and where it is
absent the answer is `UNKNOWN` — never "probably fine" and never "vulnerable".

Two kinds of statement can be made:

* **Access rules** — "context `alice` must be denied `/admin/*`".
* **Ownership** — "`/api/orders/101` belongs to `alice`". This is what makes
  object-level testing possible: every other identity is expected to be denied
  it, without the user having to write a rule per identity per object.

Matching is on the URL **path** only, with one optional trailing `*`. Query
strings are excluded deliberately: the crawler stores parameter names without
values, so a rule keyed on a query value could never match anything it stored.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.scanner.authorization.types import AccessExpectation

MAX_RULES = 200
MAX_OWNERSHIP_ENTRIES = 200
MAX_PATTERN_LENGTH = 512


class MatrixError(ValueError):
    """A declared policy that cannot be used as written."""


def normalize_pattern(raw: str) -> str:
    """A policy pattern reduced to the path form matching compares against."""
    candidate = (raw or "").strip()
    if not candidate:
        raise MatrixError("A resource pattern must not be empty.")
    if len(candidate) > MAX_PATTERN_LENGTH:
        raise MatrixError(f"A resource pattern must be at most {MAX_PATTERN_LENGTH} characters.")
    if any(ch in candidate for ch in "\r\n"):
        raise MatrixError("A resource pattern must not contain line breaks.")

    # Accept a full URL or a bare path; only the path is ever compared, so an
    # absolute URL for a different host simply cannot match anything.
    if "://" in candidate:
        candidate = urlsplit(candidate).path or "/"
    else:
        candidate = urlsplit(candidate).path or candidate

    if not candidate.startswith("/"):
        candidate = f"/{candidate}"

    # A trailing slash is not meaningful here: /admin and /admin/ are one rule.
    if len(candidate) > 1 and candidate.endswith("/") and not candidate.endswith("*"):
        candidate = candidate.rstrip("/") or "/"

    return candidate


def path_of(url: str) -> str:
    """The path of a URL, for matching. Never the query."""
    try:
        path = urlsplit(url).path or "/"
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return path


def matches(pattern: str, url: str) -> bool:
    """Whether `url` falls under `pattern`.

    Exact path match, or prefix match when the pattern ends in `*`. No regular
    expressions: a policy language a user can get subtly wrong is worse than one
    that only does the obvious thing.
    """
    path = path_of(url)
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return path.startswith(prefix)
    return path == pattern


@dataclass(frozen=True, slots=True)
class AccessRule:
    """One declared expectation: this context, this resource, this outcome."""

    context_id: str
    pattern: str
    expectation: AccessExpectation


@dataclass(frozen=True, slots=True)
class ResourceOwnership:
    """A resource and the single identity it belongs to."""

    pattern: str
    owner_context_id: str


@dataclass(frozen=True, slots=True)
class AuthorizationMatrix:
    """The declared policy. Empty by default, which means "nothing is claimed"."""

    rules: tuple[AccessRule, ...] = ()
    ownership: tuple[ResourceOwnership, ...] = ()

    @property
    def configured(self) -> bool:
        return bool(self.rules or self.ownership)

    def explicit_expectation_for(
        self, context_id: str, url: str
    ) -> AccessExpectation | None:
        """The expectation stated by a rule, or `None` if no rule matched.

        Separate from `expectation_for` because the difference matters: an
        expectation the user wrote down is stronger evidence than one the
        scanner derived from ownership, and the detector treats them
        differently.
        """
        best: AccessRule | None = None
        for rule in self.rules:
            if rule.context_id != context_id or not matches(rule.pattern, url):
                continue
            if best is None or _specificity(rule.pattern) > _specificity(best.pattern):
                best = rule
        return best.expectation if best else None

    def expectation_for(self, context_id: str, url: str) -> AccessExpectation:
        """The declared expectation for one context and URL.

        The most specific matching rule wins, so a broad `/admin/*` denial can
        be overridden by an exact `/admin/health` allowance. Ties go to the
        rule declared first, which makes the result stable and explainable.
        """
        explicit = self.explicit_expectation_for(context_id, url)
        if explicit is not None:
            return explicit

        # Ownership implies expectations without the user writing N rules: the
        # owner should be able to read their own resource, and nobody else
        # should. That second half is what makes object-level testing possible
        # from a single declaration.
        owner = self.owner_of(url)
        if owner is not None:
            return (
                AccessExpectation.ALLOWED
                if owner == context_id
                else AccessExpectation.DENIED
            )

        return AccessExpectation.UNKNOWN

    def owner_of(self, url: str) -> str | None:
        """Which context owns this resource, if the user said."""
        best: ResourceOwnership | None = None
        for entry in self.ownership:
            if not matches(entry.pattern, url):
                continue
            if best is None or _specificity(entry.pattern) > _specificity(best.pattern):
                best = entry
        return best.owner_context_id if best else None

    def declared_resources(self) -> tuple[str, ...]:
        """Concrete resources named by the policy, in declaration order.

        A pattern with a wildcard is not a resource — there is nothing specific
        to request — so only exact paths are returned. These are added to the
        endpoints under test even when the crawler never found them, which is
        what lets object-level testing reach an object the scanning identity
        was never shown.
        """
        seen: dict[str, None] = {}
        for pattern in [r.pattern for r in self.rules] + [o.pattern for o in self.ownership]:
            if not pattern.endswith("*"):
                seen.setdefault(pattern, None)
        return tuple(seen)


def _specificity(pattern: str) -> int:
    """Longer and non-wildcard patterns are more specific."""
    return len(pattern) * 2 + (0 if pattern.endswith("*") else 1)


def build_matrix(
    rules: Iterable[tuple[str, str, AccessExpectation]] = (),
    ownership: Iterable[tuple[str, str]] = (),
    *,
    known_context_ids: Sequence[str] | None = None,
) -> AuthorizationMatrix:
    """Validate and normalise a declared policy.

    A rule naming a context that was not supplied is refused rather than
    ignored: silently dropping it would leave the user believing a boundary is
    under test when nothing is testing it.
    """
    known = set(known_context_ids or ())

    parsed_rules: list[AccessRule] = []
    for context_id, pattern, expectation in rules:
        if known and context_id not in known:
            raise MatrixError(f"Rule refers to unknown context {context_id!r}.")
        parsed_rules.append(
            AccessRule(
                context_id=context_id,
                pattern=normalize_pattern(pattern),
                expectation=expectation,
            )
        )
    if len(parsed_rules) > MAX_RULES:
        raise MatrixError(f"At most {MAX_RULES} access rules can be supplied.")

    parsed_ownership: list[ResourceOwnership] = []
    seen_patterns: set[str] = set()
    for pattern, owner in ownership:
        if known and owner not in known:
            raise MatrixError(f"Ownership refers to unknown context {owner!r}.")
        normalized = normalize_pattern(pattern)
        if normalized in seen_patterns:
            # Two owners for one resource is not a policy, it is a contradiction.
            raise MatrixError(f"Resource {normalized!r} was given more than one owner.")
        seen_patterns.add(normalized)
        parsed_ownership.append(
            ResourceOwnership(pattern=normalized, owner_context_id=owner)
        )
    if len(parsed_ownership) > MAX_OWNERSHIP_ENTRIES:
        raise MatrixError(
            f"At most {MAX_OWNERSHIP_ENTRIES} ownership entries can be supplied."
        )

    return AuthorizationMatrix(
        rules=tuple(parsed_rules), ownership=tuple(parsed_ownership)
    )


@dataclass(frozen=True, slots=True)
class AuthorizationPlan:
    """Everything the authorization stage needs: identities plus policy."""

    contexts: tuple = ()
    matrix: AuthorizationMatrix = field(default_factory=AuthorizationMatrix)

    @property
    def enabled(self) -> bool:
        """At least two identities are needed for a comparison to exist."""
        return len(self.contexts) >= 2
