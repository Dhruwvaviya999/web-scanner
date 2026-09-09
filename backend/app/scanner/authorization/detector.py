"""Turning a set of per-context responses into authorization observations.

Pure: responses in, observations out. No transport, no budget, no cancellation —
those belong to the module. Keeping the judgement here is what makes every
decision in this file testable by handing it canned responses.

**The rule that governs everything below:** a finding requires all three of

1. a declared expectation of `DENIED` for this context and resource,
2. a reference identity that was actually served the resource, and
3. the subject receiving materially the same content as that reference.

Drop any one and the result is `UNKNOWN`. That is not caution for its own sake.
Without (1) the scanner would be inventing policy; without (2) it cannot know
what "the resource" even looks like; without (3) a 200 carrying an empty list or
a shared template would read as a data leak.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from app.scanner.authorization.comparator import (
    classify_access,
    equivalent,
    fingerprint,
    similarity,
)
from app.scanner.authorization.matrix import AuthorizationMatrix
from app.scanner.authorization.types import (
    AccessExpectation,
    AuthorizationConfig,
    AuthorizationContext,
    AuthorizationObservation,
    AuthorizationTestKind,
    ComparisonVerdict,
    ObservedAccess,
)
from app.scanner.types import RawHttpResponse


def analyze_resource(
    url: str,
    contexts: Sequence[AuthorizationContext],
    responses: Mapping[str, RawHttpResponse | None],
    matrix: AuthorizationMatrix,
    config: AuthorizationConfig,
    field_sets: Mapping[str, tuple[str, ...]] | None = None,
) -> list[AuthorizationObservation]:
    """Compare every context's access to one resource.

    `responses` maps context id to what that context received, or `None` when
    the request failed or was never sent.
    """
    observed: dict[str, ObservedAccess] = {}
    for context in contexts:
        response = responses.get(context.id)
        observed[context.id] = (
            ObservedAccess.INCONCLUSIVE
            if response is None
            else classify_access(response, requested_url=url)
        )

    reference = _reference_context(url, contexts, responses, observed, matrix)

    return [
        _observe(
            url,
            context,
            contexts,
            responses,
            observed,
            matrix,
            config,
            reference,
            (field_sets or {}).get(context.id, ()),
        )
        for context in contexts
    ]


def _reference_context(
    url: str,
    contexts: Sequence[AuthorizationContext],
    responses: Mapping[str, RawHttpResponse | None],
    observed: Mapping[str, ObservedAccess],
    matrix: AuthorizationMatrix,
) -> AuthorizationContext | None:
    """The identity whose response defines what "the resource" looks like.

    The declared owner when there is one; otherwise the most privileged identity
    that both was *supposed* to have access and actually received it. Requiring
    the expectation, not merely the response, is deliberate: a context that got
    a 200 it was never meant to get is evidence of a problem, not a yardstick to
    measure other contexts against.
    """
    owner_id = matrix.owner_of(url)
    if owner_id is not None:
        for context in contexts:
            if (
                context.id == owner_id
                and observed.get(context.id) is ObservedAccess.ALLOWED
                and responses.get(context.id) is not None
            ):
                return context
        return None

    candidates = [
        context
        for context in contexts
        if observed.get(context.id) is ObservedAccess.ALLOWED
        and responses.get(context.id) is not None
        and matrix.expectation_for(context.id, url) is AccessExpectation.ALLOWED
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda c: c.privilege_rank)


def _observe(
    url: str,
    context: AuthorizationContext,
    contexts: Sequence[AuthorizationContext],
    responses: Mapping[str, RawHttpResponse | None],
    observed: Mapping[str, ObservedAccess],
    matrix: AuthorizationMatrix,
    config: AuthorizationConfig,
    reference: AuthorizationContext | None,
    json_fields: tuple[str, ...] = (),
) -> AuthorizationObservation:
    response = responses.get(context.id)
    expected = matrix.expectation_for(context.id, url)
    access = observed[context.id]
    observed_fingerprint = fingerprint(response) if response is not None else None

    def build(
        verdict: ComparisonVerdict,
        *,
        kind: AuthorizationTestKind | None = None,
        equivalent_to_reference: bool | None = None,
        detail: str = "",
    ) -> AuthorizationObservation:
        return AuthorizationObservation(
            kind=kind or _kind_for(context, reference, url, matrix),
            context_id=context.id,
            context_label=context.display_name,
            reference_context_id=reference.id if reference else None,
            url=url,
            expected=expected,
            observed=access,
            verdict=verdict,
            equivalent_to_reference=equivalent_to_reference,
            fingerprint=observed_fingerprint,
            json_fields=json_fields,
            detail=detail,
        )

    if response is None:
        return build(ComparisonVerdict.UNKNOWN, detail="no response was obtained")

    if expected is AccessExpectation.UNKNOWN:
        # The most common outcome on a real site, and the correct one: nobody
        # told the scanner what should happen here, so it says so.
        return build(
            ComparisonVerdict.UNKNOWN,
            detail="no expected access was declared for this context and resource",
        )

    if access is ObservedAccess.INCONCLUSIVE:
        return build(
            ComparisonVerdict.UNKNOWN,
            detail="the response neither granted nor refused access",
        )

    if expected is AccessExpectation.ALLOWED:
        if access is ObservedAccess.ALLOWED:
            return build(ComparisonVerdict.MATCHES_POLICY)
        # Denied where the policy expects access. Fail-safe, so never a finding,
        # but the declared policy and the application disagree and somebody
        # should know which one is wrong.
        return build(
            ComparisonVerdict.CONFLICT,
            detail="access was expected but the target refused it",
        )

    # expected is DENIED from here on.
    if access is ObservedAccess.DENIED:
        return build(ComparisonVerdict.MATCHES_POLICY)

    if _privileged_over_owner(context, contexts, url, matrix):
        # Ownership says who a resource belongs to. It does not say that a more
        # privileged identity may not read it — most applications intend exactly
        # the opposite, and deciding otherwise would be the scanner inventing a
        # business rule. A user who does want that boundary tested writes it as
        # an explicit rule, which takes precedence over this.
        return build(
            ComparisonVerdict.UNKNOWN,
            detail=(
                "this identity is more privileged than the resource's owner, and "
                "no explicit rule says it should be denied"
            ),
        )

    if reference is None or reference.id == context.id:
        return build(
            ComparisonVerdict.UNKNOWN,
            detail=(
                "the request succeeded, but no identity that is supposed to have "
                "this resource was available to compare against"
            ),
        )

    reference_response = responses.get(reference.id)
    if reference_response is None:  # pragma: no cover - reference implies a response
        return build(ComparisonVerdict.UNKNOWN, detail="the reference response was missing")

    same = equivalent(reference_response, response, config)
    if not same:
        # Got a 200, but not the protected thing. Very often an empty list, a
        # generic shell, or the caller's own view of a shared route. Reporting
        # this as a breach is the single biggest source of false positives in
        # authorization scanning.
        ratio = round(similarity(reference_response, response), 3)
        return build(
            ComparisonVerdict.UNKNOWN,
            equivalent_to_reference=False,
            detail=(
                "the request succeeded but returned different content from the "
                f"reference identity (similarity {ratio})"
            ),
        )

    return build(
        ComparisonVerdict.VIOLATION,
        equivalent_to_reference=True,
        detail=f"content matches what {reference.display_name!r} receives",
    )


def _kind_for(
    context: AuthorizationContext,
    reference: AuthorizationContext | None,
    url: str,
    matrix: AuthorizationMatrix,
) -> AuthorizationTestKind:
    """Which comparison this is, from the identities involved.

    Ordered from most specific to least. An anonymous request is classified as
    anonymous whatever else is true of the resource: "no credential at all was
    needed" is the more useful thing to tell someone.
    """
    if context.anonymous:
        return AuthorizationTestKind.ANONYMOUS

    owner = matrix.owner_of(url)
    if owner is not None and owner != context.id:
        return AuthorizationTestKind.OBJECT_LEVEL

    if reference is not None and context.privilege_rank < reference.privilege_rank:
        return AuthorizationTestKind.VERTICAL

    return AuthorizationTestKind.HORIZONTAL


def _privileged_over_owner(
    context: AuthorizationContext,
    contexts: Sequence[AuthorizationContext],
    url: str,
    matrix: AuthorizationMatrix,
) -> bool:
    """Whether an ownership-derived denial should be withheld for this context.

    True only when the expectation came from ownership rather than from a rule
    the user wrote, and the requesting identity outranks the owner. An explicit
    rule always wins, so this can never override a stated policy.
    """
    if matrix.explicit_expectation_for(context.id, url) is not None:
        return False

    owner_id = matrix.owner_of(url)
    if owner_id is None or owner_id == context.id:
        return False

    owner = next((c for c in contexts if c.id == owner_id), None)
    if owner is None:
        return False

    return context.privilege_rank > owner.privilege_rank
