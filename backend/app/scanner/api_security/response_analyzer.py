"""Judging sensitive fields in a response, and field sets across contexts.

Pure. Field names in, observations out.

Two rules do most of the work here, and both exist to stop the scanner asserting
things it cannot know.

**Some fields are never legitimate.** A password hash, a salt, a private key or
a database connection string in a JSON body is a defect whoever asked for it —
there is no product in which a client is supposed to receive one. Those produce
a finding without needing any policy, because no policy could make them correct.

**Everything else depends on the application.** A phone number, an address, even
an access token can be perfectly proper: an API that returns your own token
after you sign in is working as designed. For those the scanner needs the
declared authorization policy to say the context should not have had the
resource, and where no policy was declared the answer is `UNKNOWN_POLICY` —
recorded, counted, and not a finding.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.scanner.api_security.sensitive_fields import classify_fields
from app.scanner.api_security.types import (
    ExposureVerdict,
    FieldCategory,
    FieldClassification,
    FieldSensitivity,
    PropertyComparison,
    SensitiveFieldObservation,
)

#: Categories whose presence in *any* API response is a defect. A client is
#: never meant to hold another party's password hash or private key, and a
#: connection string is a credential with a hostname attached. No authorization
#: policy could make these correct, so none is required to report them.
NEVER_LEGITIMATE: frozenset[FieldCategory] = frozenset(
    {
        FieldCategory.AUTHENTICATION,
        FieldCategory.CRYPTOGRAPHIC,
    }
)

#: Categories that are secrets, but can legitimately be returned to the party
#: they belong to — your own session, your own access token, your own card on
#: file. Anonymous exposure is still a defect; authenticated exposure needs a
#: policy to judge.
OWNER_LEGITIMATE: frozenset[FieldCategory] = frozenset(
    {FieldCategory.TOKEN, FieldCategory.SESSION, FieldCategory.FINANCIAL}
)


def _verdict_for(
    classification: FieldClassification,
    *,
    anonymous: bool,
    resource_denied: bool,
    policy_declared: bool,
) -> tuple[ExposureVerdict, str]:
    """Decide what one sensitive field in one context amounts to."""
    category = classification.category
    highly = classification.sensitivity is FieldSensitivity.HIGHLY_SENSITIVE

    if highly and category in NEVER_LEGITIMATE:
        return (
            ExposureVerdict.UNAUTHORIZED,
            "no client is meant to receive this kind of field, in any context",
        )

    if highly and category is FieldCategory.INFRASTRUCTURE:
        return (
            ExposureVerdict.UNAUTHORIZED,
            "this field carries infrastructure credentials by construction",
        )

    if resource_denied:
        return (
            ExposureVerdict.UNAUTHORIZED,
            "the declared policy says this context should not receive this resource",
        )

    if highly and anonymous and category in OWNER_LEGITIMATE:
        return (
            ExposureVerdict.UNAUTHORIZED,
            "a request carrying no credential received secret material",
        )

    if policy_declared:
        return (
            ExposureVerdict.EXPECTED,
            "the declared policy allows this context to receive this resource",
        )

    return (
        ExposureVerdict.UNKNOWN_POLICY,
        "no policy was declared for this context and resource, so whether the "
        "field belongs here cannot be established",
    )


def analyze_fields(
    *,
    url: str,
    method: str,
    context_id: str,
    context_label: str,
    field_names: Sequence[str],
    anonymous: bool,
    status_code: int | None = None,
    resource_denied: bool = False,
    policy_declared: bool = False,
    limit: int = 50,
) -> tuple[SensitiveFieldObservation, ...]:
    """Classify a response's field names and judge each sensitive one.

    `resource_denied` and `policy_declared` come from the Phase 12 matrix. The
    two are distinct: denied means a policy exists and says no; declared without
    denial means a policy exists and says yes. Neither being true means nobody
    said anything, which is the common case.
    """
    observations: list[SensitiveFieldObservation] = []

    for classification in classify_fields(field_names)[:limit]:
        verdict, detail = _verdict_for(
            classification,
            anonymous=anonymous,
            resource_denied=resource_denied,
            policy_declared=policy_declared,
        )
        observations.append(
            SensitiveFieldObservation(
                url=url,
                method=method,
                context_id=context_id,
                context_label=context_label,
                field=classification,
                verdict=verdict,
                anonymous=anonymous,
                status_code=status_code,
                detail=detail,
            )
        )

    return tuple(observations)


def compare_properties(
    *,
    url: str,
    reference_context_id: str,
    subject_context_id: str,
    subject_context_label: str,
    reference_fields: Sequence[str],
    subject_fields: Sequence[str],
    resource_denied: bool = False,
    policy_declared: bool = False,
) -> PropertyComparison | None:
    """Compare what two contexts were handed for the same resource.

    Phase 12 established who could *reach* a resource. This asks what each of
    them was given once inside, which is the property-level question — OWASP's
    broken object property level authorization.

    A difference on its own is not a defect: an administrator seeing more fields
    than a customer is the system working. It becomes one when the extra fields
    are of a kind no client should hold, or when the declared policy says this
    context should not have had the resource at all.
    """
    extra_names = [name for name in subject_fields if name not in set(reference_fields)]
    if not extra_names:
        return None

    extra = classify_fields(extra_names)
    if not extra:
        # More fields, none of them sensitive. Ordinary, and not worth a word.
        return None

    never_legitimate = [
        classification
        for classification in extra
        if classification.sensitivity is FieldSensitivity.HIGHLY_SENSITIVE
        and classification.category in (NEVER_LEGITIMATE | {FieldCategory.INFRASTRUCTURE})
    ]

    if never_legitimate:
        verdict = ExposureVerdict.UNAUTHORIZED
        detail = (
            "this context received secret fields that the reference identity did "
            "not, and that no client is meant to receive"
        )
    elif resource_denied:
        verdict = ExposureVerdict.UNAUTHORIZED
        detail = (
            "the declared policy says this context should not receive this "
            "resource, and it received additional sensitive fields"
        )
    elif policy_declared:
        verdict = ExposureVerdict.EXPECTED
        detail = "the declared policy allows this context to receive this resource"
    else:
        verdict = ExposureVerdict.UNKNOWN_POLICY
        detail = (
            "the field sets differ, but no policy says whether this context "
            "should receive the additional fields"
        )

    return PropertyComparison(
        url=url,
        reference_context_id=reference_context_id,
        subject_context_id=subject_context_id,
        subject_context_label=subject_context_label,
        extra_fields=extra,
        verdict=verdict,
        detail=detail,
    )
