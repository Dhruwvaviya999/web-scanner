"""Authorization findings.

Every builder here takes an `AuthorizationObservation` and nothing else, which
is what keeps a response body out of a finding by construction: the observation
already reduced the response to a status, a length and a digest.

Wording is chosen carefully. A finding says what was *demonstrated within the
supplied contexts* — one identity received a resource another identity's policy
reserved — and stops there. It does not claim the application is exploitable in
production, that other users are affected, or that the scanner enumerated
anything. All four rules are HIGH severity because an access-control bypass is
serious when real; confidence is what carries the uncertainty, and it is set
from the quality of the comparison rather than from the rule.
"""

from __future__ import annotations

from app.scanner.authorization.types import (
    AuthorizationObservation,
    AuthorizationTestKind,
)
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)

_RULE_FOR_KIND = {
    AuthorizationTestKind.ANONYMOUS: FindingRule.AUTHZ_ANONYMOUS_ACCESS,
    AuthorizationTestKind.HORIZONTAL: FindingRule.AUTHZ_HORIZONTAL_ACCESS,
    AuthorizationTestKind.VERTICAL: FindingRule.AUTHZ_VERTICAL_ACCESS,
    AuthorizationTestKind.OBJECT_LEVEL: FindingRule.AUTHZ_OBJECT_LEVEL_ACCESS,
}

_TITLE_FOR_KIND = {
    AuthorizationTestKind.ANONYMOUS: "Protected resource served to an unauthenticated request",
    AuthorizationTestKind.HORIZONTAL: "Resource reachable by another user at the same privilege level",
    AuthorizationTestKind.VERTICAL: "Privileged resource reachable by a lower-privilege identity",
    AuthorizationTestKind.OBJECT_LEVEL: "Object served to an identity that does not own it",
}

_IMPACT_FOR_KIND = {
    AuthorizationTestKind.ANONYMOUS: (
        "Anyone who can reach this URL can read it, with no session and no "
        "credential. Content the application treats as protected is effectively "
        "published."
    ),
    AuthorizationTestKind.HORIZONTAL: (
        "One user can read another user's resource. Where the resource contains "
        "personal or account data, this is a disclosure between customers, and "
        "it usually generalises to every record of the same kind."
    ),
    AuthorizationTestKind.VERTICAL: (
        "A lower-privilege identity reached a resource the policy reserves for a "
        "higher one. Administrative content or functionality is exposed to users "
        "who should not see it."
    ),
    AuthorizationTestKind.OBJECT_LEVEL: (
        "The application serves this object without checking who is asking. An "
        "identifier is the only thing standing between an identity and another "
        "identity's data."
    ),
}

_REMEDIATION = (
    "Enforce the access decision on the server, in the handler that loads the "
    "resource, using the identity of the caller rather than anything supplied "
    "in the request. Check ownership or role membership before the resource is "
    "read, not only before it is displayed, and return the same response for "
    "\"not allowed\" as for \"does not exist\" so the identifier itself leaks "
    "nothing. Route-level or client-side checks are not sufficient."
)


def confidence_for(observation: AuthorizationObservation) -> FindingConfidence:
    """How sure the comparison lets us be.

    HIGH is reserved for the case the scanner can actually stand behind: the
    user declared the boundary, the reference identity was served the resource,
    and the subject received materially the same thing. Anything resting on a
    shorter or partial match is MEDIUM, because a shared page template can look
    like a leaked record.
    """
    if observation.equivalent_to_reference is True:
        return FindingConfidence.HIGH
    return FindingConfidence.MEDIUM


def _description(observation: AuthorizationObservation) -> str:
    reference = observation.reference_context_id or "a reference identity"
    return (
        f"Context {observation.context_label!r} requested {observation.url}, which the "
        f"supplied authorization policy expects to be denied to it. The request "
        f"succeeded and returned materially the same content that "
        f"{reference!r} receives. This was demonstrated by direct comparison between "
        f"the two identities supplied for this scan; it is a statement about those "
        f"identities and this resource, not an estimate of how many records are "
        f"affected."
    )


def _evidence(observation: AuthorizationObservation) -> str:
    """A safe evidence line. Metadata only — never response content."""
    parts = [
        f"expected {observation.expected.value}",
        f"observed {observation.observed.value}",
    ]
    if observation.fingerprint is not None:
        parts.append(observation.fingerprint.summary())
    if observation.equivalent_to_reference is True:
        parts.append("content matches the reference identity's response")
    elif observation.equivalent_to_reference is False:
        parts.append("content differs from the reference identity's response")
    if observation.detail:
        parts.append(observation.detail)
    return "; ".join(parts)


def build_finding(observation: AuthorizationObservation) -> FindingData:
    """Turn a violation into a finding.

    The subject is the requesting context plus the resource, so two identities
    reaching the same resource stay separate findings — merging them would erase
    which boundary failed.
    """
    rule = _RULE_FOR_KIND[observation.kind]
    return FindingData(
        rule=rule,
        title=_TITLE_FOR_KIND[observation.kind],
        category=FindingCategory.AUTHORIZATION,
        severity=FindingSeverity.HIGH,
        confidence=confidence_for(observation),
        description=_description(observation),
        evidence=_evidence(observation),
        impact=_IMPACT_FOR_KIND[observation.kind],
        remediation=_REMEDIATION,
        subject=f"{observation.context_id}:{observation.url}",
    )
