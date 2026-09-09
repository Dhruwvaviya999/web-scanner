"""Authorized authorization and access-control testing.

Comparative by nature: the scanner asks whether identities the authorized user
supplied are treated differently by the same resource. It never creates an
account, never registers a user, never guesses a credential or a role, and never
attacks authentication — every identity here was handed to it.

Only the leaf modules are re-exported. `module` needs the HTTP transport, which
imports this package's types, so importing it here would make every
`authorization.types` import circular:

    from app.scanner.authorization.module import AuthorizationModule
"""

from app.scanner.authorization.budget import AuthorizationBudget
from app.scanner.authorization.detector import analyze_resource
from app.scanner.authorization.findings import build_finding, confidence_for
from app.scanner.authorization.matrix import (
    AccessRule,
    AuthorizationMatrix,
    AuthorizationPlan,
    MatrixError,
    ResourceOwnership,
    build_matrix,
    matches,
    normalize_pattern,
    path_of,
)
from app.scanner.authorization.types import (
    AccessExpectation,
    AuthorizationBudgetLimits,
    AuthorizationConfig,
    AuthorizationContext,
    AuthorizationObservation,
    AuthorizationOutcome,
    AuthorizationStats,
    AuthorizationTestKind,
    ComparisonVerdict,
    ObservedAccess,
    ResponseFingerprint,
)

__all__ = [
    "AccessExpectation",
    "AccessRule",
    "AuthorizationBudget",
    "AuthorizationBudgetLimits",
    "AuthorizationConfig",
    "AuthorizationContext",
    "AuthorizationMatrix",
    "AuthorizationObservation",
    "AuthorizationOutcome",
    "AuthorizationPlan",
    "AuthorizationStats",
    "AuthorizationTestKind",
    "ComparisonVerdict",
    "MatrixError",
    "ObservedAccess",
    "ResourceOwnership",
    "ResponseFingerprint",
    "analyze_resource",
    "build_finding",
    "build_matrix",
    "confidence_for",
    "matches",
    "normalize_pattern",
    "path_of",
]
