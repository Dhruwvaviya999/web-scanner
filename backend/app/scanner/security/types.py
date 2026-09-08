"""The vocabulary of a security finding.

These enums are the single source of truth for severity, confidence and
category. `app.models.finding` imports them for its columns rather than
redeclaring them, which keeps the scanner free of any dependency on the ORM
while still giving the database one definition to store.

Member order matters: the native PostgreSQL enum is created in this order, so
`ORDER BY severity` sorts most-severe-first without a CASE expression.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class FindingSeverity(str, enum.Enum):
    """How much a finding matters, if confirmed.

    Configuration observations belong at LOW or INFO. Reserve HIGH and above for
    something with demonstrated impact — this scanner does not confirm
    exploitability, so it should rarely reach them.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingConfidence(str, enum.Enum):
    """How certain the detector is that the observation is real.

    HIGH   — directly observed in the response (a header is absent or present).
    MEDIUM — relies on a heuristic, such as inferring a cookie's purpose.
    LOW    — indicative only; needs a human to confirm.
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingCategory(str, enum.Enum):
    """What kind of check produced the finding.

    Phase 3 emits only SECURITY_HEADER and COOKIE. The rest are declared so that
    later detectors do not require a migration to start using them.
    """

    SECURITY_HEADER = "SECURITY_HEADER"
    COOKIE = "COOKIE"
    #: Cross-site scripting. Phase 6 emits only reflected XSS.
    XSS = "XSS"
    TLS = "TLS"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    OTHER = "OTHER"


class FindingRule(str, enum.Enum):
    """Stable programmatic identity for a detector rule.

    This is what deduplication and cross-scan correlation key on, so it must
    never change once shipped. Display titles are free to be reworded.

    Stored as a plain string column rather than a native database enum: a
    security scanner gains rules constantly, and `ALTER TYPE ... ADD VALUE` on
    every one of them is friction for no benefit. Validity is enforced here and
    at the schema boundary instead.
    """

    # --- Security headers ---
    SECURITY_HEADER_HSTS_MISSING = "SECURITY_HEADER_HSTS_MISSING"
    SECURITY_HEADER_HSTS_DISABLED = "SECURITY_HEADER_HSTS_DISABLED"
    SECURITY_HEADER_HSTS_SHORT_MAX_AGE = "SECURITY_HEADER_HSTS_SHORT_MAX_AGE"
    SECURITY_HEADER_CSP_MISSING = "SECURITY_HEADER_CSP_MISSING"
    SECURITY_HEADER_CSP_PERMISSIVE = "SECURITY_HEADER_CSP_PERMISSIVE"
    SECURITY_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING = (
        "SECURITY_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING"
    )
    SECURITY_HEADER_X_FRAME_OPTIONS_MISSING = "SECURITY_HEADER_X_FRAME_OPTIONS_MISSING"
    SECURITY_HEADER_REFERRER_POLICY_MISSING = "SECURITY_HEADER_REFERRER_POLICY_MISSING"
    SECURITY_HEADER_PERMISSIONS_POLICY_MISSING = "SECURITY_HEADER_PERMISSIONS_POLICY_MISSING"

    # --- Injection ---
    #: Reflected cross-site scripting. Active detection, inert marker only.
    XSS_REFLECTED = "XSS_REFLECTED"

    # --- Cookies ---
    COOKIE_SECURE_MISSING = "COOKIE_SECURE_MISSING"
    COOKIE_HTTPONLY_MISSING = "COOKIE_HTTPONLY_MISSING"
    COOKIE_SAMESITE_MISSING = "COOKIE_SAMESITE_MISSING"
    COOKIE_SAMESITE_NONE_WITHOUT_SECURE = "COOKIE_SAMESITE_NONE_WITHOUT_SECURE"


#: Phase 3 stored short lowercase codes. Kept so the 0005 migration can rewrite
#: existing rows, and so old exports remain interpretable.
LEGACY_CODE_TO_RULE: dict[str, FindingRule] = {
    "missing_hsts": FindingRule.SECURITY_HEADER_HSTS_MISSING,
    "hsts_disabled": FindingRule.SECURITY_HEADER_HSTS_DISABLED,
    "hsts_short_max_age": FindingRule.SECURITY_HEADER_HSTS_SHORT_MAX_AGE,
    "missing_csp": FindingRule.SECURITY_HEADER_CSP_MISSING,
    "permissive_csp": FindingRule.SECURITY_HEADER_CSP_PERMISSIVE,
    "missing_content_type_options": FindingRule.SECURITY_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING,
    "missing_frame_options": FindingRule.SECURITY_HEADER_X_FRAME_OPTIONS_MISSING,
    "missing_referrer_policy": FindingRule.SECURITY_HEADER_REFERRER_POLICY_MISSING,
    "missing_permissions_policy": FindingRule.SECURITY_HEADER_PERMISSIONS_POLICY_MISSING,
    "cookie_missing_secure": FindingRule.COOKIE_SECURE_MISSING,
    "session_cookie_missing_httponly": FindingRule.COOKIE_HTTPONLY_MISSING,
    "cookie_missing_samesite": FindingRule.COOKIE_SAMESITE_MISSING,
    "cookie_samesite_none_without_secure": FindingRule.COOKIE_SAMESITE_NONE_WITHOUT_SECURE,
}


@dataclass(frozen=True, slots=True)
class FindingData:
    """A finding as produced by a detector, before it reaches the database.

    Detectors return these; the service layer turns them into `Finding` rows.
    Nothing here knows about SQLAlchemy, so every rule stays a pure function of
    the HTTP response.
    """

    #: Which rule fired. The deduplication identity, never a display string.
    rule: FindingRule
    title: str
    category: FindingCategory
    severity: FindingSeverity
    confidence: FindingConfidence
    description: str
    #: What was actually observed. Must never contain a secret — in particular,
    #: never a cookie value.
    evidence: str
    impact: str
    remediation: str
    #: What the finding is *about* within its rule — a cookie name, for example.
    #: Two findings of the same rule but different subjects stay separate, so
    #: "cookie `session` missing Secure" never merges with "cookie `theme`
    #: missing Secure". None for rules that apply to the response as a whole.
    subject: str | None = None

    @property
    def identity(self) -> tuple[str, str | None]:
        """The deduplication key: which rule, about what."""
        return (self.rule.value, self.subject)


#: Sort key for presenting findings most-severe-first.
SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}


def sort_findings(findings: list[FindingData]) -> list[FindingData]:
    """Most severe first, then alphabetically for a stable order."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.title))
