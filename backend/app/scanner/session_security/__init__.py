"""Passive session-security and conservative CSRF analysis.

Reads session handling out of what earlier phases already fetched: which
cookies carry session state, where session-like identifiers travelled, what
JSON Web Tokens declare about themselves, and how much can honestly be said
about a form's CSRF posture. It sends no request, submits no form, forges no
token and calls no logout endpoint.

Only the leaf modules are re-exported. `module` imports the shared aggregator
and `app.scanner.types`, both of which reach back into this package, so
importing it here would make every `session_security.types` import circular:

    from app.scanner.session_security.module import SessionSecurityModule
"""

from app.scanner.session_security.cookie_analyzer import (
    collect_cookies,
    infer_timeout,
    session_cookies,
    transport_exposed,
)
from app.scanner.session_security.csrf_analyzer import (
    analyze_form,
    analyze_forms,
    find_logout_endpoints,
    is_token_field,
    token_fields,
)
from app.scanner.session_security.exposure_analyzer import (
    analyze_json_fields,
    analyze_location_header,
    analyze_url,
    classify_parameter,
)
from app.scanner.session_security.session_classifier import (
    classify_cookie,
    classify_name,
    weakest_same_site,
)
from app.scanner.session_security.token_analyzer import (
    describe,
    find_tokens,
    safe_find_tokens,
    sensitive_claims,
    weaknesses,
)
from app.scanner.session_security.types import (
    CookieRole,
    CsrfObservation,
    CsrfVerdict,
    ExposureLocation,
    JwtMetadata,
    JwtObservation,
    LogoutObservation,
    ParameterClass,
    SessionConfidence,
    SessionCookie,
    SessionSecurityConfig,
    SessionSecurityLimits,
    SessionSecurityOutcome,
    SessionSecurityResult,
    SessionSecurityStats,
    SessionSignals,
    TimeoutEvidence,
    TimeoutObservation,
    UrlExposure,
)

__all__ = [
    "CookieRole",
    "CsrfObservation",
    "CsrfVerdict",
    "ExposureLocation",
    "JwtMetadata",
    "JwtObservation",
    "LogoutObservation",
    "ParameterClass",
    "SessionConfidence",
    "SessionCookie",
    "SessionSecurityConfig",
    "SessionSecurityLimits",
    "SessionSecurityOutcome",
    "SessionSecurityResult",
    "SessionSecurityStats",
    "SessionSignals",
    "TimeoutEvidence",
    "TimeoutObservation",
    "UrlExposure",
    "analyze_form",
    "analyze_forms",
    "analyze_json_fields",
    "analyze_location_header",
    "analyze_url",
    "classify_cookie",
    "classify_name",
    "classify_parameter",
    "collect_cookies",
    "describe",
    "find_logout_endpoints",
    "find_tokens",
    "infer_timeout",
    "is_token_field",
    "safe_find_tokens",
    "sensitive_claims",
    "session_cookies",
    "token_fields",
    "transport_exposed",
    "weakest_same_site",
    "weaknesses",
]
