"""Read-only API security analysis.

Reads weaknesses out of responses earlier phases already fetched: exposed field
names, verbose error diagnostics, unsafe cross-origin policies, disclosing
headers and inventory drift. It sends no payload, invokes no operation, and
provokes no error.

Only the leaf modules are re-exported. `module` needs the aggregator and the
authorization plan, both of which import this package's types, so importing it
here would make every `api_security.types` import circular:

    from app.scanner.api_security.module import ApiSecurityModule
"""

from app.scanner.api_security.configuration import (
    analyze_cors,
    analyze_disclosure,
    analyze_inventory,
    version_of,
)
from app.scanner.api_security.error_analyzer import (
    analyze as analyze_error,
)
from app.scanner.api_security.error_analyzer import (
    detect_error_signals,
    safe_detect,
)
from app.scanner.api_security.response_analyzer import analyze_fields, compare_properties
from app.scanner.api_security.sensitive_fields import (
    classify_field,
    classify_fields,
    normalize,
)
from app.scanner.api_security.types import (
    ApiSecurityConfig,
    ApiSecurityLimits,
    ApiSecurityOutcome,
    ApiSecurityResult,
    ApiSecurityStats,
    CorsObservation,
    CorsVerdict,
    DisclosureObservation,
    ErrorObservation,
    ErrorSignal,
    ExposureVerdict,
    FieldCategory,
    FieldClassification,
    FieldSensitivity,
    InventoryObservation,
    PropertyComparison,
    SensitiveFieldObservation,
)

__all__ = [
    "ApiSecurityConfig",
    "ApiSecurityLimits",
    "ApiSecurityOutcome",
    "ApiSecurityResult",
    "ApiSecurityStats",
    "CorsObservation",
    "CorsVerdict",
    "DisclosureObservation",
    "ErrorObservation",
    "ErrorSignal",
    "ExposureVerdict",
    "FieldCategory",
    "FieldClassification",
    "FieldSensitivity",
    "InventoryObservation",
    "PropertyComparison",
    "SensitiveFieldObservation",
    "analyze_cors",
    "analyze_disclosure",
    "analyze_error",
    "analyze_fields",
    "analyze_inventory",
    "classify_field",
    "classify_fields",
    "compare_properties",
    "detect_error_signals",
    "normalize",
    "safe_detect",
    "version_of",
]
