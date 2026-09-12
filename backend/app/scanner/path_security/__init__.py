"""Path-traversal and local-file-inclusion detection.

Tests parameters that name a file or a path for whether attacker-controlled
input can escape the intended directory. It does this safely: it targets a
controlled canary the local fixture places outside the boundary, never a real
system file, and a finding requires that harmless marker to be returned
reproducibly. It performs no file writes, no deletion, no command execution and
no remote file inclusion.

Only the leaf modules are re-exported. `module` and `detector` import the active
framework and the shared aggregator, both of which reach back into this package,
so importing them here would make every `path_security.types` import circular:

    from app.scanner.path_security.module import PathSecurityModule
"""

from app.scanner.path_security.analyzer import (
    BaselineEvidence,
    ProbeEvidence,
    TraversalAssessment,
    analyze,
    baseline_is_usable,
)
from app.scanner.path_security.findings import build_traversal_finding, subject_for
from app.scanner.path_security.parameter_classifier import (
    classify,
    classify_all,
    classify_name,
    normalize,
)
from app.scanner.path_security.payloads import (
    CANARY_MARKER,
    CANARY_SUFFIX,
    TRAVERSAL_PROBES,
    TraversalProbe,
    is_safe_probe,
    traversal_probes,
)
from app.scanner.path_security.types import (
    InclusionMechanism,
    ParameterAssessment,
    ParameterClass,
    PathSecurityConfig,
    PathSecurityLimits,
    PathSecurityOutcome,
    PathSecurityResult,
    PathSecurityStats,
    TargetPlatform,
    TraversalObservation,
    TraversalVerdict,
)

__all__ = [
    "CANARY_MARKER",
    "CANARY_SUFFIX",
    "TRAVERSAL_PROBES",
    "BaselineEvidence",
    "InclusionMechanism",
    "ParameterAssessment",
    "ParameterClass",
    "PathSecurityConfig",
    "PathSecurityLimits",
    "PathSecurityOutcome",
    "PathSecurityResult",
    "PathSecurityStats",
    "ProbeEvidence",
    "TargetPlatform",
    "TraversalAssessment",
    "TraversalObservation",
    "TraversalProbe",
    "TraversalVerdict",
    "analyze",
    "baseline_is_usable",
    "build_traversal_finding",
    "classify",
    "classify_all",
    "classify_name",
    "is_safe_probe",
    "normalize",
    "subject_for",
    "traversal_probes",
]
