"""Configuration, deployment and transport security analysis.

Examines how a target is *deployed* rather than how it is coded: transport and
HSTS, which HTTP methods are advertised, whether debug mode is on, whether
deployment files or repository metadata are reachable, directory listings,
source maps, CSP quality, header defects and path-handling inconsistencies.

Every request it makes is a GET, HEAD or OPTIONS through the existing
`HttpFetcher`, against a fixed and small list of candidate paths. There is no
directory brute-forcing, no filename enumeration, no recursion and no arbitrary
download anywhere in the package.

Only the leaf modules are re-exported. `module` imports the shared aggregator,
the authorization plan and `app.scanner.types`, all of which reach back into
this package, so importing it here would make every `config_security.types`
import circular:

    from app.scanner.config_security.module import ConfigSecurityModule
"""

from app.scanner.config_security.deployment import (
    count_map_sources,
    detect_debug,
    detect_directory_listing,
    detect_technology,
    find_source_map_reference,
    is_default_content,
    javascript_assets,
    merge_technologies,
    safe_signals_for,
    signals_for,
    source_map_observation,
)
from app.scanner.config_security.discovery import (
    ADMIN_CANDIDATES,
    BACKUP_SUFFIXES,
    DEBUG_CANDIDATES,
    HEALTH_CANDIDATES,
    MANAGEMENT_CANDIDATES,
    REPOSITORY_CANDIDATES,
    SAMPLE_CANDIDATES,
    SENSITIVE_FILE_CANDIDATES,
    backup_variants,
    body_matches_candidate,
    candidates_for,
    classify,
    discovered_file_paths,
    not_tested,
    visibility,
)
from app.scanner.config_security.headers import (
    analyze_csp,
    analyze_header_defects,
    effective_script_sources,
    merge_defects,
    parse_directives,
)
from app.scanner.config_security.methods import (
    analyze_options,
    looks_like_api,
    parse_methods,
    reportable,
    surprising_methods,
)
from app.scanner.config_security.path_confusion import (
    analyze as analyze_paths,
)
from app.scanner.config_security.path_confusion import (
    duplicate_representations,
)
from app.scanner.config_security.transport import (
    analyze as analyze_transport,
)
from app.scanner.config_security.transport import (
    classify_redirect,
    classify_tls,
    grade_hsts,
    hsts_findings_suppressed,
    is_local_target,
    parse_hsts,
)
from app.scanner.config_security.types import (
    AccessVisibility,
    CandidateKind,
    CandidateObservation,
    CandidateOutcome,
    ConfigSecurityConfig,
    ConfigSecurityLimits,
    ConfigSecurityOutcome,
    ConfigSecurityResult,
    ConfigSecurityStats,
    ConfigSignals,
    CspGrade,
    CspObservation,
    DebugObservation,
    DebugSignal,
    HeaderDefect,
    HeaderDefectObservation,
    HstsQuality,
    ListingObservation,
    MethodObservation,
    NormalizationObservation,
    NormalizationSignal,
    RedirectBehaviour,
    SAFE_METHODS,
    SourceMapObservation,
    TechnologyObservation,
    TlsObservation,
    TransportObservation,
    TransportScheme,
)

__all__ = [
    "ADMIN_CANDIDATES",
    "BACKUP_SUFFIXES",
    "DEBUG_CANDIDATES",
    "HEALTH_CANDIDATES",
    "MANAGEMENT_CANDIDATES",
    "REPOSITORY_CANDIDATES",
    "SAFE_METHODS",
    "SAMPLE_CANDIDATES",
    "SENSITIVE_FILE_CANDIDATES",
    "AccessVisibility",
    "CandidateKind",
    "CandidateObservation",
    "CandidateOutcome",
    "ConfigSecurityConfig",
    "ConfigSecurityLimits",
    "ConfigSecurityOutcome",
    "ConfigSecurityResult",
    "ConfigSecurityStats",
    "ConfigSignals",
    "CspGrade",
    "CspObservation",
    "DebugObservation",
    "DebugSignal",
    "HeaderDefect",
    "HeaderDefectObservation",
    "HstsQuality",
    "ListingObservation",
    "MethodObservation",
    "NormalizationObservation",
    "NormalizationSignal",
    "RedirectBehaviour",
    "SourceMapObservation",
    "TechnologyObservation",
    "TlsObservation",
    "TransportObservation",
    "TransportScheme",
    "analyze_csp",
    "analyze_header_defects",
    "analyze_options",
    "analyze_paths",
    "analyze_transport",
    "backup_variants",
    "body_matches_candidate",
    "candidates_for",
    "classify",
    "classify_redirect",
    "classify_tls",
    "count_map_sources",
    "detect_debug",
    "detect_directory_listing",
    "detect_technology",
    "discovered_file_paths",
    "duplicate_representations",
    "effective_script_sources",
    "find_source_map_reference",
    "grade_hsts",
    "hsts_findings_suppressed",
    "is_default_content",
    "is_local_target",
    "javascript_assets",
    "looks_like_api",
    "merge_defects",
    "merge_technologies",
    "not_tested",
    "parse_directives",
    "parse_hsts",
    "parse_methods",
    "reportable",
    "safe_signals_for",
    "signals_for",
    "source_map_observation",
    "surprising_methods",
    "visibility",
]
