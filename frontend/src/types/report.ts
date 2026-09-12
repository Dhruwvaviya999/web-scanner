import type { FindingCategory, FindingConfidence, FindingSeverity } from "@/types/finding";
import type { AuthMode, AuthStatus } from "@/types/scan";

/** How the scan authenticated. Cannot describe a secret, because none is sent. */
export interface ReportAuthentication {
  mode: AuthMode;
  status: AuthStatus;
  /** Whether any credential was configured — not whether it worked. */
  authenticated: boolean;
  /**
   * Whether one initial access check accepted the credential. Not a claim that
   * it was valid for every path, or for the whole scan.
   */
  confirmed: boolean;
}

/**
 * What the authorization stage compared.
 *
 * `unknown` is the number to read first: comparisons where no policy was
 * declared. A high count does not mean the application is fine — it means the
 * scan was never told what "fine" would look like.
 */
export interface ReportAuthorization {
  enabled: boolean;
  contexts: number;
  context_labels: string[];
  endpoints_eligible: number;
  endpoints_tested: number;
  comparisons: number;
  unknown: number;
  skipped: number;
  failed: number;
  /** True only when at least one comparison was measured against a declared rule. */
  has_policy: boolean;
}

/** One API parameter in a report. A name and a place, never a value. */
export interface ReportApiParameter {
  name: string;
  location: string;
  required: boolean | null;
}

export interface ReportApiEndpoint {
  path: string;
  method: string;
  confidence: string;
  sources: string[];
  auth_status: string;
  /** The scanner requested this and something answered. */
  observed: boolean;
  /** A specification says it exists. A claim, not a fact. */
  documented: boolean;
  documented_only: boolean;
  status_code: number | null;
  request_media_type: string | null;
  response_media_type: string | null;
  operation_id: string | null;
  security: string[];
  parameters: ReportApiParameter[];
  /** Field names from a JSON response. Never a value from one. */
  json_field_names: string[];
  json_top_level: string | null;
}

export interface ReportApiDocument {
  url: string;
  version: string;
  title: string | null;
  path_count: number;
  operation_count: number;
  security_schemes: string[];
  truncated: boolean;
}

/**
 * What API discovery found.
 *
 * `endpoints_observed` and `endpoints_documented_only` are kept apart because
 * adding them together would describe operations nobody has ever reached as
 * though they were known to work.
 */
export interface ReportApiSurface {
  detected: boolean;
  endpoints_discovered: number;
  endpoints_observed: number;
  endpoints_documented_only: number;
  parameters_discovered: number;
  authenticated_endpoints: number;
  unknown_auth_endpoints: number;
  openapi_documents: number;
  graphql_detected: boolean;
  graphql_path: string | null;
  /** Always false: this phase detects GraphQL and never queries it. */
  graphql_introspection_tested: boolean;
  truncated: boolean;
  complete_inventory: boolean;
  endpoints: ReportApiEndpoint[];
  documents: ReportApiDocument[];
}

/**
 * What the read-only API security review found.
 *
 * `unknown_policy` is the number to read first. A sensitive-looking field with
 * no declared policy behind it is an observation, not a finding — and not a
 * clean result either. A high count means the scan needs an authorization
 * policy, not that the API is fine.
 */
export interface ReportApiSecurity {
  analyzed: boolean;
  endpoints_analyzed: number;
  endpoints_skipped: number;
  responses_analyzed: number;
  sensitive_fields_detected: number;
  property_comparisons: number;
  verbose_errors: number;
  cors_checks: number;
  inventory_observations: number;
  contexts_analyzed: number;
  unknown_policy: number;
  findings_count: number;
  /** True when something was measured against a declared policy, not just seen. */
  judged: boolean;
}

/**
 * Session handling coverage. Every field is a boolean or a count — there is no
 * field for a cookie value, a session identifier, a token or a JWT segment,
 * because none of those ever reach the API.
 *
 * Read `csrf_potential` alongside `csrf_strong`. A potential is a form where
 * several signals line up and a server-side defence could still exist: origin
 * validation, a required header, framework middleware, none of them visible
 * without forging a request, which the scanner never does. Only `csrf_strong`
 * produced findings, and even those are unconfirmed.
 */
export interface ReportSessionSecurity {
  analyzed: boolean;
  session_cookies_identified: number;
  session_identifiers_in_urls: number;
  token_exposures: number;
  csrf_forms_analyzed: number;
  /** Worth reviewing. Deliberately never a finding on its own. */
  csrf_potential: number;
  /** The only verdict that produced a finding, and still unconfirmed. */
  csrf_strong: number;
  jwt_tokens_observed: number;
  /**
   * Whether anything established a session lifetime. False is not a weakness:
   * server-side expiry cannot be observed from outside.
   */
  timeout_known: boolean;
  /** Found and recorded. None of them was ever called. */
  logout_endpoints_discovered: number;
  findings_count: number;
  /** Requests this stage made. Zero by design. */
  requests_sent: number;
  /** False whenever any form landed on POTENTIAL — not an all-clear. */
  csrf_conclusive: boolean;
}

/**
 * Configuration and deployment coverage. Every field is a boolean or a count —
 * there is no field for a response body, a file's contents, an environment
 * variable, a secret, a repository object or a source line, because none of
 * those ever reach the API.
 *
 * Read `candidates_not_tested` and `budget_exhausted` before anything else.
 * This is the only late stage that sends requests, so its coverage can be cut
 * short; a candidate the budget never reached established nothing, and
 * `coverage_complete` is what says whether silence can be trusted.
 */
export interface ReportConfigSecurity {
  analyzed: boolean;
  https_used: boolean;
  https_redirect: boolean;
  hsts_observed: boolean;
  method_observations: number;
  debug_indicators: number;
  sensitive_files_checked: number;
  sensitive_files_exposed: number;
  /** Administrative paths that answered. Not by itself a weakness. */
  admin_endpoints_discovered: number;
  management_endpoints_discovered: number;
  directory_listings: number;
  source_maps: number;
  /** Headers naming the stack. Informational; this is how servers behave. */
  technology_disclosures: number;
  path_normalization_observations: number;
  /** Never reached by the budget. Not the same as "came back clean". */
  candidates_not_tested: number;
  requests_sent: number;
  findings_count: number;
  budget_exhausted: boolean;
  /** False when a budget cut the checks short — silence is then not evidence. */
  coverage_complete: boolean;
}

export interface ReportMetadata {
  scan_id: string;
  target_url: string;
  final_url: string | null;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  /** When the report was rendered, not when the scan ran. */
  generated_at: string;
  error_message: string | null;
  cancelled_at: string | null;
  /** Stage a failed scan was in. A stage name only, never a trace. */
  failure_stage: string | null;
  authentication: ReportAuthentication;
  /**
   * True only when the scan ran to completion. A failed or cancelled scan
   * covers only what it reached before stopping, so an empty findings list on
   * an inconclusive report is not an all-clear.
   */
  is_conclusive: boolean;
}

export interface CoverageSummary {
  endpoints_discovered: number | null;
  endpoints_analyzed: number | null;
  endpoints_skipped: number | null;
  endpoints_failed: number | null;
  forms_discovered: number | null;
  parameters_discovered: number | null;
  pages_crawled: number | null;
  pages_skipped: number | null;
  max_depth_reached: number | null;
  crawl_limit_reached: boolean | null;
  /** Whether the run itself finished, rather than failing or being cancelled. */
  scan_completed: boolean;
  /**
   * False when credentials were supplied and the target refused them, so only
   * the anonymous surface was ever covered.
   */
  authentication_usable: boolean;
  /** Authorization testing, which is separate from authentication coverage. */
  authorization: ReportAuthorization;
  /** API reconnaissance: a classification of the surface, not a test of it. */
  api: ReportApiSurface;
  /** The read-only API security review of those same responses. */
  api_security: ReportApiSecurity;
  /** Session handling and CSRF posture. Passive: the stage sends nothing. */
  session_security: ReportSessionSecurity;
  /** Deployment and transport configuration. Bounded, and never a brute-force. */
  config_security: ReportConfigSecurity;
  /**
   * True only when every discovered endpoint was analysed or deliberately
   * skipped, with no failures. A clean result with this false means the scan
   * did not cover everything it found — never present that as "secure".
   */
  is_complete: boolean;
}

export interface SeveritySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ReportEndpoint {
  /** Canonical URL: parameter names only, never values. */
  url: string;
  path: string | null;
  method: string | null;
}

export interface ReportFinding {
  rule_id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  title: string;
  description: string;
  impact: string;
  remediation: string;
  /** Normalised observation. Never contains secrets or probe values. */
  evidence: string;
  subject: string | null;
  occurrence_count: number;
  endpoints: ReportEndpoint[];
}

export interface CategoryGroup {
  category: FindingCategory;
  total: number;
  severity: SeveritySummary;
}

export interface ReportAttackSurface {
  endpoints: number;
  forms: number;
  parameters: number;
}

export interface ScanReport {
  metadata: ReportMetadata;
  coverage: CoverageSummary;
  severity: SeveritySummary;
  attack_surface: ReportAttackSurface;
  findings: ReportFinding[];
  categories: CategoryGroup[];
  /** Discovered parameter names. Names only, never values. */
  parameter_names: string[];
}

/** Filters applied to the findings list. `null` means "any". */
export interface FindingFilters {
  severity: FindingSeverity | null;
  category: FindingCategory | null;
  confidence: FindingConfidence | null;
}

export const EMPTY_FILTERS: FindingFilters = {
  severity: null,
  category: null,
  confidence: null,
};

export function applyFilters(
  findings: ReportFinding[],
  filters: FindingFilters,
): ReportFinding[] {
  return findings.filter(
    (finding) =>
      (filters.severity === null || finding.severity === filters.severity) &&
      (filters.category === null || finding.category === filters.category) &&
      (filters.confidence === null || finding.confidence === filters.confidence),
  );
}
