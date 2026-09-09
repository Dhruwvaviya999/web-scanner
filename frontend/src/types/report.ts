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
