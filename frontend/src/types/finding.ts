export const FINDING_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export const FINDING_CONFIDENCES = ["HIGH", "MEDIUM", "LOW"] as const;
export const FINDING_CATEGORIES = [
  "SECURITY_HEADER",
  "COOKIE",
  "XSS",
  "SQLI",
  "TLS",
  "AUTHORIZATION",
  "API_SECURITY",
  "SESSION_SECURITY",
  "CONFIGURATION",
  "INPUT_VALIDATION",
  "INFORMATION_DISCLOSURE",
  "OTHER",
] as const;

/** Ordered most severe first, matching the backend's enum declaration order. */
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];
export type FindingConfidence = (typeof FINDING_CONFIDENCES)[number];
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

/** Minimal endpoint context carried on a finding. */
export interface FindingEndpointRef {
  id: string;
  url: string;
  method: string;
  path: string;
}

/** One endpoint a finding was observed on. */
export interface FindingOccurrence {
  id: string;
  endpoint_id: string | null;
  endpoint_url: string | null;
  evidence: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  /** Stable rule identity, e.g. "SECURITY_HEADER_CSP_MISSING". The dedup key. */
  rule_id: string;
  /** What the finding is about within its rule, such as a cookie name. */
  subject: string | null;
  title: string;
  category: FindingCategory;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  description: string;
  /** What was observed. Never contains secrets or cookie values. */
  evidence: string;
  impact: string;
  remediation: string;
  created_at: string;
  updated_at: string;

  /** The first endpoint this was observed on, when one is known. */
  endpoint: FindingEndpointRef | null;
  /** How many endpoints the rule failed on. */
  occurrence_count: number;
  /** Every affected endpoint. */
  occurrences: FindingOccurrence[];
}

export interface FindingSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface FindingListResponse {
  items: Finding[];
  summary: FindingSummary;
}

/** Human-readable label for a category enum value. */
export const CATEGORY_LABELS: Record<FindingCategory, string> = {
  SECURITY_HEADER: "Security header",
  COOKIE: "Cookie",
  XSS: "Cross-site scripting",
  SQLI: "SQL injection",
  TLS: "TLS",
  AUTHORIZATION: "Access control",
  API_SECURITY: "API security",
  SESSION_SECURITY: "Session security",
  CONFIGURATION: "Configuration",
  INPUT_VALIDATION: "Path traversal / LFI",
  INFORMATION_DISCLOSURE: "Information disclosure",
  OTHER: "Other",
};

/**
 * A finding's subject is a stable `kind:value` string, e.g. `parameter:q`.
 * Returns the parameter name when the subject names one, else null.
 */
export function parameterFromSubject(subject: string | null): string | null {
  if (!subject) return null;
  const [kind, ...rest] = subject.split(":");
  return kind === "parameter" && rest.length > 0 ? rest.join(":") : null;
}

/** Categories that represent an actively tested vulnerability class. */
export const ACTIVE_CATEGORIES: ReadonlySet<FindingCategory> = new Set<FindingCategory>([
  "XSS",
  "SQLI",
  "AUTHORIZATION",
  "API_SECURITY",
  "INPUT_VALIDATION",
]);
