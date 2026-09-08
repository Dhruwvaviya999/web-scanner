export const FINDING_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export const FINDING_CONFIDENCES = ["HIGH", "MEDIUM", "LOW"] as const;
export const FINDING_CATEGORIES = [
  "SECURITY_HEADER",
  "COOKIE",
  "TLS",
  "INFORMATION_DISCLOSURE",
  "OTHER",
] as const;

/** Ordered most severe first, matching the backend's enum declaration order. */
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];
export type FindingConfidence = (typeof FINDING_CONFIDENCES)[number];
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export interface Finding {
  id: string;
  scan_id: string;
  /** Stable identifier of the rule that fired, e.g. "missing_csp". */
  code: string;
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
  TLS: "TLS",
  INFORMATION_DISCLOSURE: "Information disclosure",
  OTHER: "Other",
};
