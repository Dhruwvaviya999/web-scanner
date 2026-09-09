export const SCAN_STATUSES = [
  "QUEUED",
  "RUNNING",
  "COMPLETED",
  "FAILED",
  "CANCELLED",
] as const;

/** States a scan can still leave. Anything else is terminal. */
export const ACTIVE_SCAN_STATUSES = ["QUEUED", "RUNNING"] as const;

/**
 * How a scan authenticates **to the target application**.
 *
 * Not the scanner's own login. This is a credential the user already holds for
 * an application they are authorised to test. The scanner never discovers,
 * guesses or brute-forces one.
 */
export const AUTH_MODES = ["NONE", "BEARER_TOKEN", "COOKIE"] as const;

export type AuthMode = (typeof AUTH_MODES)[number];

/** What one initial access check concluded about the supplied credential. */
export const AUTH_STATUSES = [
  "NOT_CONFIGURED",
  "AVAILABLE",
  "REJECTED",
  "UNKNOWN",
] as const;

export type AuthStatus = (typeof AUTH_STATUSES)[number];

export const AUTH_MODE_LABELS: Record<AuthMode, string> = {
  NONE: "None",
  BEARER_TOKEN: "Bearer token",
  COOKIE: "Cookies",
};

export const AUTH_STATUS_LABELS: Record<AuthStatus, string> = {
  NOT_CONFIGURED: "Not configured",
  AVAILABLE: "Available",
  REJECTED: "Rejected",
  UNKNOWN: "Unconfirmed",
};

/**
 * Safe authentication metadata for a scan.
 *
 * There is deliberately no field here for a token or a cookie value: the API
 * never returns one, so the type cannot describe one.
 */
export interface ScanAuthenticationInfo {
  mode: AuthMode;
  status: AuthStatus;
  enabled: boolean;
}

export type ScanStatus = (typeof SCAN_STATUSES)[number];

export interface Scan {
  id: string;
  target_url: string;
  status: ScanStatus;
  queued_at: string | null;
  started_at: string | null;
  /** Set for every ending — completed, failed and cancelled alike. */
  completed_at: string | null;
  /** When cancellation was requested, not when the run wound down. */
  cancelled_at: string | null;
  created_at: string;
  updated_at: string;

  /** Lifecycle stage, e.g. `CRAWLING`. Null before a scan starts. */
  current_stage: string | null;
  /** Indicative only: a stage milestone, never a measurement of work done. */
  progress_percent: number | null;
  progress_message: string | null;
  /**
   * True once the owner has asked the scan to stop. The scan stays RUNNING
   * until it observes the request — the status is what says it has stopped.
   */
  cancel_requested: boolean;
  /** Which stage a failed scan was in. A stage name only, never a trace. */
  failure_stage: string | null;

  /** How the scan authenticated to the target. Metadata only — never a secret. */
  auth_mode: AuthMode;
  auth_status: AuthStatus;
  authentication: ScanAuthenticationInfo;

  /** Basic HTTP probe result. Null until a scan completes, or when it failed. */
  http_status_code: number | null;
  response_time_ms: number | null;
  final_url: string | null;
  content_type: string | null;
  server_header: string | null;
  is_https: boolean | null;
  redirect_count: number | null;

  /** Response analysis. Null when the target returned no HTML title / size. */
  page_title: string | null;
  content_length: number | null;

  /** Crawl summary. Null when the crawler did not run for this scan. */
  pages_crawled: number | null;
  pages_skipped: number | null;
  max_depth_reached: number | null;
  crawl_limit_reached: boolean | null;

  /** Scan summary. Null when the corresponding stage did not run. */
  endpoints_discovered: number | null;
  endpoints_analyzed: number | null;
  endpoints_skipped: number | null;
  endpoints_failed: number | null;
  forms_discovered: number | null;
  parameters_discovered: number | null;

  total_findings: number | null;
  critical_count: number | null;
  high_count: number | null;
  medium_count: number | null;
  low_count: number | null;
  info_count: number | null;

  /** Set only when `status === "FAILED"`. */
  error_message: string | null;
}

export interface ScanListResponse {
  items: Scan[];
  total: number;
  limit: number;
  offset: number;
}

export interface ScanStats {
  total: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
  cancelled: number;
}

/** Whether a scan can still change state, and so is worth polling for. */
export function isScanActive(scan: Pick<Scan, "status">): boolean {
  return scan.status === "QUEUED" || scan.status === "RUNNING";
}

/** Whether credentials were supplied and the target refused them. */
export function isAuthRejected(scan: Pick<Scan, "auth_mode" | "auth_status">): boolean {
  return scan.auth_mode !== "NONE" && scan.auth_status === "REJECTED";
}

/** Whether a scan stopped before covering everything it could have. */
export function isScanInconclusive(scan: Pick<Scan, "status">): boolean {
  return scan.status === "FAILED" || scan.status === "CANCELLED";
}

/**
 * Target-authentication material for one scan.
 *
 * Sent once, in the body of the create request, over the same authenticated
 * session as everything else. It is never placed in a URL, never written to
 * localStorage or sessionStorage, and never read back from the API — the
 * server has nowhere to return it from.
 */
export interface CreateScanAuthentication {
  mode: AuthMode;
  token?: string;
  cookies?: { name: string; value: string }[];
}

export interface CreateScanPayload {
  target_url: string;
  authentication?: CreateScanAuthentication;
}

export interface ListScansParams {
  limit?: number;
  offset?: number;
  status?: ScanStatus;
}
