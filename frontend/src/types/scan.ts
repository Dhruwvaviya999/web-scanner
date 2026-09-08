export const SCAN_STATUSES = ["PENDING", "RUNNING", "COMPLETED", "FAILED"] as const;

export type ScanStatus = (typeof SCAN_STATUSES)[number];

export interface Scan {
  id: string;
  target_url: string;
  status: ScanStatus;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;

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
  pending: number;
  running: number;
  completed: number;
  failed: number;
}

export interface CreateScanPayload {
  target_url: string;
}

export interface ListScansParams {
  limit?: number;
  offset?: number;
  status?: ScanStatus;
}
