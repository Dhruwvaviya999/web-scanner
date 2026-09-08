export const PARAMETER_LOCATIONS = ["QUERY", "PATH", "FORM"] as const;
export const ENDPOINT_ANALYSIS_STATUSES = [
  "NOT_ANALYZED",
  "ANALYZED",
  "SKIPPED",
  "FAILED",
] as const;
export const ANALYSIS_SKIP_REASONS = [
  "NON_HTML",
  "EXTERNAL",
  "DUPLICATE",
  "CRAWL_LIMIT",
  "REQUEST_FAILED",
  "UNSUPPORTED_SCHEME",
  "EXCLUDED_RESOURCE",
] as const;

export const FORM_FIELD_KINDS = ["INPUT", "TEXTAREA", "SELECT", "BUTTON"] as const;

export type ParameterLocation = (typeof PARAMETER_LOCATIONS)[number];
export type FormFieldKind = (typeof FORM_FIELD_KINDS)[number];
export type EndpointAnalysisStatus = (typeof ENDPOINT_ANALYSIS_STATUSES)[number];
export type AnalysisSkipReason = (typeof ANALYSIS_SKIP_REASONS)[number];

export interface EndpointParameter {
  id: string;
  /** Parameter name. Values are never recorded by the crawler. */
  name: string;
  location: ParameterLocation;
}

export interface Endpoint {
  id: string;
  scan_id: string;
  /** Canonical URL: query parameter names are kept, their values removed. */
  url: string;
  path: string;
  method: string;
  status_code: number | null;
  content_type: string | null;
  depth: number;
  page_title: string | null;
  discovered_at: string;
  analysis_status: EndpointAnalysisStatus;
  skip_reason: AnalysisSkipReason | null;
  analysis_error: string | null;
  parameters: EndpointParameter[];
}

export interface FormField {
  id: string;
  name: string;
  kind: FormFieldKind;
  /** The input's `type` attribute. Metadata only — values are never stored. */
  input_type: string | null;
}

export interface DiscoveredForm {
  id: string;
  scan_id: string;
  page_url: string;
  action: string;
  method: string;
  discovered_at: string;
  fields: FormField[];
}

export interface AttackSurfaceSummary {
  endpoints: number;
  forms: number;
  /** Distinct parameter names across all endpoints. */
  parameters: number;
  pages_crawled: number | null;
  pages_skipped: number | null;
  max_depth_reached: number | null;
  /** True when max_pages or the time budget ended the crawl. Normal termination. */
  crawl_limit_reached: boolean | null;

  /** Coverage: how many discovered endpoints were actually assessed. */
  endpoints_analyzed: number | null;
  endpoints_skipped: number | null;
  /** Endpoints that could not be assessed. These never produce findings. */
  endpoints_failed: number | null;
}

export interface EndpointListResponse {
  items: Endpoint[];
  summary: AttackSurfaceSummary;
}

export interface FormListResponse {
  items: DiscoveredForm[];
  total: number;
}
