/**
 * The API attack surface.
 *
 * Reconnaissance, not a verdict. An endpoint appearing here means the scanner
 * believes it behaves like an API — not that it is vulnerable, and not that it
 * is safe.
 *
 * Note `observed` against `documented`. The first means the scanner requested
 * it and something answered; the second means a specification claims it exists.
 * They are counted separately on purpose: adding them together is how an API
 * inventory ends up describing operations nobody has ever reached.
 *
 * No type here can carry a response value, a credential or a header.
 * `response_fields` is a list of field *names*; the data that was in them was
 * discarded at capture time.
 */

export const API_CONFIDENCES = ["HIGH", "MEDIUM", "LOW"] as const;

export const API_AUTH_STATUSES = [
  "ANONYMOUS_ACCESSIBLE",
  "AUTHENTICATED_ACCESSIBLE",
  "AUTH_REQUIRED",
  "UNKNOWN",
] as const;

export const API_SOURCES = [
  "CRAWLER",
  "OPENAPI",
  "SWAGGER",
  "FORM",
  "RESPONSE_ANALYSIS",
  "GRAPHQL",
] as const;

export const API_PARAMETER_LOCATIONS = [
  "PATH",
  "QUERY",
  "HEADER",
  "COOKIE",
  "BODY",
] as const;

export type ApiConfidence = (typeof API_CONFIDENCES)[number];
export type ApiAuthStatus = (typeof API_AUTH_STATUSES)[number];
export type ApiSource = (typeof API_SOURCES)[number];
export type ApiParameterLocation = (typeof API_PARAMETER_LOCATIONS)[number];

export const API_AUTH_STATUS_LABELS: Record<ApiAuthStatus, string> = {
  ANONYMOUS_ACCESSIBLE: "Public",
  AUTHENTICATED_ACCESSIBLE: "Authenticated",
  AUTH_REQUIRED: "Auth required",
  UNKNOWN: "Unknown",
};

export const API_SOURCE_LABELS: Record<ApiSource, string> = {
  CRAWLER: "Crawled",
  OPENAPI: "OpenAPI",
  SWAGGER: "Swagger",
  FORM: "Form",
  RESPONSE_ANALYSIS: "Response",
  GRAPHQL: "GraphQL",
};

export interface ApiEndpointParameter {
  id: string;
  /** Parameter name. Values are never recorded. */
  name: string;
  location: ApiParameterLocation;
  /** From a specification, when it said. Null means nobody said. */
  required: boolean | null;
}

export interface ApiEndpoint {
  id: string;
  scan_id: string;
  /** The crawl row this was seen on. Null when only documented. */
  endpoint_id: string | null;
  path: string;
  method: string;
  url: string | null;
  confidence: ApiConfidence;
  auth_status: ApiAuthStatus;
  /** The scanner requested it and something answered. */
  observed: boolean;
  /** A specification says it exists. A claim, not a fact. */
  documented: boolean;
  /** Described by a specification and never actually reached. */
  documented_only: boolean;
  status_code: number | null;
  request_media_type: string | null;
  response_media_type: string | null;
  operation_id: string | null;
  json_top_level: string | null;
  json_depth: number | null;
  json_field_count: number | null;
  discovered_at: string;
  parameters: ApiEndpointParameter[];
  /** Every mechanism that found this operation. More than one is normal. */
  discovery_sources: ApiSource[];
  /** Security scheme names a specification declared. Never a credential. */
  security_schemes: string[];
  /** Field names seen in a JSON response. Never a value from one. */
  response_fields: string[];
}

export interface ApiDocument {
  id: string;
  url: string;
  version: string;
  title: string | null;
  document_version: string | null;
  path_count: number;
  operation_count: number;
  truncated: boolean;
  discovered_at: string;
  schemes: string[];
}

export interface ApiSurfaceSummary {
  detected: boolean;
  endpoints_discovered: number | null;
  /** Actually requested and answered, as opposed to merely described. */
  endpoints_observed: number | null;
  /** Described by a specification and never reached. */
  endpoints_documented_only: number | null;
  parameters_discovered: number | null;
  documents: number | null;
  authenticated_endpoints: number | null;
  unknown_auth_endpoints: number | null;
  graphql_detected: boolean;
  graphql_path: string | null;
  truncated: boolean;
}

export interface ApiEndpointListResponse {
  items: ApiEndpoint[];
  documents: ApiDocument[];
  summary: ApiSurfaceSummary;
}
