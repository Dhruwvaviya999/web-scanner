"use client";

import {
  Braces,
  ChevronDown,
  FileJson,
  KeyRound,
  Network,
  ShieldQuestion,
} from "lucide-react";
import { useMemo, useState } from "react";

import { ErrorAlert } from "@/components/common/error-alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import {
  API_AUTH_STATUS_LABELS,
  API_SOURCE_LABELS,
  type ApiEndpoint,
  type ApiEndpointListResponse,
} from "@/types/api-surface";

const ALL = "ALL";

const METHOD_STYLES: Record<string, string> = {
  GET: "border-info/40 bg-info/15 text-info",
  POST: "border-warning/40 bg-warning/15 text-warning",
  PUT: "border-warning/40 bg-warning/15 text-warning",
  PATCH: "border-warning/40 bg-warning/15 text-warning",
  DELETE: "border-destructive/40 bg-destructive/15 text-destructive",
};

const CONFIDENCE_STYLES: Record<string, string> = {
  HIGH: "border-success/40 bg-success/15 text-success",
  MEDIUM: "border-warning/40 bg-warning/15 text-warning",
  LOW: "border-muted-foreground/30 bg-muted text-muted-foreground",
};

function MethodBadge({ method }: { method: string }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "w-16 justify-center font-mono text-xs font-semibold",
        METHOD_STYLES[method] ?? "border-border text-muted-foreground",
      )}
    >
      {method}
    </Badge>
  );
}

function Stat({
  icon: Icon,
  value,
  label,
  hint,
}: {
  icon: typeof Network;
  value: number | string;
  label: string;
  hint?: string;
}) {
  return (
    <div className="rounded-lg border border-border px-4 py-3">
      <div className="flex items-center gap-3">
        <Icon className="size-4 shrink-0 text-primary" aria-hidden />
        <div className="min-w-0">
          <p className="text-xl leading-none font-semibold tabular-nums">{value}</p>
          <p className="mt-1 text-xs text-muted-foreground">{label}</p>
        </div>
      </div>
      {hint ? <p className="mt-2 text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

function EndpointRow({ endpoint }: { endpoint: ApiEndpoint }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="border-b border-border last:border-0">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-3 py-2.5 text-left hover:bg-muted/40"
      >
        <MethodBadge method={endpoint.method} />
        <span className="min-w-0 flex-1 truncate font-mono text-sm" title={endpoint.path}>
          {endpoint.path}
        </span>
        {endpoint.documented_only ? (
          <Badge
            variant="outline"
            className="border-muted-foreground/30 bg-muted text-xs text-muted-foreground"
          >
            Documented only
          </Badge>
        ) : null}
        <Badge
          variant="outline"
          className={cn("text-xs", CONFIDENCE_STYLES[endpoint.confidence])}
        >
          {endpoint.confidence}
        </Badge>
        <span className="hidden w-28 shrink-0 text-xs text-muted-foreground sm:inline">
          {API_AUTH_STATUS_LABELS[endpoint.auth_status]}
        </span>
        <ChevronDown
          className={cn(
            "size-4 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-180",
          )}
          aria-hidden
        />
      </button>

      {open ? (
        <div className="space-y-3 border-t border-border bg-muted/20 px-3 py-3 text-sm">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div>
              <p className="text-xs text-muted-foreground">Discovered by</p>
              <p className="font-medium">
                {endpoint.discovery_sources
                  .map((source) => API_SOURCE_LABELS[source] ?? source)
                  .join(", ") || "—"}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Response type</p>
              <p className="font-mono text-xs">{endpoint.response_media_type ?? "—"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Accepts</p>
              <p className="font-mono text-xs">{endpoint.request_media_type ?? "—"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Operation</p>
              <p className="font-mono text-xs">{endpoint.operation_id ?? "—"}</p>
            </div>
          </div>

          {endpoint.parameters.length > 0 ? (
            <div>
              <p className="text-xs text-muted-foreground">Parameters</p>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {endpoint.parameters.map((parameter) => (
                  <Badge
                    key={parameter.id}
                    variant="outline"
                    className="font-mono text-xs"
                    title={`${parameter.location}${parameter.required ? " · required" : ""}`}
                  >
                    {parameter.name}
                    <span className="ml-1 text-muted-foreground">
                      {parameter.location.toLowerCase()}
                    </span>
                  </Badge>
                ))}
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Names only. No parameter value is ever recorded.
              </p>
            </div>
          ) : null}

          {endpoint.response_fields.length > 0 ? (
            <div>
              <p className="text-xs text-muted-foreground">Response fields</p>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {endpoint.response_fields.map((field) => (
                  <Badge key={field} variant="outline" className="font-mono text-xs">
                    {field}
                  </Badge>
                ))}
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Field names from the response structure. The values in them were never kept.
              </p>
            </div>
          ) : null}

          {endpoint.security_schemes.length > 0 ? (
            <div>
              <p className="text-xs text-muted-foreground">Declared security</p>
              <p className="font-medium">{endpoint.security_schemes.join(", ")}</p>
            </div>
          ) : null}

          {endpoint.documented_only ? (
            <p className="text-xs text-muted-foreground">
              This operation appears in a specification and was never reached by the scan.
              It has not been shown to exist.
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

interface ApiSurfaceSectionProps {
  data: ApiEndpointListResponse | null;
  loading?: boolean;
  error?: string | null;
}

/**
 * The API attack surface.
 *
 * A classification of what was found, never a judgement about it. The wording
 * throughout keeps three things apart that are easy to blur: what the scan
 * observed, what a document claims, and what nobody established either way.
 */
export function ApiSurfaceSection({
  data,
  loading = false,
  error,
}: ApiSurfaceSectionProps) {
  const [method, setMethod] = useState<string>(ALL);
  const [auth, setAuth] = useState<string>(ALL);
  const [source, setSource] = useState<string>(ALL);

  const endpoints = useMemo(() => data?.items ?? [], [data]);

  const methods = useMemo(
    () => Array.from(new Set(endpoints.map((endpoint) => endpoint.method))).sort(),
    [endpoints],
  );

  const visible = useMemo(
    () =>
      endpoints.filter(
        (endpoint) =>
          (method === ALL || endpoint.method === method) &&
          (auth === ALL || endpoint.auth_status === auth) &&
          (source === ALL || endpoint.discovery_sources.includes(source as never)),
      ),
    [endpoints, method, auth, source],
  );

  if (error) {
    return <ErrorAlert title="API surface unavailable" message={error} />;
  }

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">API attack surface</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {Array.from({ length: 3 }).map((_, index) => (
            <Skeleton key={index} className="h-8 w-full" />
          ))}
        </CardContent>
      </Card>
    );
  }

  const summary = data?.summary;

  if (!summary?.detected) {
    return (
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="text-base">API attack surface</CardTitle>
        </CardHeader>
        <CardContent className="flex items-start gap-3 text-sm">
          <ShieldQuestion
            className="mt-0.5 size-5 shrink-0 text-muted-foreground"
            aria-hidden
          />
          <p className="text-muted-foreground">
            Nothing on this origin behaved like an API, no specification was published at a
            conventional path, and no GraphQL endpoint was found. That is not a guarantee
            there is none — only that the crawl and a short list of well-known documentation
            paths did not reveal one.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardTitle className="text-base">API attack surface</CardTitle>
        {summary.graphql_detected ? (
          <Badge variant="outline" className="border-info/40 bg-info/15 text-info">
            <Network className="mr-1 size-3.5" aria-hidden />
            GraphQL {summary.graphql_path ?? ""}
          </Badge>
        ) : null}
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Stat
            icon={Braces}
            value={summary.endpoints_discovered ?? 0}
            label="API endpoints"
          />
          <Stat
            icon={Network}
            value={summary.endpoints_observed ?? 0}
            label="Observed"
            hint="Requested, and something answered."
          />
          <Stat
            icon={FileJson}
            value={summary.endpoints_documented_only ?? 0}
            label="Documented only"
            hint="Listed in a specification and never reached."
          />
          <Stat
            icon={KeyRound}
            value={summary.authenticated_endpoints ?? 0}
            label="Authenticated"
          />
        </div>

        {summary.truncated ? (
          <p className="text-xs text-warning">
            A limit stopped the inventory growing, so this list is partial.
          </p>
        ) : null}

        {data?.documents.length ? (
          <div className="rounded-lg border border-border px-3 py-2.5 text-sm">
            <p className="font-medium">Specifications found</p>
            <ul className="mt-1 space-y-1 text-muted-foreground">
              {data.documents.map((document) => (
                <li key={document.id} className="font-mono text-xs">
                  {document.title ?? "Untitled"} · {document.version} ·{" "}
                  {document.operation_count} operations
                  {document.truncated ? " · partially read" : ""}
                </li>
              ))}
            </ul>
            <p className="mt-1.5 text-xs text-muted-foreground">
              Read, never executed. Nothing described in a specification was invoked.
            </p>
          </div>
        ) : null}

        {/* --- filters --- */}
        <div className="flex flex-wrap gap-2">
          <Select value={method} onValueChange={(value) => setMethod(value ?? ALL)}>
            <SelectTrigger className="w-32" aria-label="Filter by method">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All methods</SelectItem>
              {methods.map((value) => (
                <SelectItem key={value} value={value}>
                  {value}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={auth} onValueChange={(value) => setAuth(value ?? ALL)}>
            <SelectTrigger className="w-44" aria-label="Filter by authentication">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>Any access</SelectItem>
              {Object.entries(API_AUTH_STATUS_LABELS).map(([value, label]) => (
                <SelectItem key={value} value={value}>
                  {label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={source} onValueChange={(value) => setSource(value ?? ALL)}>
            <SelectTrigger className="w-40" aria-label="Filter by discovery source">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>Any source</SelectItem>
              {Object.entries(API_SOURCE_LABELS).map(([value, label]) => (
                <SelectItem key={value} value={value}>
                  {label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {method !== ALL || auth !== ALL || source !== ALL ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setMethod(ALL);
                setAuth(ALL);
                setSource(ALL);
              }}
            >
              Clear
            </Button>
          ) : null}
        </div>

        <div className="overflow-hidden rounded-lg border border-border">
          {visible.length === 0 ? (
            <p className="px-3 py-6 text-center text-sm text-muted-foreground">
              No API endpoint matches these filters.
            </p>
          ) : (
            visible.map((endpoint) => (
              <EndpointRow key={endpoint.id} endpoint={endpoint} />
            ))
          )}
        </div>

        <p className="text-xs text-muted-foreground">
          Discovery only. An endpoint appearing here means it behaves like an API — not
          that it is vulnerable, and not that it is safe. No operation was invoked, no
          request body was sent, and GraphQL was detected without being queried.
        </p>
      </CardContent>
    </Card>
  );
}
