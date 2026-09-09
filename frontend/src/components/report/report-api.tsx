import { Braces, FileJson, Network, ShieldQuestion } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { ReportApiSurface } from "@/types/report";

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-sm font-medium tabular-nums">{value}</p>
    </div>
  );
}

/**
 * The report's API attack-surface section.
 *
 * Its whole job is to keep three claims apart, because collapsing them is how
 * an API inventory becomes misleading: what the scan observed working, what a
 * specification merely claims exists, and the fact that neither amounts to a
 * complete list of the application's APIs.
 */
export function ReportApiSection({ api }: { api: ReportApiSurface }) {
  if (!api.detected) {
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
            No API endpoint, specification or GraphQL endpoint was identified. That is not
            a guarantee the application has none — only that the crawl and a short list of
            conventional documentation paths did not reveal one.
          </p>
        </CardContent>
      </Card>
    );
  }

  const documentedOnly = api.endpoints.filter((endpoint) => endpoint.documented_only);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardTitle className="text-base">API attack surface</CardTitle>
        {api.graphql_detected ? (
          <Badge variant="outline" className="border-info/40 bg-info/15 text-info">
            <Network className="mr-1 size-3.5" aria-hidden />
            GraphQL detected
          </Badge>
        ) : null}
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
          <Stat label="Endpoints" value={api.endpoints_discovered} />
          <Stat label="Observed" value={api.endpoints_observed} />
          <Stat label="Documented only" value={api.endpoints_documented_only} />
          <Stat label="Parameters" value={api.parameters_discovered} />
          <Stat label="Specifications" value={api.openapi_documents} />
          <Stat label="Authenticated" value={api.authenticated_endpoints} />
        </div>

        <p className="text-sm text-muted-foreground">
          {api.endpoints_observed} endpoint{api.endpoints_observed === 1 ? " was" : "s were"}{" "}
          requested and answered.{" "}
          {api.endpoints_documented_only > 0
            ? `${api.endpoints_documented_only} more appear only in a specification and were never reached, so they have not been shown to exist.`
            : "Every endpoint listed was reached during the scan."}{" "}
          {api.truncated
            ? "A limit stopped the inventory growing, so this list is partial."
            : "This is what the crawl and the published documentation revealed, which is not necessarily every API the application has."}
        </p>

        {api.graphql_detected ? (
          <p className="text-sm text-muted-foreground">
            A GraphQL endpoint was found
            {api.graphql_path ? ` at ${api.graphql_path}` : ""}. Its presence was detected
            from the response alone — introspection was not run
            {api.graphql_introspection_tested ? "" : " and no query or mutation was sent"}.
          </p>
        ) : null}

        {api.documents.length > 0 ? (
          <div className="rounded-lg border border-border px-3 py-2.5 text-sm">
            <p className="font-medium">Specifications read</p>
            <ul className="mt-1 space-y-1 text-muted-foreground">
              {api.documents.map((document) => (
                <li key={document.url} className="font-mono text-xs">
                  {document.title ?? "Untitled"} · {document.version} ·{" "}
                  {document.operation_count} operations
                  {document.security_schemes.length > 0
                    ? ` · declares ${document.security_schemes.join(", ")}`
                    : ""}
                </li>
              ))}
            </ul>
            <p className="mt-1.5 text-xs text-muted-foreground">
              Read, never executed. No operation described in a specification was invoked.
            </p>
          </div>
        ) : null}

        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="px-3 py-2 font-medium">Method</th>
                <th className="px-3 py-2 font-medium">Path</th>
                <th className="px-3 py-2 font-medium">Access</th>
                <th className="px-3 py-2 font-medium">Evidence</th>
                <th className="px-3 py-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody>
              {api.endpoints.map((endpoint) => (
                <tr
                  key={`${endpoint.method} ${endpoint.path}`}
                  className="border-b border-border last:border-0"
                >
                  <td className="px-3 py-2 font-mono text-xs font-semibold">
                    {endpoint.method}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{endpoint.path}</td>
                  <td className="px-3 py-2 text-xs">{endpoint.auth_status}</td>
                  <td
                    className={cn(
                      "px-3 py-2 text-xs",
                      endpoint.documented_only && "text-muted-foreground",
                    )}
                  >
                    {endpoint.observed ? "Observed" : "Documented only"}
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">
                    {endpoint.sources.join(", ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="flex items-start gap-3 text-xs text-muted-foreground">
          <Braces className="mt-0.5 size-4 shrink-0" aria-hidden />
          <p>
            Discovery only. This section says which endpoints behave like APIs and how they
            were found; it is not a test of them, and it never claims an API is secure. No
            request body was sent and no documented operation was invoked.
          </p>
        </div>

        {documentedOnly.length > 0 ? (
          <div className="flex items-start gap-3 text-xs text-muted-foreground">
            <FileJson className="mt-0.5 size-4 shrink-0" aria-hidden />
            <p>
              Operations marked &quot;documented only&quot; come from a specification the
              target published. They were not requested, so nothing here establishes that
              they exist, work, or are reachable.
            </p>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
