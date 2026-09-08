"use client";

import { FileInput, Globe2, Layers, SlidersHorizontal, Spline } from "lucide-react";
import { useMemo, useState } from "react";

import { ErrorAlert } from "@/components/common/error-alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { truncateUrl } from "@/lib/format";
import type {
  DiscoveredForm,
  Endpoint,
  EndpointListResponse,
  FormListResponse,
} from "@/types/attack-surface";

type Tab = "endpoints" | "forms" | "parameters";

const METHOD_STYLES: Record<string, string> = {
  GET: "border-info/40 bg-info/15 text-info",
  POST: "border-warning/40 bg-warning/15 text-warning",
};

function MethodBadge({ method }: { method: string }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "w-14 justify-center font-mono text-xs font-semibold",
        METHOD_STYLES[method] ?? "border-border text-muted-foreground",
      )}
    >
      {method}
    </Badge>
  );
}

function StatCell({
  icon: Icon,
  value,
  label,
}: {
  icon: typeof Globe2;
  value: number | string;
  label: string;
}) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-border px-4 py-3">
      <Icon className="size-4 shrink-0 text-primary" aria-hidden />
      <div className="min-w-0">
        <p className="text-xl leading-none font-semibold tabular-nums">{value}</p>
        <p className="mt-1 text-xs text-muted-foreground">{label}</p>
      </div>
    </div>
  );
}

function EndpointRow({ endpoint }: { endpoint: Endpoint }) {
  const parameters = endpoint.parameters.map((p) => p.name);

  return (
    <div className="flex items-start gap-3 border-b border-border py-2.5 last:border-b-0">
      <MethodBadge method={endpoint.method} />
      <div className="min-w-0 flex-1">
        <p className="truncate font-mono text-sm" title={endpoint.url}>
          {endpoint.path}
          {parameters.length > 0 ? (
            <span className="text-muted-foreground">?{parameters.join("&")}</span>
          ) : null}
        </p>
        {endpoint.page_title ? (
          <p className="mt-0.5 truncate text-xs text-muted-foreground">{endpoint.page_title}</p>
        ) : null}
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <span className="text-xs text-muted-foreground">d{endpoint.depth}</span>
        <span
          className={cn(
            "font-mono text-xs tabular-nums",
            endpoint.status_code && endpoint.status_code >= 400
              ? "text-destructive"
              : "text-muted-foreground",
          )}
        >
          {endpoint.status_code ?? "—"}
        </span>
      </div>
    </div>
  );
}

function FormRow({ form }: { form: DiscoveredForm }) {
  return (
    <div className="space-y-2 border-b border-border py-3 last:border-b-0">
      <div className="flex items-start gap-3">
        <MethodBadge method={form.method} />
        <p className="min-w-0 flex-1 truncate font-mono text-sm" title={form.action}>
          {truncateUrl(form.action, 64)}
        </p>
      </div>
      {form.fields.length > 0 ? (
        <div className="flex flex-wrap gap-1.5 pl-[4.25rem]">
          {form.fields.map((field) => (
            <Badge
              key={field.id}
              variant="outline"
              className={cn(
                "font-mono text-xs",
                field.input_type === "password"
                  ? "border-warning/40 bg-warning/10 text-warning"
                  : "border-border text-muted-foreground",
              )}
            >
              {field.name}
              {field.input_type ? (
                <span className="opacity-60">:{field.input_type}</span>
              ) : null}
            </Badge>
          ))}
        </div>
      ) : (
        <p className="pl-[4.25rem] text-xs text-muted-foreground">No named fields.</p>
      )}
    </div>
  );
}

interface AttackSurfaceSectionProps {
  endpoints: EndpointListResponse | null;
  forms: FormListResponse | null;
  loading: boolean;
  error: string | null;
  scanFailed: boolean;
}

export function AttackSurfaceSection({
  endpoints,
  forms,
  loading,
  error,
  scanFailed,
}: AttackSurfaceSectionProps) {
  const [tab, setTab] = useState<Tab>("endpoints");

  // One parameter may appear on many endpoints; show each name once.
  const parameterNames = useMemo(() => {
    const names = new Set<string>();
    for (const endpoint of endpoints?.items ?? []) {
      for (const parameter of endpoint.parameters) names.add(parameter.name);
    }
    return [...names].sort();
  }, [endpoints]);

  const summary = endpoints?.summary;
  const crawled = summary?.pages_crawled;

  const tabs: { id: Tab; label: string; count: number }[] = [
    { id: "endpoints", label: "Endpoints", count: summary?.endpoints ?? 0 },
    { id: "forms", label: "Forms", count: forms?.total ?? 0 },
    { id: "parameters", label: "Parameters", count: parameterNames.length },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Attack Surface</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-32 w-full" />
          </div>
        ) : error ? (
          <ErrorAlert title="Attack surface unavailable" message={error} />
        ) : scanFailed || crawled === null || crawled === undefined ? (
          <div className="rounded-md border border-dashed border-border px-4 py-6 text-sm">
            <p className="font-medium">No crawl was performed</p>
            <p className="mt-1 text-muted-foreground">
              {scanFailed
                ? "The scan did not reach the target, so there was nothing to crawl."
                : "This scan was recorded before crawling was enabled."}
            </p>
          </div>
        ) : (
          <>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <StatCell icon={Globe2} value={crawled} label="Pages crawled" />
              <StatCell icon={Spline} value={summary?.endpoints ?? 0} label="Endpoints" />
              <StatCell icon={FileInput} value={forms?.total ?? 0} label="Forms" />
              <StatCell
                icon={SlidersHorizontal}
                value={parameterNames.length}
                label="Parameters"
              />
            </div>

            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <Layers className="size-3.5" aria-hidden />
                Max depth reached: {summary?.max_depth_reached ?? 0}
              </span>
              <span>Links skipped: {summary?.pages_skipped ?? 0}</span>
              {summary?.crawl_limit_reached ? (
                // Hitting a limit is normal termination, not a failure.
                <Badge variant="outline" className="border-info/40 bg-info/10 text-info">
                  Crawl limit reached
                </Badge>
              ) : null}
            </div>

            <div className="flex flex-wrap gap-1 border-b border-border">
              {tabs.map((entry) => (
                <Button
                  key={entry.id}
                  variant="ghost"
                  size="sm"
                  onClick={() => setTab(entry.id)}
                  aria-pressed={tab === entry.id}
                  className={cn(
                    "-mb-px rounded-b-none border-b-2 border-transparent",
                    tab === entry.id && "border-primary text-primary",
                  )}
                >
                  {entry.label}
                  <span className="ml-1.5 tabular-nums opacity-70">{entry.count}</span>
                </Button>
              ))}
            </div>

            {tab === "endpoints" ? (
              endpoints && endpoints.items.length > 0 ? (
                <div className="max-h-96 overflow-y-auto pr-1">
                  {endpoints.items.map((endpoint) => (
                    <EndpointRow key={endpoint.id} endpoint={endpoint} />
                  ))}
                </div>
              ) : (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  No endpoints were discovered.
                </p>
              )
            ) : null}

            {tab === "forms" ? (
              forms && forms.items.length > 0 ? (
                <div className="max-h-96 overflow-y-auto pr-1">
                  {forms.items.map((form) => (
                    <FormRow key={form.id} form={form} />
                  ))}
                </div>
              ) : (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  No forms were found on the crawled pages.
                </p>
              )
            ) : null}

            {tab === "parameters" ? (
              parameterNames.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {parameterNames.map((name) => (
                    <Badge key={name} variant="outline" className="border-border font-mono">
                      {name}
                    </Badge>
                  ))}
                </div>
              ) : (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  No query parameters were discovered.
                </p>
              )
            ) : null}

            <p className="text-xs text-muted-foreground">
              Discovery only. The crawler stays on this origin, follows no external links,
              submits no forms and sends no payloads. Parameter and field values are never
              recorded.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
