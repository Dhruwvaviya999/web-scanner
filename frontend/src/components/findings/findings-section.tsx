"use client";

import { ChevronDown, ShieldCheck, ShieldQuestion } from "lucide-react";
import { useState } from "react";

import { ErrorAlert } from "@/components/common/error-alert";
import {
  ConfidenceBadge,
  SeverityBadge,
  SeverityDot,
} from "@/components/findings/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import {
  CATEGORY_LABELS,
  FINDING_SEVERITIES,
  type Finding,
  type FindingListResponse,
  type FindingSeverity,
} from "@/types/finding";

const SUMMARY_LABELS: Record<FindingSeverity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Info",
};

function SummaryRow({ summary }: { summary: FindingListResponse["summary"] }) {
  return (
    <div className="flex flex-wrap gap-2">
      {FINDING_SEVERITIES.map((severity) => {
        const count = summary[severity.toLowerCase() as keyof typeof summary] as number;
        return (
          <div
            key={severity}
            className={cn(
              "flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm",
              count === 0 && "opacity-50",
            )}
          >
            <SeverityDot severity={severity} />
            <span className="font-medium tabular-nums">{count}</span>
            <span className="text-muted-foreground">{SUMMARY_LABELS[severity]}</span>
          </div>
        );
      })}
    </div>
  );
}

function FindingDetail({ label, children }: { label: string; children: string }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {label}
      </p>
      <p className="text-sm leading-relaxed whitespace-pre-line">{children}</p>
    </div>
  );
}

function AffectedEndpoints({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  const withUrl = finding.occurrences.filter((o) => o.endpoint_url !== null);

  if (withUrl.length === 0) return null;

  // A single endpoint is already named in the header; listing it again is noise.
  if (withUrl.length === 1) {
    return (
      <div className="space-y-1">
        <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          Affected endpoint
        </p>
        <p className="font-mono text-sm break-all">{withUrl[0].endpoint_url}</p>
      </div>
    );
  }

  const shown = expanded ? withUrl : withUrl.slice(0, 5);

  return (
    <div className="space-y-2">
      <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
        Affected endpoints: {withUrl.length}
      </p>
      <ul className="space-y-1">
        {shown.map((occurrence) => (
          <li key={occurrence.id} className="font-mono text-xs break-all text-muted-foreground">
            {occurrence.endpoint_url}
          </li>
        ))}
      </ul>
      {withUrl.length > 5 ? (
        <Button variant="ghost" size="sm" onClick={() => setExpanded((value) => !value)}>
          {expanded ? "Show fewer" : `Show all ${withUrl.length}`}
        </Button>
      ) : null}
    </div>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const panelId = `finding-panel-${finding.id}`;

  return (
    <div className="border-b border-border last:border-b-0">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-controls={panelId}
        className="flex w-full items-center gap-3 px-1 py-3 text-left transition-colors hover:bg-muted/40"
      >
        <SeverityDot severity={finding.severity} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium">{finding.title}</span>
          <span className="mt-0.5 block truncate text-xs text-muted-foreground">
            {CATEGORY_LABELS[finding.category]}
            {finding.endpoint ? (
              <>
                {" · "}
                <span className="font-mono">
                  {finding.endpoint.method} {finding.endpoint.path}
                </span>
              </>
            ) : null}
            {finding.occurrence_count > 1 ? (
              <> {" · "}{finding.occurrence_count} endpoints affected</>
            ) : null}
          </span>
        </span>
        <SeverityBadge severity={finding.severity} />
        <ChevronDown
          className={cn(
            "size-4 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-180",
          )}
          aria-hidden
        />
      </button>

      {open ? (
        <div id={panelId} className="space-y-4 px-1 pt-1 pb-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <ConfidenceBadge confidence={finding.confidence} />
            <Badge variant="outline" className="border-border text-muted-foreground">
              {CATEGORY_LABELS[finding.category]}
            </Badge>
            {finding.subject ? (
              <Badge variant="outline" className="border-border font-mono text-muted-foreground">
                {finding.subject}
              </Badge>
            ) : null}
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
              {finding.rule_id}
            </code>
          </div>

          <FindingDetail label="Description">{finding.description}</FindingDetail>

          <div className="space-y-1">
            <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
              Evidence
            </p>
            <p className="rounded-md border border-border bg-muted/50 px-3 py-2 font-mono text-xs leading-relaxed break-words">
              {finding.evidence}
            </p>
          </div>

          <FindingDetail label="Impact">{finding.impact}</FindingDetail>
          <FindingDetail label="Remediation">{finding.remediation}</FindingDetail>

          <AffectedEndpoints finding={finding} />
        </div>
      ) : null}
    </div>
  );
}

interface FindingsSectionProps {
  data: FindingListResponse | null;
  loading: boolean;
  error: string | null;
  /** Findings are only produced for a scan that got a response. */
  scanFailed: boolean;
}

export function FindingsSection({ data, loading, error, scanFailed }: FindingsSectionProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Security Findings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {loading ? (
          <div className="space-y-2">
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : error ? (
          <ErrorAlert title="Findings unavailable" message={error} />
        ) : scanFailed ? (
          <div className="flex items-start gap-3 rounded-md border border-dashed border-border px-4 py-6">
            <ShieldQuestion className="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-hidden />
            <div className="space-y-1 text-sm">
              <p className="font-medium">No analysis was possible</p>
              <p className="text-muted-foreground">
                The scan did not receive a response from the target, so there was nothing to
                analyse.
              </p>
            </div>
          </div>
        ) : !data || data.items.length === 0 ? (
          <div className="flex items-start gap-3 rounded-md border border-dashed border-border px-4 py-6">
            <ShieldCheck className="mt-0.5 size-5 shrink-0 text-success" aria-hidden />
            <div className="space-y-1 text-sm">
              <p className="font-medium">
                No findings were detected by the checks performed in this scan
              </p>
              {/* Deliberately not "this site is secure": only security headers and
                  cookies were examined, and only on a single response. */}
              <p className="text-muted-foreground">
                This scan examined security headers and cookies on the endpoints it reached.
                That is a narrow set of checks — it is not an assessment of whether the site is
                secure.
              </p>
            </div>
          </div>
        ) : (
          <>
            <SummaryRow summary={data.summary} />
            <p className="text-sm text-muted-foreground">
              {data.summary.total} finding{data.summary.total === 1 ? "" : "s"} from security
              header and cookie checks across the analysed endpoints. Repeats of the same rule are
              grouped; select one for evidence, remediation and every endpoint it affects.
            </p>
            <div className="rounded-lg border border-border px-3">
              {data.items.map((finding) => (
                <FindingRow key={finding.id} finding={finding} />
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              These are configuration observations, not confirmed vulnerabilities. No payloads
              were sent and no exploitation was attempted.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
