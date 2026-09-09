"use client";

import {
  AlertTriangle,
  CalendarClock,
  CheckCircle2,
  CircleSlash,
  KeyRound,
  Globe2,
  ShieldQuestion,
  Timer,
  type LucideIcon,
} from "lucide-react";

import { SeverityDot } from "@/components/findings/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { formatDateTime } from "@/lib/format";
import { FINDING_SEVERITIES, type FindingSeverity } from "@/types/finding";
import type { CoverageSummary, ReportMetadata, SeveritySummary } from "@/types/report";
import { AUTH_MODE_LABELS, AUTH_STATUS_LABELS } from "@/types/scan";

const SEVERITY_LABELS: Record<FindingSeverity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Informational",
};

function formatDuration(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

function MetaItem({
  icon: Icon,
  label,
  children,
}: {
  icon: LucideIcon;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-3">
      <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
      <div className="min-w-0">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="truncate text-sm font-medium">{children}</p>
      </div>
    </div>
  );
}

export function ReportHeader({ metadata }: { metadata: ReportMetadata }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Executive summary</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <MetaItem icon={Globe2} label="Target">
          <span className="font-mono" title={metadata.target_url}>
            {metadata.target_url}
          </span>
        </MetaItem>
        <MetaItem icon={CalendarClock} label="Scanned">
          {formatDateTime(metadata.started_at)}
        </MetaItem>
        <MetaItem icon={Timer} label="Duration">
          {formatDuration(metadata.duration_seconds)}
        </MetaItem>
        <MetaItem icon={ShieldQuestion} label="Status">
          {metadata.status}
        </MetaItem>
        <MetaItem icon={KeyRound} label="Authentication">
          {metadata.authentication.authenticated
            ? `${AUTH_MODE_LABELS[metadata.authentication.mode]} · ${
                AUTH_STATUS_LABELS[metadata.authentication.status]
              }`
            : "Not configured"}
        </MetaItem>
      </CardContent>
    </Card>
  );
}

/**
 * The report's headline conclusion.
 *
 * The wording is deliberately conditional on coverage: a scan with no findings
 * but incomplete coverage must never read as "secure", because the checks that
 * would have found something may simply not have run.
 */
export function ReportVerdict({
  metadata,
  severity,
  coverage,
}: {
  metadata: ReportMetadata;
  severity: SeveritySummary;
  coverage: CoverageSummary;
}) {
  if (metadata.status === "FAILED") {
    return (
      <Card className="border-destructive/40">
        <CardContent className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 size-5 shrink-0 text-destructive" aria-hidden />
          <div className="space-y-1 text-sm">
            <p className="font-medium">The scan did not complete</p>
            <p className="text-muted-foreground">
              {metadata.error_message ??
                "The target could not be reached, so nothing was assessed."}{" "}
              No conclusion about this target can be drawn from this report.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (metadata.authentication.authenticated && metadata.authentication.status === "REJECTED") {
    return (
      <Card className="border-warning/40">
        <CardContent className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
          <div className="space-y-1 text-sm">
            <p className="font-medium">The target refused the credentials supplied</p>
            <p className="text-muted-foreground">
              The scan ran, but as an anonymous visitor: everything behind the login was never
              reached. Whatever this report does not list may simply never have been checked, so
              it says nothing about the authenticated part of the application.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (metadata.status === "CANCELLED") {
    return (
      <Card className="border-warning/40">
        <CardContent className="flex items-start gap-3">
          <CircleSlash className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
          <div className="space-y-1 text-sm">
            <p className="font-medium">This scan was stopped before it finished</p>
            <p className="text-muted-foreground">
              What it found up to that point is reported below, but the target was not fully
              assessed. Whatever this report does not list may simply never have been checked,
              so treat it as inconclusive rather than clean.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (metadata.status === "QUEUED" || metadata.status === "RUNNING") {
    return (
      <Card className="border-info/40">
        <CardContent className="flex items-start gap-3">
          <ShieldQuestion className="mt-0.5 size-5 shrink-0 text-info" aria-hidden />
          <div className="space-y-1 text-sm">
            <p className="font-medium">
              {metadata.status === "QUEUED" ? "This scan has not started yet" : "This scan is still running"}
            </p>
            <p className="text-muted-foreground">
              The report shows what has been recorded so far and is not final.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (severity.total > 0) {
    const worst = FINDING_SEVERITIES.find(
      (level) => severity[level.toLowerCase() as keyof SeveritySummary] > 0,
    );
    return (
      <Card className="border-warning/40">
        <CardContent className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
          <div className="space-y-1 text-sm">
            <p className="font-medium">
              {severity.total} finding{severity.total === 1 ? "" : "s"} recorded
              {worst ? ` — highest severity ${SEVERITY_LABELS[worst].toLowerCase()}` : ""}
            </p>
            <p className="text-muted-foreground">
              Each finding below lists what was observed, where, and how to address it.
              Findings are observations from the checks performed, not confirmed exploits.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  // No findings. What that means depends entirely on coverage.
  return (
    <Card className={coverage.is_complete ? "border-success/40" : "border-warning/40"}>
      <CardContent className="flex items-start gap-3">
        {coverage.is_complete ? (
          <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-success" aria-hidden />
        ) : (
          <AlertTriangle className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
        )}
        <div className="space-y-1 text-sm">
          <p className="font-medium">
            {coverage.is_complete
              ? "No findings from the checks performed"
              : "No findings, but coverage was incomplete"}
          </p>
          <p className="text-muted-foreground">
            {coverage.is_complete
              ? "Every endpoint that was discovered was analysed, and none of the checks in this scan reported an issue. That is not a proof of security: the scanner performs a specific, limited set of checks."
              : "Some discovered endpoints were not analysed, so checks that might have reported an issue may never have run. Treat this result as inconclusive rather than clean."}{" "}
            {metadata.authentication.authenticated
              ? "Results reflect the endpoints reachable with the authentication context supplied — no other user, role or permission level was tested."
              : "Authentication was not configured, so only the surface a signed-out visitor can reach was covered."}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

export function SeverityOverview({ severity }: { severity: SeveritySummary }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Severity overview</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-5">
          {FINDING_SEVERITIES.map((level) => {
            const count = severity[level.toLowerCase() as keyof SeveritySummary] as number;
            return (
              <div
                key={level}
                className={cn(
                  "flex items-center gap-3 rounded-lg border border-border px-4 py-3",
                  count === 0 && "opacity-50",
                )}
              >
                <SeverityDot severity={level} />
                <div>
                  <p className="text-xl leading-none font-semibold tabular-nums">{count}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {SEVERITY_LABELS[level]}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

function CoverageStat({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="rounded-lg border border-border px-4 py-3">
      <p className="text-xl leading-none font-semibold tabular-nums">{value ?? "—"}</p>
      <p className="mt-1 text-xs text-muted-foreground">{label}</p>
    </div>
  );
}

export function CoverageSection({
  coverage,
  attackSurface,
}: {
  coverage: CoverageSummary;
  attackSurface: { endpoints: number; forms: number; parameters: number };
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardTitle className="text-base">Coverage &amp; attack surface</CardTitle>
        {coverage.is_complete ? (
          <Badge variant="outline" className="border-success/40 bg-success/10 text-success">
            Full coverage
          </Badge>
        ) : (
          <Badge variant="outline" className="border-warning/40 bg-warning/10 text-warning">
            Partial coverage
          </Badge>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <CoverageStat label="Endpoints discovered" value={coverage.endpoints_discovered} />
          <CoverageStat label="Analysed" value={coverage.endpoints_analyzed} />
          <CoverageStat label="Skipped" value={coverage.endpoints_skipped} />
          <CoverageStat label="Failed to analyse" value={coverage.endpoints_failed} />
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <CoverageStat label="Forms discovered" value={attackSurface.forms} />
          <CoverageStat label="Parameters discovered" value={attackSurface.parameters} />
          <CoverageStat label="Pages crawled" value={coverage.pages_crawled} />
        </div>

        {coverage.endpoints_failed ? (
          <p className="text-xs text-warning">
            {coverage.endpoints_failed} endpoint
            {coverage.endpoints_failed === 1 ? "" : "s"} could not be analysed. No findings were
            produced for them — their state is unknown, not clean.
          </p>
        ) : null}

        {coverage.crawl_limit_reached ? (
          <p className="text-xs text-muted-foreground">
            The crawl stopped at its configured limit, so the site may extend beyond what is
            listed here.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
