"use client";

import { ChevronDown, FilterX, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";

import {
  ConfidenceBadge,
  SeverityBadge,
  SeverityDot,
} from "@/components/findings/severity-badge";
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
import { cn } from "@/lib/utils";
import {
  ACTIVE_CATEGORIES,
  CATEGORY_LABELS,
  FINDING_CONFIDENCES,
  FINDING_SEVERITIES,
  parameterFromSubject,
  type FindingCategory,
  type FindingConfidence,
  type FindingSeverity,
} from "@/types/finding";
import {
  applyFilters,
  EMPTY_FILTERS,
  type FindingFilters,
  type ReportFinding,
} from "@/types/report";

const ANY = "ANY";

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {label}
      </p>
      <div className="text-sm leading-relaxed">{children}</div>
    </div>
  );
}

function FindingRow({ finding }: { finding: ReportFinding }) {
  const [open, setOpen] = useState(false);
  const panelId = `report-finding-${finding.rule_id}-${finding.subject ?? "none"}`;
  const parameter = parameterFromSubject(finding.subject);

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
            {parameter ? (
              <>
                {" · "}parameter <span className="font-mono">{parameter}</span>
              </>
            ) : null}
            {" · "}
            {finding.occurrence_count} endpoint
            {finding.occurrence_count === 1 ? "" : "s"}
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
            {ACTIVE_CATEGORIES.has(finding.category) ? (
              <Badge
                variant="outline"
                className="border-primary/40 bg-primary/10 text-primary"
                title="Confirmed by an active probe, not inferred from the response alone"
              >
                actively tested
              </Badge>
            ) : null}
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
              {finding.rule_id}
            </code>
          </div>

          <Detail label="Description">{finding.description}</Detail>

          <Detail label="Evidence">
            <p className="rounded-md border border-border bg-muted/50 px-3 py-2 font-mono text-xs leading-relaxed break-words">
              {finding.evidence}
            </p>
          </Detail>

          <Detail label="Impact">{finding.impact}</Detail>
          <Detail label="Remediation">{finding.remediation}</Detail>

          {finding.endpoints.length > 0 ? (
            <Detail label={`Affected endpoints (${finding.endpoints.length})`}>
              <ul className="space-y-1">
                {finding.endpoints.map((endpoint) => (
                  <li
                    key={endpoint.url}
                    className="font-mono text-xs break-all text-muted-foreground"
                  >
                    {endpoint.method ? `${endpoint.method} ` : ""}
                    {endpoint.url}
                  </li>
                ))}
              </ul>
            </Detail>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export function FindingsSection({ findings }: { findings: ReportFinding[] }) {
  const [filters, setFilters] = useState<FindingFilters>(EMPTY_FILTERS);

  const categories = useMemo(
    () => [...new Set(findings.map((f) => f.category))],
    [findings],
  );
  const visible = useMemo(() => applyFilters(findings, filters), [findings, filters]);
  const filtered = filters.severity || filters.category || filters.confidence;

  if (findings.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Findings</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-start gap-3 rounded-md border border-dashed border-border px-4 py-6">
            <ShieldCheck className="mt-0.5 size-5 shrink-0 text-success" aria-hidden />
            <div className="space-y-1 text-sm">
              <p className="font-medium">No findings were recorded</p>
              <p className="text-muted-foreground">
                None of the checks performed in this scan reported an issue. See the coverage
                section above for what was actually analysed.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Findings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <Select
            value={filters.severity ?? ANY}
            onValueChange={(value) =>
              setFilters((f) => ({
                ...f,
                severity: value === ANY || value === null ? null : (value as FindingSeverity),
              }))
            }
          >
            <SelectTrigger className="w-40" aria-label="Filter by severity">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ANY}>Any severity</SelectItem>
              {FINDING_SEVERITIES.map((level) => (
                <SelectItem key={level} value={level}>
                  {level.charAt(0) + level.slice(1).toLowerCase()}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select
            value={filters.category ?? ANY}
            onValueChange={(value) =>
              setFilters((f) => ({
                ...f,
                category: value === ANY || value === null ? null : (value as FindingCategory),
              }))
            }
          >
            <SelectTrigger className="w-48" aria-label="Filter by category">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ANY}>Any category</SelectItem>
              {categories.map((category) => (
                <SelectItem key={category} value={category}>
                  {CATEGORY_LABELS[category]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select
            value={filters.confidence ?? ANY}
            onValueChange={(value) =>
              setFilters((f) => ({
                ...f,
                confidence:
                  value === ANY || value === null ? null : (value as FindingConfidence),
              }))
            }
          >
            <SelectTrigger className="w-44" aria-label="Filter by confidence">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ANY}>Any confidence</SelectItem>
              {FINDING_CONFIDENCES.map((level) => (
                <SelectItem key={level} value={level}>
                  {level.charAt(0) + level.slice(1).toLowerCase()} confidence
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {filtered ? (
            <Button variant="ghost" size="sm" onClick={() => setFilters(EMPTY_FILTERS)}>
              <FilterX className="size-4" aria-hidden />
              Clear
            </Button>
          ) : null}
        </div>

        <p className="text-sm text-muted-foreground">
          Showing {visible.length} of {findings.length} finding
          {findings.length === 1 ? "" : "s"}, most severe first.
        </p>

        {visible.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">
            No findings match these filters.
          </p>
        ) : (
          <div className="rounded-lg border border-border px-3">
            {visible.map((finding) => (
              <FindingRow
                key={`${finding.rule_id}:${finding.subject ?? ""}`}
                finding={finding}
              />
            ))}
          </div>
        )}

        <p className="text-xs text-muted-foreground">
          Findings are observations from the checks this scanner performs. They are not
          confirmed exploits, and their absence does not prove the target is secure.
        </p>
      </CardContent>
    </Card>
  );
}
