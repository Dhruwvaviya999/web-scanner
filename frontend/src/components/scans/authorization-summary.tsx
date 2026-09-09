import { ShieldCheck, ShieldQuestion } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ReportAuthorization } from "@/types/report";
import type { ScanAuthorizationInfo } from "@/types/scan";

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-sm font-medium tabular-nums">{value}</p>
    </div>
  );
}

/** Normalises the scan-row shape and the report shape onto one view model. */
export interface AuthorizationView {
  enabled: boolean;
  contexts: number;
  contextLabels: string[];
  endpointsEligible: number;
  endpointsTested: number;
  comparisons: number;
  unknown: number;
  skipped: number;
  failed: number;
  hasPolicy: boolean;
}

export function fromScan(info: ScanAuthorizationInfo): AuthorizationView {
  const comparisons = info.comparisons ?? 0;
  const unknown = info.unknown ?? 0;
  return {
    enabled: info.enabled,
    contexts: info.contexts ?? 0,
    contextLabels: info.context_labels,
    endpointsEligible: info.endpoints_eligible ?? 0,
    endpointsTested: info.endpoints_tested ?? 0,
    comparisons,
    unknown,
    skipped: info.skipped ?? 0,
    failed: info.failed ?? 0,
    hasPolicy: info.enabled && comparisons - unknown > 0,
  };
}

export function fromReport(info: ReportAuthorization): AuthorizationView {
  return {
    enabled: info.enabled,
    contexts: info.contexts,
    contextLabels: info.context_labels,
    endpointsEligible: info.endpoints_eligible,
    endpointsTested: info.endpoints_tested,
    comparisons: info.comparisons,
    unknown: info.unknown,
    skipped: info.skipped,
    failed: info.failed,
    hasPolicy: info.has_policy,
  };
}

/**
 * Authorization coverage.
 *
 * The wording works hard to keep three states apart, because conflating them is
 * how a scanner misleads: testing was never asked for, testing ran but nothing
 * was asserted, and testing ran against a declared policy. Only the third can
 * support "no access-control problems were found".
 */
export function AuthorizationSummary({ view }: { view: AuthorizationView }) {
  if (!view.enabled) {
    return (
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="text-base">Access control</CardTitle>
        </CardHeader>
        <CardContent className="flex items-start gap-3 text-sm">
          <ShieldQuestion className="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-hidden />
          <p className="text-muted-foreground">
            Authorization testing was not configured for this scan, so nothing here says whether
            one user can reach another&apos;s data. Supply two or more identities to test it.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Access control</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-start gap-3 text-sm">
          {view.hasPolicy ? (
            <ShieldCheck className="mt-0.5 size-5 shrink-0 text-success" aria-hidden />
          ) : (
            <ShieldQuestion className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
          )}
          <p className="text-muted-foreground">
            {view.hasPolicy
              ? "Access was compared across the supplied identities and measured against the expectations you declared. Results cover those identities and those resources only — no other user, role or permission level was tested."
              : "Access was compared across the supplied identities, but no expected access was declared, so every comparison is reported as unknown. Nothing here can be read as a clean result."}
          </p>
        </div>

        {view.contextLabels.length > 0 ? (
          <div>
            <p className="text-xs text-muted-foreground">Identities</p>
            <p className="text-sm font-medium">{view.contextLabels.join(" · ")}</p>
          </div>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
          <Stat label="Identities" value={view.contexts} />
          <Stat label="Endpoints eligible" value={view.endpointsEligible} />
          <Stat label="Endpoints tested" value={view.endpointsTested} />
          <Stat label="Comparisons" value={view.comparisons} />
          <Stat label="Unknown" value={view.unknown} />
          <Stat label="Skipped" value={view.skipped + view.failed} />
        </div>

        {view.unknown > 0 ? (
          <p className="text-xs text-muted-foreground">
            {view.unknown} comparison{view.unknown === 1 ? "" : "s"} had no declared expectation
            to judge against. Those are not findings, and they are not passes either — the
            scanner cannot infer which of them should have been refused.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
