import { FileWarning, ShieldAlert, ShieldQuestion } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ReportApiSecurity } from "@/types/report";

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-sm font-medium tabular-nums">{value}</p>
    </div>
  );
}

/**
 * The report's API security section.
 *
 * Its job is to keep three states apart, because collapsing them is how a
 * scanner misleads: the review never ran, it ran and could judge nothing, or it
 * ran against a declared policy. Only the third can support "no API problems
 * were found", and even then only for the checks this phase performs.
 */
export function ReportApiSecuritySection({ api }: { api: ReportApiSecurity }) {
  if (!api.analyzed) {
    return (
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="text-base">API security</CardTitle>
        </CardHeader>
        <CardContent className="flex items-start gap-3 text-sm">
          <ShieldQuestion
            className="mt-0.5 size-5 shrink-0 text-muted-foreground"
            aria-hidden
          />
          <p className="text-muted-foreground">
            No API responses were reviewed, so nothing here says anything about API
            exposure. This review runs on responses the scan already fetched; a scan that
            found no APIs has none to read.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">API security</CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="flex items-start gap-3 text-sm">
          {api.findings_count > 0 ? (
            <ShieldAlert className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
          ) : (
            <FileWarning
              className="mt-0.5 size-5 shrink-0 text-muted-foreground"
              aria-hidden
            />
          )}
          <p className="text-muted-foreground">
            {api.responses_analyzed} API response
            {api.responses_analyzed === 1 ? " was" : "s were"} reviewed across{" "}
            {api.endpoints_analyzed} endpoint
            {api.endpoints_analyzed === 1 ? "" : "s"}. This review is read-only: it reads
            field names, headers and error signals from responses the scan already
            fetched, and sends nothing of its own.
          </p>
        </div>

        <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
          <Stat label="Endpoints" value={api.endpoints_analyzed} />
          <Stat label="Responses" value={api.responses_analyzed} />
          <Stat label="Sensitive fields" value={api.sensitive_fields_detected} />
          <Stat label="Property comparisons" value={api.property_comparisons} />
          <Stat label="Verbose errors" value={api.verbose_errors} />
          <Stat label="Findings" value={api.findings_count} />
        </div>

        {api.unknown_policy > 0 ? (
          <p className="text-xs text-muted-foreground">
            {api.unknown_policy} sensitive-looking field
            {api.unknown_policy === 1 ? "" : "s"} had no declared authorization policy to
            judge against. Those are observations, not findings — whether an API should
            return a given field depends on what the application is for, and the scanner
            has no basis for deciding. They are also not a clean result: supplying an
            authorization policy is what turns them into an answer either way.
          </p>
        ) : null}

        {api.endpoints_skipped > 0 ? (
          <p className="text-xs text-muted-foreground">
            {api.endpoints_skipped} endpoint
            {api.endpoints_skipped === 1 ? " was" : "s were"} skipped because they are
            documented but were never reached, so there is no response to review.
          </p>
        ) : null}

        <p className="text-xs text-muted-foreground">
          Findings from this review appear in the findings list under &quot;API
          security&quot;. Field names are reported; no value from any response was kept.
        </p>
      </CardContent>
    </Card>
  );
}
