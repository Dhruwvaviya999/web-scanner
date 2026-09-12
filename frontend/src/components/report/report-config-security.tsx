import {
  AlertTriangle,
  FileWarning,
  Lock,
  ServerCog,
  ShieldQuestion,
  Unlock,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ReportConfigSecurity } from "@/types/report";

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-sm font-medium tabular-nums">{value}</p>
    </div>
  );
}

function TransportRow({
  label,
  ok,
  okText,
  notText,
}: {
  label: string;
  ok: boolean;
  okText: string;
  notText: string;
}) {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="flex items-center gap-1.5 text-sm">
        {ok ? (
          <Lock className="size-3.5 text-muted-foreground" aria-hidden />
        ) : (
          <Unlock className="size-3.5 text-muted-foreground" aria-hidden />
        )}
        {ok ? okText : notText}
      </span>
    </div>
  );
}

/**
 * The report's configuration and deployment section.
 *
 * Two things this card must never let a reader conclude.
 *
 * The first is that a quiet result means everything was checked. This is the
 * only late stage that sends requests, so its coverage can run out of budget —
 * `coverage_complete` drives an explicit warning rather than leaving the
 * shortfall to be inferred from a number nobody reads.
 *
 * The second is that discovery equals exposure. An administrative path that
 * answered is not thereby a weakness (a login form looks exactly like this),
 * and a `Server` header is not a vulnerability. Both are shown as inventory,
 * with the wording doing the work of saying so.
 */
export function ReportConfigSecuritySection({
  config,
}: {
  config: ReportConfigSecurity;
}) {
  if (!config.analyzed) {
    return (
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="text-base">Configuration &amp; deployment</CardTitle>
        </CardHeader>
        <CardContent className="flex items-start gap-3 text-sm">
          <ShieldQuestion
            className="mt-0.5 size-5 shrink-0 text-muted-foreground"
            aria-hidden
          />
          <p className="text-muted-foreground">
            No configuration checks ran, so nothing here says anything about how this
            target is deployed. Transport, deployment files and administrative surface
            were all left unexamined.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Configuration &amp; deployment</CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="flex items-start gap-3 text-sm">
          {config.sensitive_files_exposed > 0 || config.debug_indicators > 0 ? (
            <AlertTriangle className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
          ) : (
            <ServerCog
              className="mt-0.5 size-5 shrink-0 text-muted-foreground"
              aria-hidden
            />
          )}
          <p className="text-muted-foreground">
            {config.sensitive_files_checked} deployment path
            {config.sensitive_files_checked === 1 ? " was" : "s were"} checked using{" "}
            {config.requests_sent} request
            {config.requests_sent === 1 ? "" : "s"}, all of them GET, HEAD or OPTIONS
            against a fixed list. This scanner does not brute-force directories,
            enumerate filenames or download arbitrary files.
          </p>
        </div>

        {!config.coverage_complete ? (
          <div className="flex items-start gap-3 rounded-md border border-dashed p-3">
            <FileWarning
              className="mt-0.5 size-4 shrink-0 text-muted-foreground"
              aria-hidden
            />
            <p className="text-xs text-muted-foreground">
              {config.candidates_not_tested > 0
                ? `${config.candidates_not_tested} candidate path${
                    config.candidates_not_tested === 1 ? " was" : "s were"
                  } never checked because the request budget ran out first.`
                : "The request budget ran out before the candidate checks finished."}{" "}
              Those paths established nothing either way — treat this section as partial
              coverage rather than a clean result.
            </p>
          </div>
        ) : null}

        <div className="rounded-md border p-3">
          <p className="mb-1 text-xs font-medium">Transport</p>
          <TransportRow
            label="Connection"
            ok={config.https_used}
            okText="HTTPS"
            notText="Plain HTTP"
          />
          <TransportRow
            label="HTTP → HTTPS redirect"
            ok={config.https_redirect}
            okText="In place"
            notText="Not observed"
          />
          <TransportRow
            label="Strict-Transport-Security"
            ok={config.hsts_observed}
            okText="Sent"
            notText="Not sent"
          />
          {!config.https_used ? (
            <p className="mt-2 text-xs text-muted-foreground">
              Plain HTTP is expected for a local or development target and is not
              reported as a weakness for one.
            </p>
          ) : null}
        </div>

        <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
          <Stat label="Files exposed" value={config.sensitive_files_exposed} />
          <Stat label="Debug indicators" value={config.debug_indicators} />
          <Stat label="Admin paths" value={config.admin_endpoints_discovered} />
          <Stat label="Management" value={config.management_endpoints_discovered} />
          <Stat label="Directory listings" value={config.directory_listings} />
          <Stat label="Findings" value={config.findings_count} />
        </div>

        <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-4">
          <Stat label="Methods examined" value={config.method_observations} />
          <Stat label="Source maps" value={config.source_maps} />
          <Stat label="Technology headers" value={config.technology_disclosures} />
          <Stat label="Path observations" value={config.path_normalization_observations} />
        </div>

        {config.admin_endpoints_discovered > 0 ? (
          <p className="text-xs text-muted-foreground">
            {config.admin_endpoints_discovered} administrative path
            {config.admin_endpoints_discovered === 1 ? "" : "s"} answered an anonymous
            request. That is not a weakness on its own — many applications correctly
            serve a login form at one, and this looks identical from outside. It is
            reported as a finding only where a supplied authorization policy says the
            request should have been refused.
          </p>
        ) : null}

        {config.technology_disclosures > 0 ? (
          <p className="text-xs text-muted-foreground">
            {config.technology_disclosures} response header
            {config.technology_disclosures === 1 ? "" : "s"} named the software serving
            the site. This is the default behaviour of most web servers and is recorded
            as inventory, not as a vulnerability.
          </p>
        ) : null}

        <p className="text-xs text-muted-foreground">
          Findings from these checks appear in the findings list under
          &quot;Configuration&quot;. Paths, status codes, media types and sizes are
          reported; no file contents, environment values, repository data or source code
          was read into anything that survives the scan.
        </p>
      </CardContent>
    </Card>
  );
}
