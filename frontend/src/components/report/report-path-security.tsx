import { AlertTriangle, FileSearch, FolderTree, ShieldQuestion } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ReportPathSecurity } from "@/types/report";

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-sm font-medium tabular-nums">{value}</p>
    </div>
  );
}

/**
 * The report's path-traversal / LFI section.
 *
 * Two things this card must not let a reader conclude.
 *
 * The first is that a quiet result means everything was checked. This stage
 * sends requests and has a budget, and a parameter with an unusable baseline is
 * skipped — `coverage_complete` drives an explicit note rather than leaving the
 * shortfall to be inferred.
 *
 * The second is that a discovered file parameter is a weakness. Most are not;
 * the number that matters is `canary_matches`, where a controlled marker was
 * actually returned from outside its directory. Everything else is coverage.
 */
export function ReportPathSecuritySection({
  path,
}: {
  path: ReportPathSecurity;
}) {
  if (!path.analyzed) {
    return (
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="text-base">Path security</CardTitle>
        </CardHeader>
        <CardContent className="flex items-start gap-3 text-sm">
          <ShieldQuestion
            className="mt-0.5 size-5 shrink-0 text-muted-foreground"
            aria-hidden
          />
          <p className="text-muted-foreground">
            No file or path parameters were tested, so nothing here says anything about
            directory traversal. This stage probes parameters the crawl found that look
            like file or path inputs; a scan that discovered none has nothing to test.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Path security</CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="flex items-start gap-3 text-sm">
          {path.canary_matches > 0 ? (
            <AlertTriangle className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
          ) : (
            <FolderTree
              className="mt-0.5 size-5 shrink-0 text-muted-foreground"
              aria-hidden
            />
          )}
          <p className="text-muted-foreground">
            {path.file_parameters} file or path parameter
            {path.file_parameters === 1 ? " was" : "s were"} identified and{" "}
            {path.parameters_tested} tested with {path.traversal_probes} bounded
            traversal probe
            {path.traversal_probes === 1 ? "" : "s"}. Every probe aimed at a controlled
            canary; the scanner reads no real system file, and no file contents or probe
            values are stored.
          </p>
        </div>

        {!path.coverage_complete ? (
          <div className="flex items-start gap-3 rounded-md border border-dashed p-3">
            <FileSearch
              className="mt-0.5 size-4 shrink-0 text-muted-foreground"
              aria-hidden
            />
            <p className="text-xs text-muted-foreground">
              {path.parameters_skipped > 0
                ? `${path.parameters_skipped} file-like parameter${
                    path.parameters_skipped === 1 ? " was" : "s were"
                  } not tested — an unusable baseline, or the probe budget ran out first.`
                : "The probe budget ran out before every file-like parameter was tested."}{" "}
              Those parameters established nothing; treat this as partial coverage rather
              than a clean result.
            </p>
          </div>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
          <Stat label="Considered" value={path.parameters_considered} />
          <Stat label="File params" value={path.file_parameters} />
          <Stat label="Tested" value={path.parameters_tested} />
          <Stat label="Traversal probes" value={path.traversal_probes} />
          <Stat label="Canary matches" value={path.canary_matches} />
          <Stat label="Findings" value={path.findings_count} />
        </div>

        {path.canary_matches > 0 ? (
          <p className="text-xs text-muted-foreground">
            A controlled traversal canary was returned from outside the intended
            directory{path.lfi_candidates > 0 ? ", including via a file-inclusion parameter" : ""}. This
            is a demonstrated escape against a harmless marker; against a real deployment
            the same weakness could reach genuinely sensitive files. See the findings
            list under &quot;Path traversal / LFI&quot;.
          </p>
        ) : (
          <p className="text-xs text-muted-foreground">
            No traversal was confirmed. A file parameter that reflects its input, returns
            a generic error, or simply changes is not treated as a finding — only a
            reproduced canary retrieval is.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
