"use client";

import { useRouter } from "next/navigation";
import { ArrowLeft, Trash2 } from "lucide-react";
import { use, useCallback } from "react";

import { ButtonLink } from "@/components/common/button-link";
import { ErrorAlert } from "@/components/common/error-alert";
import { FullPageLoader } from "@/components/common/full-page-loader";
import { PageHeader } from "@/components/common/page-header";
import { FindingsSection } from "@/components/findings/findings-section";
import { DeleteScanDialog } from "@/components/scans/delete-scan-dialog";
import { ScanStatusBadge } from "@/components/scans/scan-status-badge";
import {
  HttpInformation,
  PageInformation,
  TargetInformation,
} from "@/components/scans/scan-result-sections";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAsyncData } from "@/hooks/use-async-data";
import { formatDateTime } from "@/lib/format";
import { scanService } from "@/services/scan.service";

export default function ScanDetailPage({ params }: PageProps<"/dashboard/scans/[id]">) {
  const { id } = use(params);
  const router = useRouter();

  const fetchScan = useCallback(() => scanService.get(id), [id]);
  const { data: scan, loading, error } = useAsyncData(fetchScan);

  const fetchFindings = useCallback(() => scanService.findings(id), [id]);
  const {
    data: findings,
    loading: findingsLoading,
    error: findingsError,
  } = useAsyncData(fetchFindings);

  if (loading) return <FullPageLoader label="Loading scan…" />;

  if (error || !scan) {
    return (
      <>
        <ButtonLink variant="ghost" size="sm" className="-ml-2 w-fit" href="/dashboard/scans">
          <ArrowLeft className="size-4" aria-hidden />
          Back to scans
        </ButtonLink>
        <ErrorAlert title="Scan unavailable" message={error ?? "This scan could not be loaded."} />
      </>
    );
  }

  const failed = scan.status === "FAILED";

  return (
    <>
      <ButtonLink variant="ghost" size="sm" className="-ml-2 w-fit" href="/dashboard/scans">
        <ArrowLeft className="size-4" aria-hidden />
        Back to scans
      </ButtonLink>

      <PageHeader
        title="Scan result"
        description={`Recorded ${formatDateTime(scan.created_at)}`}
        actions={
          <DeleteScanDialog
            scan={scan}
            onDeleted={() => router.replace("/dashboard/scans")}
            trigger={
              <Button variant="outline">
                <Trash2 className="size-4" aria-hidden />
                Delete
              </Button>
            }
          />
        }
      />

      {/* --- Scan Status --- */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Scan Status</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
            <ScanStatusBadge status={scan.status} />
            <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-muted-foreground">
              <span>
                Started <span className="text-foreground">{formatDateTime(scan.started_at)}</span>
              </span>
              <span>
                Finished{" "}
                <span className="text-foreground">{formatDateTime(scan.completed_at)}</span>
              </span>
            </div>
          </div>

          {failed && scan.error_message ? (
            <ErrorAlert title="This scan failed" message={scan.error_message} />
          ) : null}
        </CardContent>
      </Card>

      {/* A failed scan reached no response, so the result sections would be
          nothing but em dashes. Showing the reason alone is more honest. */}
      {failed ? null : (
        <>
          <TargetInformation scan={scan} />
          <HttpInformation scan={scan} />
          <PageInformation scan={scan} />
        </>
      )}

      <FindingsSection
        data={findings}
        loading={findingsLoading}
        error={findingsError}
        scanFailed={failed}
      />

      <Card className="border-dashed">
        <CardContent className="space-y-2 text-sm">
          <p className="font-medium">Scope of this result</p>
          <p className="text-muted-foreground">
            This scan performed a single HTTP GET against the target, recorded what came back,
            and checked the response&apos;s security headers and cookies. No vulnerability testing
            was performed — no payloads were sent, and no crawling, TLS, injection or CORS
            analysis was run. Findings are configuration observations, not confirmed
            vulnerabilities, and their absence does not mean the site is secure.
          </p>
          <p className="pt-1 font-mono text-xs text-muted-foreground">Scan ID: {scan.id}</p>
        </CardContent>
      </Card>
    </>
  );
}
