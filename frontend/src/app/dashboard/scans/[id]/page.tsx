"use client";

import { useRouter } from "next/navigation";
import { ArrowLeft, CircleSlash, FileText, Trash2 } from "lucide-react";
import { use, useCallback } from "react";

import { ButtonLink } from "@/components/common/button-link";
import { ErrorAlert } from "@/components/common/error-alert";
import { FullPageLoader } from "@/components/common/full-page-loader";
import { PageHeader } from "@/components/common/page-header";
import { AttackSurfaceSection } from "@/components/attack-surface/attack-surface-section";
import { FindingsSection } from "@/components/findings/findings-section";
import { CancelScanDialog } from "@/components/scans/cancel-scan-dialog";
import { DeleteScanDialog } from "@/components/scans/delete-scan-dialog";
import { ScanProgress } from "@/components/scans/scan-progress";
import { ScanStatusBadge } from "@/components/scans/scan-status-badge";
import {
  HttpInformation,
  PageInformation,
  TargetInformation,
} from "@/components/scans/scan-result-sections";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAsyncData } from "@/hooks/use-async-data";
import { SCAN_POLL_INTERVAL_MS, usePolling } from "@/hooks/use-polling";
import { formatDateTime } from "@/lib/format";
import { scanService } from "@/services/scan.service";
import { isScanActive } from "@/types/scan";

export default function ScanDetailPage({ params }: PageProps<"/dashboard/scans/[id]">) {
  const { id } = use(params);
  const router = useRouter();

  const fetchScan = useCallback(() => scanService.get(id), [id]);
  const { data: scan, loading, error, refresh, setData } = useAsyncData(fetchScan);

  const fetchFindings = useCallback(() => scanService.findings(id), [id]);
  const {
    data: findings,
    loading: findingsLoading,
    error: findingsError,
    refresh: refreshFindings,
  } = useAsyncData(fetchFindings);

  const fetchEndpoints = useCallback(() => scanService.endpoints(id), [id]);
  const {
    data: endpoints,
    loading: endpointsLoading,
    error: endpointsError,
    refresh: refreshEndpoints,
  } = useAsyncData(fetchEndpoints);

  const fetchForms = useCallback(() => scanService.forms(id), [id]);
  const {
    data: forms,
    loading: formsLoading,
    error: formsError,
    refresh: refreshForms,
  } = useAsyncData(fetchForms);

  // A scan that has not reached a terminal state is re-read on a plain
  // interval. Results are re-read with it, so the page fills in as the scan
  // progresses rather than only once it ends.
  const active = scan ? isScanActive(scan) : false;
  const poll = useCallback(() => {
    refresh();
    refreshFindings();
    refreshEndpoints();
    refreshForms();
  }, [refresh, refreshFindings, refreshEndpoints, refreshForms]);
  usePolling(poll, active ? SCAN_POLL_INTERVAL_MS : null);

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
  const cancelled = scan.status === "CANCELLED";
  // A failed scan reached no response at all; a cancelled or still-running one
  // may have partial results worth showing.
  const hasResult = !failed && (scan.http_status_code !== null || !active);

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
          <>
            {active ? (
              <CancelScanDialog
                scan={scan}
                onRequested={setData}
                trigger={
                  <Button variant="outline" disabled={scan.cancel_requested}>
                    <CircleSlash className="size-4" aria-hidden />
                    {scan.cancel_requested ? "Stopping…" : "Stop scan"}
                  </Button>
                }
              />
            ) : null}
            <ButtonLink variant="outline" href={`/dashboard/scans/${id}/report`}>
              <FileText className="size-4" aria-hidden />
              View report
            </ButtonLink>
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
          </>
        }
      />

      {/* --- Scan Status --- */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Scan Status</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
            <ScanStatusBadge status={scan.status} cancelRequested={scan.cancel_requested} />
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

          <ScanProgress scan={scan} />

          {failed && scan.error_message ? (
            <ErrorAlert
              title={
                scan.failure_stage
                  ? `This scan failed while ${scan.failure_stage.toLowerCase()}`
                  : "This scan failed"
              }
              message={scan.error_message}
            />
          ) : null}

          {cancelled ? (
            <Alert>
              <CircleSlash className="size-4" aria-hidden />
              <AlertTitle>This scan was stopped before it finished</AlertTitle>
              <AlertDescription>
                Everything found before it stopped is shown below, but the target was not fully
                assessed. An empty result here is not a clean bill of health — run the scan again
                to cover the rest.
              </AlertDescription>
            </Alert>
          ) : null}
        </CardContent>
      </Card>

      {hasResult ? (
        <>
          <TargetInformation scan={scan} />
          <HttpInformation scan={scan} />
          <PageInformation scan={scan} />
        </>
      ) : null}

      <FindingsSection
        data={findings}
        loading={findingsLoading}
        error={findingsError}
        scanFailed={failed}
      />

      <AttackSurfaceSection
        endpoints={endpoints}
        forms={forms}
        loading={endpointsLoading || formsLoading}
        error={endpointsError ?? formsError}
        scanFailed={failed}
      />

      <Card className="border-dashed">
        <CardContent className="space-y-2 text-sm">
          <p className="font-medium">Scope of this result</p>
          <p className="text-muted-foreground">
            This scan fetched the target, recorded the response,
            checked the response&apos;s security headers and cookies, then crawled the origin to
            map its attack surface. No vulnerability testing was performed — no payloads were
            sent, no forms were submitted, and no TLS, injection or CORS analysis was run.
            Findings are configuration observations, not confirmed vulnerabilities, and their
            absence does not mean the site is secure.
          </p>
          <p className="pt-1 font-mono text-xs text-muted-foreground">Scan ID: {scan.id}</p>
        </CardContent>
      </Card>
    </>
  );
}
