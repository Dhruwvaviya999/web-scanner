"use client";

import { useRouter } from "next/navigation";
import { ArrowLeft, ExternalLink, Lock, ShieldOff, Trash2 } from "lucide-react";
import { use, useCallback } from "react";

import { ErrorAlert } from "@/components/common/error-alert";
import { FullPageLoader } from "@/components/common/full-page-loader";
import { ButtonLink } from "@/components/common/button-link";
import { PageHeader } from "@/components/common/page-header";
import { DeleteScanDialog } from "@/components/scans/delete-scan-dialog";
import { ScanStatusBadge } from "@/components/scans/scan-status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { useAsyncData } from "@/hooks/use-async-data";
import { formatDateTime, formatDuration, primaryContentType } from "@/lib/format";
import { scanService } from "@/services/scan.service";

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 py-3 sm:grid-cols-[13rem_1fr] sm:gap-4">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm break-words">{children}</dd>
    </div>
  );
}

export default function ScanDetailPage({ params }: PageProps<"/dashboard/scans/[id]">) {
  const { id } = use(params);
  const router = useRouter();

  const fetchScan = useCallback(() => scanService.get(id), [id]);
  const { data: scan, loading, error } = useAsyncData(fetchScan);

  if (loading) return <FullPageLoader label="Loading scan…" />;

  if (error || !scan) {
    return (
      <>
        <ButtonLink variant="ghost" size="sm" href="/dashboard/scans">
          <ArrowLeft className="size-4" aria-hidden />
          Back to scans
        </ButtonLink>
        <ErrorAlert title="Scan unavailable" message={error ?? "This scan could not be loaded."} />
      </>
    );
  }

  const completed = scan.status === "COMPLETED";

  return (
    <>
      <ButtonLink variant="ghost" size="sm" className="-ml-2 w-fit" href="/dashboard/scans">
        <ArrowLeft className="size-4" aria-hidden />
        Back to scans
      </ButtonLink>

      <PageHeader
        title="Scan detail"
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

      {scan.status === "FAILED" && scan.error_message ? (
        <ErrorAlert title="This scan failed" message={scan.error_message} />
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Result</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="divide-y divide-border">
            <DetailRow label="Target">
              <span className="font-mono">{scan.target_url}</span>
            </DetailRow>

            <DetailRow label="Status">
              <ScanStatusBadge status={scan.status} />
            </DetailRow>

            <DetailRow label="HTTP status">
              <span className="font-mono">{scan.http_status_code ?? "—"}</span>
            </DetailRow>

            <DetailRow label="Response time">
              <span className="font-mono">{formatDuration(scan.response_time_ms)}</span>
            </DetailRow>

            <DetailRow label="Final URL">
              {scan.final_url ? (
                <a
                  href={scan.final_url}
                  target="_blank"
                  rel="noopener noreferrer nofollow"
                  className="inline-flex items-center gap-1.5 font-mono text-primary hover:underline"
                >
                  {scan.final_url}
                  <ExternalLink className="size-3.5 shrink-0" aria-hidden />
                </a>
              ) : (
                "—"
              )}
            </DetailRow>

            <DetailRow label="Redirects followed">
              <span className="font-mono">{scan.redirect_count ?? "—"}</span>
            </DetailRow>

            <DetailRow label="HTTPS">
              {scan.is_https === null ? (
                "—"
              ) : scan.is_https ? (
                <span className="inline-flex items-center gap-1.5 text-success">
                  <Lock className="size-4" aria-hidden />
                  Enabled
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-warning">
                  <ShieldOff className="size-4" aria-hidden />
                  Disabled
                </span>
              )}
            </DetailRow>

            <DetailRow label="Content type">
              <span className="font-mono">{primaryContentType(scan.content_type)}</span>
            </DetailRow>

            <DetailRow label="Server">
              <span className="font-mono">{scan.server_header ?? "—"}</span>
            </DetailRow>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Metadata</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="divide-y divide-border">
            <DetailRow label="Scan ID">
              <span className="font-mono text-xs">{scan.id}</span>
            </DetailRow>
            <DetailRow label="Created">{formatDateTime(scan.created_at)}</DetailRow>
            <DetailRow label="Started">{formatDateTime(scan.started_at)}</DetailRow>
            <DetailRow label="Completed">{formatDateTime(scan.completed_at)}</DetailRow>
          </dl>

          {completed ? (
            <>
              <Separator className="my-4" />
              <p className="text-xs text-muted-foreground">
                This release records only what a single HTTP request observed. No vulnerability
                analysis has been performed on this target.
              </p>
            </>
          ) : null}
        </CardContent>
      </Card>
    </>
  );
}
