"use client";

import { ScanLine } from "lucide-react";
import { useCallback, useState } from "react";

import { EmptyState } from "@/components/common/empty-state";
import { ErrorAlert } from "@/components/common/error-alert";
import { PageHeader } from "@/components/common/page-header";
import { CreateScanForm } from "@/components/scans/create-scan-form";
import { ScanTable } from "@/components/scans/scan-table";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAsyncData } from "@/hooks/use-async-data";
import { SCAN_POLL_INTERVAL_MS, usePolling } from "@/hooks/use-polling";
import { scanService } from "@/services/scan.service";
import { isScanActive, SCAN_STATUSES, type ScanStatus } from "@/types/scan";

const PAGE_SIZE = 20;
const ALL_STATUSES = "ALL";

type StatusFilter = ScanStatus | typeof ALL_STATUSES;

export default function ScansPage() {
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState<StatusFilter>(ALL_STATUSES);

  const fetchScans = useCallback(
    () =>
      scanService.list({
        limit: PAGE_SIZE,
        offset,
        status: status === ALL_STATUSES ? undefined : status,
      }),
    [offset, status],
  );

  const { data, loading, error, reload, refresh } = useAsyncData(fetchScans);
  const scans = data?.items ?? [];
  const total = data?.total ?? 0;

  // Poll only while something on this page can still change. Once every scan
  // shown is terminal, the interval stops entirely.
  const hasActiveScan = scans.some(isScanActive);
  usePolling(refresh, hasActiveScan ? SCAN_POLL_INTERVAL_MS : null);

  const handleFilterChange = (value: string | null) => {
    setStatus((value as StatusFilter | null) ?? ALL_STATUSES);
    setOffset(0);
  };

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const isEmpty = !loading && scans.length === 0;

  return (
    <>
      <PageHeader
        title="Scans"
        description={`${total} scan${total === 1 ? "" : "s"} recorded against your account.`}
      />

      <Card>
        <CardHeader>
          <CardTitle>New scan</CardTitle>
        </CardHeader>
        <CardContent>
          <CreateScanForm
            onCreated={() => {
              setOffset(0);
              reload();
            }}
          />
        </CardContent>
      </Card>

      {error ? <ErrorAlert message={error} /> : null}

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-3">
          <CardTitle>Scan history</CardTitle>
          <Select value={status} onValueChange={handleFilterChange}>
            <SelectTrigger className="w-40" aria-label="Filter by status">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_STATUSES}>All statuses</SelectItem>
              {SCAN_STATUSES.map((value) => (
                <SelectItem key={value} value={value}>
                  {value.charAt(0) + value.slice(1).toLowerCase()}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent className="space-y-4">
          {isEmpty ? (
            <EmptyState
              icon={ScanLine}
              title={status === ALL_STATUSES ? "No scans yet" : "No scans with this status"}
              description={
                status === ALL_STATUSES
                  ? "Start a scan above and it will appear here with its full result."
                  : "Try a different status filter to see your other scans."
              }
            />
          ) : (
            <ScanTable scans={scans} loading={loading} onChanged={reload} />
          )}

          {total > PAGE_SIZE ? (
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                Page {page} of {pageCount}
              </p>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset === 0 || loading}
                  onClick={() => setOffset((value) => Math.max(0, value - PAGE_SIZE))}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset + PAGE_SIZE >= total || loading}
                  onClick={() => setOffset((value) => value + PAGE_SIZE)}
                >
                  Next
                </Button>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </>
  );
}
