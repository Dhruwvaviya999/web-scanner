"use client";

import Link from "next/link";
import { ArrowUpRight } from "lucide-react";

import { CancelScanDialog } from "@/components/scans/cancel-scan-dialog";
import { DeleteScanDialog } from "@/components/scans/delete-scan-dialog";
import { HttpStatusBadge } from "@/components/scans/http-status-badge";
import { ScanStatusBadge } from "@/components/scans/scan-status-badge";
import { ButtonLink } from "@/components/common/button-link";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatDateTime, formatDuration, truncateUrl } from "@/lib/format";
import { isScanActive, type Scan } from "@/types/scan";

interface ScanTableProps {
  scans: Scan[];
  loading?: boolean;
  onChanged: () => void;
  /** Hide the scan id / delete columns on compact dashboards. */
  compact?: boolean;
}

export function ScanTable({ scans, loading = false, onChanged, compact = false }: ScanTableProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="min-w-64">Target</TableHead>
            <TableHead className="w-32">Status</TableHead>
            <TableHead className="w-36">HTTP</TableHead>
            <TableHead className="w-28">Time</TableHead>
            <TableHead className="w-44">Created</TableHead>
            {!compact && <TableHead className="w-36">Scan ID</TableHead>}
            <TableHead className="w-24 text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading
            ? Array.from({ length: 4 }).map((_, index) => (
                <TableRow key={`skeleton-${index}`}>
                  <TableCell colSpan={compact ? 6 : 7}>
                    <Skeleton className="h-6 w-full" />
                  </TableCell>
                </TableRow>
              ))
            : scans.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell className="text-sm">
                    <Link
                      href={`/dashboard/scans/${scan.id}`}
                      className="font-mono hover:text-primary hover:underline"
                      title={scan.target_url}
                    >
                      {truncateUrl(scan.target_url, 52)}
                    </Link>
                    {scan.page_title ? (
                      <span
                        className="mt-0.5 block truncate text-xs text-muted-foreground"
                        title={scan.page_title}
                      >
                        {scan.page_title}
                      </span>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <ScanStatusBadge
                      status={scan.status}
                      cancelRequested={scan.cancel_requested}
                    />
                  </TableCell>
                  <TableCell>
                    <HttpStatusBadge code={scan.http_status_code} />
                  </TableCell>
                  <TableCell className="font-mono text-sm text-muted-foreground">
                    {formatDuration(scan.response_time_ms)}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatDateTime(scan.created_at)}
                  </TableCell>
                  {!compact && (
                    <TableCell
                      className="font-mono text-xs text-muted-foreground"
                      title={scan.id}
                    >
                      {scan.id.slice(0, 8)}…
                    </TableCell>
                  )}
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <ButtonLink
                        variant="ghost"
                        size="icon"
                        aria-label="Open scan details"
                        href={`/dashboard/scans/${scan.id}`}
                      >
                        <ArrowUpRight className="size-4 text-muted-foreground" aria-hidden />
                      </ButtonLink>
                      {isScanActive(scan) && !scan.cancel_requested ? (
                        <CancelScanDialog scan={scan} onRequested={onChanged} />
                      ) : null}
                      {!compact && <DeleteScanDialog scan={scan} onDeleted={onChanged} />}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
        </TableBody>
      </Table>
    </div>
  );
}
