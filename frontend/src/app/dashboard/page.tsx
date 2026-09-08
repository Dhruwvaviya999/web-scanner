"use client";

import { CheckCircle2, ListChecks, Loader2, ScanLine, XCircle } from "lucide-react";
import { useCallback } from "react";

import { StatCard } from "@/components/dashboard/stat-card";
import { EmptyState } from "@/components/common/empty-state";
import { ErrorAlert } from "@/components/common/error-alert";
import { PageHeader } from "@/components/common/page-header";
import { CreateScanForm } from "@/components/scans/create-scan-form";
import { ScanTable } from "@/components/scans/scan-table";
import { ButtonLink } from "@/components/common/button-link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAsyncData } from "@/hooks/use-async-data";
import { useAuth } from "@/hooks/use-auth";
import { scanService } from "@/services/scan.service";
import type { Scan, ScanStats } from "@/types/scan";

const RECENT_SCAN_LIMIT = 5;

interface Overview {
  stats: ScanStats;
  recent: Scan[];
}

export default function DashboardPage() {
  const { user } = useAuth();

  const fetchOverview = useCallback(async (): Promise<Overview> => {
    const [stats, list] = await Promise.all([
      scanService.stats(),
      scanService.list({ limit: RECENT_SCAN_LIMIT }),
    ]);
    return { stats, recent: list.items };
  }, []);

  const { data, loading, error, reload } = useAsyncData(fetchOverview);
  const stats = data?.stats ?? null;
  const recent = data?.recent ?? [];

  return (
    <>
      <PageHeader
        title={user ? `Welcome back, ${user.name.split(" ")[0]}` : "Overview"}
        description="Run a scan and review what your targets returned."
        actions={
          <ButtonLink variant="outline" href="/dashboard/scans">
            View all scans
          </ButtonLink>
        }
      />

      {error ? <ErrorAlert message={error} /> : null}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total scans" value={stats?.total ?? 0} icon={ListChecks} loading={loading} />
        <StatCard
          label="Completed"
          value={stats?.completed ?? 0}
          icon={CheckCircle2}
          loading={loading}
          accentClassName="bg-success/15 text-success"
        />
        <StatCard
          label="Failed"
          value={stats?.failed ?? 0}
          icon={XCircle}
          loading={loading}
          accentClassName="bg-destructive/15 text-destructive"
        />
        <StatCard
          label="In progress"
          value={(stats?.pending ?? 0) + (stats?.running ?? 0)}
          icon={Loader2}
          loading={loading}
          accentClassName="bg-info/15 text-info"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>New scan</CardTitle>
        </CardHeader>
        <CardContent>
          <CreateScanForm onCreated={reload} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent scans</CardTitle>
        </CardHeader>
        <CardContent>
          {!loading && recent.length === 0 ? (
            <EmptyState
              icon={ScanLine}
              title="No scans yet"
              description="Enter a URL above to run your first scan. Results appear here immediately."
            />
          ) : (
            <ScanTable scans={recent} loading={loading} onChanged={reload} compact />
          )}
        </CardContent>
      </Card>
    </>
  );
}
