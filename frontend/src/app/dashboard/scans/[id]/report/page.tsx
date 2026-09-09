"use client";

import { ArrowLeft, Download } from "lucide-react";
import { use, useCallback } from "react";

import { ButtonLink } from "@/components/common/button-link";
import { ErrorAlert } from "@/components/common/error-alert";
import { FullPageLoader } from "@/components/common/full-page-loader";
import { PageHeader } from "@/components/common/page-header";
import { FindingsSection } from "@/components/report/report-findings";
import { ReportApiSection } from "@/components/report/report-api";
import { ReportApiSecuritySection } from "@/components/report/report-api-security";
import {
  AuthorizationSummary,
  fromReport,
} from "@/components/scans/authorization-summary";
import {
  CoverageSection,
  ReportHeader,
  ReportVerdict,
  SeverityOverview,
} from "@/components/report/report-summary";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useAsyncData } from "@/hooks/use-async-data";
import { formatDateTime } from "@/lib/format";
import { scanService } from "@/services/scan.service";

export default function ScanReportPage({ params }: PageProps<"/dashboard/scans/[id]/report">) {
  const { id } = use(params);

  const fetchReport = useCallback(() => scanService.report(id), [id]);
  const { data: report, loading, error } = useAsyncData(fetchReport);

  if (loading) return <FullPageLoader label="Building report…" />;

  if (error || !report) {
    return (
      <>
        <ButtonLink
          variant="ghost"
          size="sm"
          className="-ml-2 w-fit"
          href={`/dashboard/scans/${id}`}
        >
          <ArrowLeft className="size-4" aria-hidden />
          Back to scan
        </ButtonLink>
        <ErrorAlert
          title="Report unavailable"
          message={error ?? "This report could not be generated."}
        />
      </>
    );
  }

  return (
    <>
      <ButtonLink
        variant="ghost"
        size="sm"
        className="-ml-2 w-fit"
        href={`/dashboard/scans/${id}`}
      >
        <ArrowLeft className="size-4" aria-hidden />
        Back to scan
      </ButtonLink>

      <PageHeader
        title="Security report"
        description={`Generated ${formatDateTime(report.metadata.generated_at)}`}
        actions={
          <Button
            variant="outline"
            onClick={() => {
              // The download endpoint returns the same document with an
              // attachment header, so the browser saves rather than renders it.
              window.location.href = scanService.reportDownloadUrl(id);
            }}
          >
            <Download className="size-4" aria-hidden />
            Download JSON
          </Button>
        }
      />

      <ReportVerdict
        metadata={report.metadata}
        severity={report.severity}
        coverage={report.coverage}
      />

      <ReportHeader metadata={report.metadata} />

      <SeverityOverview severity={report.severity} />

      <CoverageSection coverage={report.coverage} attackSurface={report.attack_surface} />

      <ReportApiSection api={report.coverage.api} />

      <ReportApiSecuritySection api={report.coverage.api_security} />

      <AuthorizationSummary view={fromReport(report.coverage.authorization)} />

      <FindingsSection findings={report.findings} />

      <Card className="border-dashed">
        <CardContent className="space-y-2 text-sm">
          <p className="font-medium">What this report is</p>
          <p className="text-muted-foreground">
            A summary of what this scanner observed on {report.metadata.target_url}: security
            headers and cookies on the endpoints it analysed, the attack surface it discovered,
            and the results of reflected-XSS and SQL-injection probes on discovered query
            parameters. It does not cover authenticated areas, form submissions,
            JavaScript-rendered content, or any vulnerability class the scanner does not test.
          </p>
          <p className="text-muted-foreground">
            Findings describe observations, not confirmed exploits. An empty report means these
            particular checks found nothing — it is not proof that the target is secure.
          </p>
        </CardContent>
      </Card>
    </>
  );
}
