import {
  Clock,
  CornerDownRight,
  FileCode2,
  Globe,
  Heading,
  Link2,
  Lock,
  Server,
  ShieldOff,
  Type,
  Weight,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";

import { HttpStatusBadge } from "@/components/scans/http-status-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  formatBytes,
  formatDuration,
  primaryContentType,
} from "@/lib/format";
import type { Scan } from "@/types/scan";

interface FactProps {
  icon: LucideIcon;
  label: string;
  children: ReactNode;
  /** Render the value in monospace — for URLs, codes and header values. */
  mono?: boolean;
}

function Fact({ icon: Icon, label, children, mono = false }: FactProps) {
  return (
    <div className="flex items-start gap-3 py-3">
      <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
      <div className="grid min-w-0 flex-1 gap-1 sm:grid-cols-[11rem_1fr] sm:gap-4">
        <dt className="text-sm text-muted-foreground">{label}</dt>
        <dd className={`min-w-0 text-sm break-words ${mono ? "font-mono" : ""}`}>{children}</dd>
      </div>
    </div>
  );
}

function Empty() {
  return <span className="text-muted-foreground">—</span>;
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="divide-y divide-border">{children}</dl>
      </CardContent>
    </Card>
  );
}

export function TargetInformation({ scan }: { scan: Scan }) {
  const redirected = scan.final_url !== null && scan.final_url !== scan.target_url;

  return (
    <Section title="Target Information">
      <Fact icon={Globe} label="Target URL" mono>
        {scan.target_url}
      </Fact>

      <Fact icon={Link2} label="Final URL" mono>
        {scan.final_url ? (
          <span className="space-y-1">
            <a
              href={scan.final_url}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="text-primary hover:underline"
            >
              {scan.final_url}
            </a>
            {redirected ? (
              <span className="block font-sans text-xs text-muted-foreground">
                Different from the target — the request was redirected.
              </span>
            ) : null}
          </span>
        ) : (
          <Empty />
        )}
      </Fact>

      <Fact icon={scan.is_https ? Lock : ShieldOff} label="HTTPS">
        {scan.is_https === null ? (
          <Empty />
        ) : scan.is_https ? (
          <span className="font-medium text-success">Enabled</span>
        ) : (
          <span className="font-medium text-warning">Disabled</span>
        )}
      </Fact>
    </Section>
  );
}

export function HttpInformation({ scan }: { scan: Scan }) {
  return (
    <Section title="HTTP Information">
      <Fact icon={FileCode2} label="Status Code">
        <HttpStatusBadge code={scan.http_status_code} />
      </Fact>

      <Fact icon={Type} label="Content Type" mono>
        {scan.content_type ? primaryContentType(scan.content_type) : <Empty />}
      </Fact>

      <Fact icon={Server} label="Server" mono>
        {scan.server_header ?? (
          <span className="font-sans text-muted-foreground">Not disclosed</span>
        )}
      </Fact>

      <Fact icon={Clock} label="Response Time" mono>
        {scan.response_time_ms === null ? <Empty /> : formatDuration(scan.response_time_ms)}
      </Fact>

      <Fact icon={CornerDownRight} label="Redirect Count" mono>
        {scan.redirect_count === null ? <Empty /> : scan.redirect_count}
      </Fact>
    </Section>
  );
}

export function PageInformation({ scan }: { scan: Scan }) {
  const isHtml = primaryContentType(scan.content_type).includes("html");

  return (
    <Section title="Page Information">
      <Fact icon={Heading} label="Page Title">
        {scan.page_title ? (
          scan.page_title
        ) : (
          <span className="text-muted-foreground">
            {isHtml ? "The page did not declare a title." : "Not an HTML page."}
          </span>
        )}
      </Fact>

      <Fact icon={Weight} label="Content Length" mono>
        {scan.content_length === null ? <Empty /> : formatBytes(scan.content_length)}
      </Fact>
    </Section>
  );
}
