import { CircleHelp, KeyRound, ShieldAlert, ShieldQuestion } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ReportSessionSecurity } from "@/types/report";

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-sm font-medium tabular-nums">{value}</p>
    </div>
  );
}

/**
 * The report's session security section.
 *
 * The whole point of this card is the gap between what was observed and what
 * can be concluded. Two numbers carry that and must never be collapsed:
 *
 * - `csrf_potential` is forms worth reviewing that produced no finding. The
 *   absence of a visible CSRF token is not evidence that CSRF is exploitable,
 *   so showing only the findings count would let unresolved questions read as
 *   an all-clear.
 * - `timeout_known: false` is an unanswered question, not a weakness. Server-
 *   side session expiry cannot be observed from outside.
 */
export function ReportSessionSecuritySection({
  session,
}: {
  session: ReportSessionSecurity;
}) {
  if (!session.analyzed) {
    return (
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="text-base">Session security</CardTitle>
        </CardHeader>
        <CardContent className="flex items-start gap-3 text-sm">
          <ShieldQuestion
            className="mt-0.5 size-5 shrink-0 text-muted-foreground"
            aria-hidden
          />
          <p className="text-muted-foreground">
            No session handling was reviewed, so nothing here says anything about session
            security. This review reads cookies, URLs and forms the scan already
            captured; a scan that reached none has nothing to read.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Session security</CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="flex items-start gap-3 text-sm">
          {session.findings_count > 0 ? (
            <ShieldAlert className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />
          ) : (
            <KeyRound
              className="mt-0.5 size-5 shrink-0 text-muted-foreground"
              aria-hidden
            />
          )}
          <p className="text-muted-foreground">
            {session.session_cookies_identified} session cookie
            {session.session_cookies_identified === 1 ? " was" : "s were"} identified and{" "}
            {session.csrf_forms_analyzed} form
            {session.csrf_forms_analyzed === 1 ? " was" : "s were"} examined. This review
            is passive: it sent {session.requests_sent} requests of its own, submitted no
            form, forged no token and called no logout endpoint.
          </p>
        </div>

        <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
          <Stat label="Session cookies" value={session.session_cookies_identified} />
          <Stat label="IDs in URLs" value={session.session_identifiers_in_urls} />
          <Stat label="Token exposures" value={session.token_exposures} />
          <Stat label="Forms examined" value={session.csrf_forms_analyzed} />
          <Stat label="Tokens observed" value={session.jwt_tokens_observed} />
          <Stat label="Findings" value={session.findings_count} />
        </div>

        {session.csrf_potential > 0 ? (
          <div className="flex items-start gap-3 rounded-md border border-dashed p-3">
            <CircleHelp
              className="mt-0.5 size-4 shrink-0 text-muted-foreground"
              aria-hidden
            />
            <p className="text-xs text-muted-foreground">
              {session.csrf_potential} state-changing form
              {session.csrf_potential === 1 ? "" : "s"} had no anti-CSRF token field that
              this scan could see, and{" "}
              {session.csrf_potential === 1 ? "was" : "were"} not reported as a finding.
              That is deliberate. A missing token is not a missing defence: origin or
              Referer validation, a required custom header, framework middleware, or the
              browser&apos;s own SameSite behaviour would each stop an attack, and none of
              them is visible without submitting a forged request — which this scanner
              does not do. Verify these by hand.
            </p>
          </div>
        ) : null}

        {session.csrf_strong > 0 ? (
          <p className="text-xs text-muted-foreground">
            {session.csrf_strong} form{session.csrf_strong === 1 ? "" : "s"} went further:
            the session cookie declares <code>SameSite=None</code>, so the browser will
            attach it to a cross-site request and its own defence does not apply. Those
            produced findings — still unconfirmed, because no request was forged to test
            them.
          </p>
        ) : null}

        {!session.timeout_known ? (
          <p className="text-xs text-muted-foreground">
            Nothing observed established when a session expires. This is a gap in what a
            passive scan can see, not evidence that sessions never expire — server-side
            expiry is invisible from outside. Confirm by hand that sessions time out and
            that logout destroys server-side state.
          </p>
        ) : null}

        {session.logout_endpoints_discovered > 0 ? (
          <p className="text-xs text-muted-foreground">
            {session.logout_endpoints_discovered} logout endpoint
            {session.logout_endpoints_discovered === 1 ? " was" : "s were"} found and
            recorded for review. None was called: invoking logout mid-scan would end the
            session every other stage depends on, and a 200 response would prove nothing
            about whether the server actually invalidated it.
          </p>
        ) : null}

        <p className="text-xs text-muted-foreground">
          Findings from this review appear in the findings list under &quot;Session
          security&quot;. Cookie names, parameter names and token claim names are
          reported; no cookie value, session identifier, token or form field value was
          ever stored.
        </p>
      </CardContent>
    </Card>
  );
}
