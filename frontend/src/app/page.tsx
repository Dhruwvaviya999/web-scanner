import { Activity, ArrowRight, LockKeyhole, ScanLine, ShieldCheck } from "lucide-react";

import { Brand } from "@/components/common/brand";
import { ButtonLink } from "@/components/common/button-link";
import { Card, CardContent } from "@/components/ui/card";

const FEATURES = [
  {
    icon: ScanLine,
    title: "Targeted HTTP probes",
    description:
      "Submit a URL and capture the response status, timing, redirect chain and server banner in one request.",
  },
  {
    icon: Activity,
    title: "Scan history",
    description:
      "Every scan is stored against your account with its status, target and result, so you can compare runs over time.",
  },
  {
    icon: LockKeyhole,
    title: "Private by default",
    description:
      "Sessions use httpOnly cookies and every scan query is scoped to its owner. You only ever see your own data.",
  },
];

export default function HomePage() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex h-16 items-center justify-between border-b border-border px-4 sm:px-8">
        <Brand />
        <div className="flex items-center gap-2">
          <ButtonLink variant="ghost" href="/login">
            Sign in
          </ButtonLink>
          <ButtonLink href="/register">Get started</ButtonLink>
        </div>
      </header>

      <main className="flex-1">
        <section className="bg-grid border-b border-border">
          <div className="mx-auto flex max-w-4xl flex-col items-center gap-6 px-4 py-24 text-center sm:px-8">
            <span className="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
              <ShieldCheck className="size-3.5" aria-hidden />
              Phase 1 · Reconnaissance
            </span>
            <h1 className="text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
              Know what your web endpoints are actually returning
            </h1>
            <p className="max-w-2xl text-lg text-pretty text-muted-foreground">
              Web Scanner records the HTTP reality of the sites you own — status codes, redirects,
              TLS usage and response times — and keeps every run in one auditable history.
            </p>
            <div className="flex flex-col gap-3 sm:flex-row">
              <ButtonLink size="lg" href="/register">
                Create an account
                <ArrowRight className="size-4" aria-hidden />
              </ButtonLink>
              <ButtonLink size="lg" variant="outline" href="/login">
                Sign in
              </ButtonLink>
            </div>
          </div>
        </section>

        <section className="mx-auto grid max-w-5xl gap-4 px-4 py-16 sm:px-8 md:grid-cols-3">
          {FEATURES.map((feature) => (
            <Card key={feature.title}>
              <CardContent className="space-y-3">
                <span className="flex size-10 items-center justify-center rounded-md bg-primary/15">
                  <feature.icon className="size-5 text-primary" aria-hidden />
                </span>
                <h2 className="font-medium">{feature.title}</h2>
                <p className="text-sm text-muted-foreground">{feature.description}</p>
              </CardContent>
            </Card>
          ))}
        </section>

        <section className="mx-auto max-w-5xl px-4 pb-20 sm:px-8">
          <Card className="border-dashed">
            <CardContent className="space-y-2">
              <h2 className="font-medium">What this release does not do yet</h2>
              <p className="text-sm text-muted-foreground">
                This is the foundation release. It performs a single HTTP request per scan and
                reports exactly what it observed. Crawling, security-header and cookie analysis,
                TLS inspection, XSS and SQL-injection testing, CORS checks and risk scoring are
                planned for later phases and are deliberately not implemented — no scan will ever
                show a vulnerability finding that was not actually measured.
              </p>
            </CardContent>
          </Card>
        </section>
      </main>

      <footer className="border-t border-border px-4 py-6 text-center text-sm text-muted-foreground sm:px-8">
        Only scan systems you own or have written permission to test.
      </footer>
    </div>
  );
}
