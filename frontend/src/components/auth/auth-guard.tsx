"use client";

import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";

import { FullPageLoader } from "@/components/common/full-page-loader";
import { useAuth } from "@/hooks/use-auth";

/**
 * Client-side gate for the dashboard.
 *
 * The middleware already redirects visitors without a cookie; this catches the
 * cases it cannot see — an expired or revoked token — by trusting the API's
 * answer rather than the cookie's existence.
 */
export function AuthGuard({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (status === "unauthenticated") {
      router.replace("/login");
    }
  }, [status, router]);

  if (status !== "authenticated") {
    return <FullPageLoader label="Verifying your session…" />;
  }

  return <>{children}</>;
}
