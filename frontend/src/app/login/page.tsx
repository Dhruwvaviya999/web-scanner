import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";

import { Brand } from "@/components/common/brand";
import { LoginForm } from "@/components/auth/login-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export const metadata: Metadata = { title: "Sign in" };

export default function LoginPage() {
  return (
    <div className="bg-grid flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-12">
      <Brand />
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
          <CardDescription>Access your scans and start a new one.</CardDescription>
        </CardHeader>
        <CardContent>
          <Suspense fallback={null}>
            <LoginForm />
          </Suspense>
        </CardContent>
      </Card>
      <p className="text-sm text-muted-foreground">
        No account?{" "}
        <Link href="/register" className="font-medium text-primary hover:underline">
          Create one
        </Link>
      </p>
    </div>
  );
}
