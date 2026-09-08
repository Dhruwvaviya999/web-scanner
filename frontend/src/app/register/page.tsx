import type { Metadata } from "next";
import Link from "next/link";

import { Brand } from "@/components/common/brand";
import { RegisterForm } from "@/components/auth/register-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export const metadata: Metadata = { title: "Create account" };

export default function RegisterPage() {
  return (
    <div className="bg-grid flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-12">
      <Brand />
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Create your account</CardTitle>
          <CardDescription>Start recording scans against the sites you own.</CardDescription>
        </CardHeader>
        <CardContent>
          <RegisterForm />
        </CardContent>
      </Card>
      <p className="text-sm text-muted-foreground">
        Already registered?{" "}
        <Link href="/login" className="font-medium text-primary hover:underline">
          Sign in
        </Link>
      </p>
    </div>
  );
}
