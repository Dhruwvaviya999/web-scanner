"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";
import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { ErrorAlert } from "@/components/common/error-alert";
import { FieldError } from "@/components/common/field-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/use-auth";
import { ApiError } from "@/lib/errors";

const schema = z.object({
  email: z.string().trim().min(1, "Email is required.").email("Enter a valid email address."),
  password: z.string().min(1, "Password is required."),
});

type FormValues = z.infer<typeof schema>;

export function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login } = useAuth();

  const nextPath = searchParams.get("next");
  const expired = searchParams.get("reason") === "expired";

  const {
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { email: "", password: "" },
  });

  useEffect(() => {
    if (expired) {
      toast.info("Your session expired. Please sign in again.");
    }
  }, [expired]);

  const onSubmit = handleSubmit(async (values) => {
    try {
      await login(values);
      toast.success("Signed in.");
      // Only follow an in-app path, so `next` cannot be used as an open redirect.
      const destination = nextPath?.startsWith("/") ? nextPath : "/dashboard";
      router.replace(destination);
      router.refresh();
    } catch (error) {
      const apiError = error instanceof ApiError ? error : null;

      if (apiError?.isValidation) {
        for (const [field, message] of Object.entries(apiError.fieldErrors())) {
          if (field === "email" || field === "password") {
            setError(field, { message });
          }
        }
        return;
      }

      setError("root", {
        message: apiError?.message ?? "Could not sign you in. Please try again.",
      });
    }
  });

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      {errors.root?.message ? (
        <ErrorAlert title="Sign in failed" message={errors.root.message} />
      ) : null}

      <div className="space-y-2">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          autoComplete="email"
          placeholder="you@example.com"
          aria-invalid={Boolean(errors.email)}
          disabled={isSubmitting}
          {...register("email")}
        />
        <FieldError message={errors.email?.message} />
      </div>

      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          type="password"
          autoComplete="current-password"
          aria-invalid={Boolean(errors.password)}
          disabled={isSubmitting}
          {...register("password")}
        />
        <FieldError message={errors.password?.message} />
      </div>

      <Button type="submit" className="w-full" disabled={isSubmitting}>
        {isSubmitting ? <Loader2 className="size-4 animate-spin" aria-hidden /> : null}
        Sign in
      </Button>
    </form>
  );
}
