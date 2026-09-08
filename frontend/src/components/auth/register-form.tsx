"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
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

// Mirrors the backend rules in backend/app/schemas/user.py. The server remains
// the authority; this only gives immediate feedback.
const schema = z
  .object({
    name: z.string().trim().min(2, "Name must be at least 2 characters.").max(120, "Name is too long."),
    email: z.string().trim().min(1, "Email is required.").email("Enter a valid email address."),
    password: z
      .string()
      .min(10, "Password must be at least 10 characters.")
      .max(128, "Password is too long.")
      .regex(/[A-Za-z]/, "Password must contain at least one letter.")
      .regex(/\d/, "Password must contain at least one number."),
    confirm_password: z.string().min(1, "Confirm your password."),
  })
  .refine((values) => values.password === values.confirm_password, {
    path: ["confirm_password"],
    message: "Passwords do not match.",
  });

type FormValues = z.infer<typeof schema>;

const FIELD_NAMES = ["name", "email", "password", "confirm_password"] as const;

function isFieldName(value: string): value is (typeof FIELD_NAMES)[number] {
  return (FIELD_NAMES as readonly string[]).includes(value);
}

export function RegisterForm() {
  const router = useRouter();
  const { register: registerUser } = useAuth();

  const {
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { name: "", email: "", password: "", confirm_password: "" },
  });

  const onSubmit = handleSubmit(async (values) => {
    try {
      await registerUser(values);
      toast.success("Account created. Welcome!");
      router.replace("/dashboard");
      router.refresh();
    } catch (error) {
      const apiError = error instanceof ApiError ? error : null;

      if (apiError?.code === "email_already_registered") {
        setError("email", { message: apiError.message });
        return;
      }

      if (apiError?.isValidation) {
        const fieldErrors = apiError.fieldErrors();
        let matched = false;
        for (const [field, message] of Object.entries(fieldErrors)) {
          if (isFieldName(field)) {
            setError(field, { message });
            matched = true;
          }
        }
        if (matched) return;
      }

      setError("root", {
        message: apiError?.message ?? "Could not create your account. Please try again.",
      });
    }
  });

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      {errors.root?.message ? (
        <ErrorAlert title="Registration failed" message={errors.root.message} />
      ) : null}

      <div className="space-y-2">
        <Label htmlFor="name">Name</Label>
        <Input
          id="name"
          autoComplete="name"
          placeholder="Ada Lovelace"
          aria-invalid={Boolean(errors.name)}
          disabled={isSubmitting}
          {...register("name")}
        />
        <FieldError message={errors.name?.message} />
      </div>

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
          autoComplete="new-password"
          aria-invalid={Boolean(errors.password)}
          disabled={isSubmitting}
          {...register("password")}
        />
        <FieldError message={errors.password?.message} />
        {!errors.password ? (
          <p className="text-xs text-muted-foreground">
            At least 10 characters, including a letter and a number.
          </p>
        ) : null}
      </div>

      <div className="space-y-2">
        <Label htmlFor="confirm_password">Confirm password</Label>
        <Input
          id="confirm_password"
          type="password"
          autoComplete="new-password"
          aria-invalid={Boolean(errors.confirm_password)}
          disabled={isSubmitting}
          {...register("confirm_password")}
        />
        <FieldError message={errors.confirm_password?.message} />
      </div>

      <Button type="submit" className="w-full" disabled={isSubmitting}>
        {isSubmitting ? <Loader2 className="size-4 animate-spin" aria-hidden /> : null}
        Create account
      </Button>
    </form>
  );
}
