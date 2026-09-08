"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2 } from "lucide-react";
import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { FieldError } from "@/components/common/field-error";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/use-auth";
import { errorMessage } from "@/lib/errors";
import { formatDateTime } from "@/lib/format";
import { userService } from "@/services/user.service";

const schema = z.object({
  name: z.string().trim().min(2, "Name must be at least 2 characters.").max(120, "Name is too long."),
});

type FormValues = z.infer<typeof schema>;

export default function ProfilePage() {
  const { user, setUser, logout } = useAuth();

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting, isDirty },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { name: user?.name ?? "" },
  });

  useEffect(() => {
    if (user) reset({ name: user.name });
  }, [user, reset]);

  const onSubmit = handleSubmit(async (values) => {
    try {
      const updated = await userService.updateProfile(values);
      setUser(updated);
      reset({ name: updated.name });
      toast.success("Profile updated.");
    } catch (error) {
      toast.error("Could not update your profile", { description: errorMessage(error) });
    }
  });

  if (!user) return null;

  return (
    <>
      <PageHeader title="Profile" description="Your account details and session." />

      <Card>
        <CardHeader>
          <CardTitle>Account</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} noValidate className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                autoComplete="name"
                aria-invalid={Boolean(errors.name)}
                disabled={isSubmitting}
                {...register("name")}
              />
              <FieldError message={errors.name?.message} />
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" value={user.email} readOnly disabled className="font-mono" />
              <p className="text-xs text-muted-foreground">
                Your email is used to sign in and cannot be changed in this release.
              </p>
            </div>

            <Button type="submit" disabled={isSubmitting || !isDirty}>
              {isSubmitting ? <Loader2 className="size-4 animate-spin" aria-hidden /> : null}
              Save changes
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Details</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="divide-y divide-border">
            <div className="grid gap-1 py-3 sm:grid-cols-[13rem_1fr]">
              <dt className="text-sm text-muted-foreground">User ID</dt>
              <dd className="font-mono text-xs break-all">{user.id}</dd>
            </div>
            <div className="grid gap-1 py-3 sm:grid-cols-[13rem_1fr]">
              <dt className="text-sm text-muted-foreground">Member since</dt>
              <dd className="text-sm">{formatDateTime(user.created_at)}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Session</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-sm text-muted-foreground">
            Signing out clears the session cookie in your browser.
          </p>
          <Button variant="outline" onClick={() => void logout()}>
            Sign out
          </Button>
        </CardContent>
      </Card>
    </>
  );
}
