"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2, Radar } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { FieldError } from "@/components/common/field-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/lib/errors";
import { truncateUrl } from "@/lib/format";
import { scanService } from "@/services/scan.service";
import type { Scan } from "@/types/scan";

const schema = z.object({
  target_url: z
    .string()
    .trim()
    .min(1, "Enter a URL to scan.")
    .max(2048, "That URL is too long.")
    .refine((value) => !/\s/.test(value), "A URL cannot contain spaces."),
});

type FormValues = z.infer<typeof schema>;

export function CreateScanForm({ onCreated }: { onCreated?: (scan: Scan) => void }) {
  // The URL currently being probed, kept separately so the progress panel keeps
  // showing it after the input has been cleared.
  const [scanning, setScanning] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { target_url: "" },
  });

  const onSubmit = handleSubmit(async (values) => {
    setScanning(values.target_url);
    try {
      const scan = await scanService.create(values);
      reset();

      if (scan.status === "FAILED") {
        toast.warning("Scan failed", {
          description: scan.error_message ?? "The target could not be reached.",
        });
      } else {
        toast.success("Scan completed", {
          description: `${scan.http_status_code ?? "—"} · ${scan.final_url ?? scan.target_url}`,
        });
      }
      onCreated?.(scan);
    } catch (error) {
      const apiError = error instanceof ApiError ? error : null;

      // A rejected URL belongs on the field itself, not in a toast.
      const fieldMessage = apiError?.fieldErrors().target_url;
      if (fieldMessage) {
        setError("target_url", { message: fieldMessage });
        return;
      }

      toast.error("Could not start the scan", {
        description: apiError?.message ?? "Please try again.",
      });
    } finally {
      setScanning(null);
    }
  });

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row">
        <Input
          {...register("target_url")}
          type="text"
          inputMode="url"
          autoComplete="url"
          placeholder="https://example.com"
          aria-label="Target URL"
          aria-invalid={Boolean(errors.target_url)}
          disabled={isSubmitting}
          className="font-mono"
        />
        <Button type="submit" disabled={isSubmitting} className="sm:w-40">
          {isSubmitting ? (
            <>
              <Loader2 className="size-4 animate-spin" aria-hidden />
              Scanning…
            </>
          ) : (
            <>
              <Radar className="size-4" aria-hidden />
              Start scan
            </>
          )}
        </Button>
      </div>

      <FieldError message={errors.target_url?.message} />

      {isSubmitting && scanning ? (
        <div
          role="status"
          aria-live="polite"
          className="flex items-center gap-3 rounded-md border border-primary/30 bg-primary/10 px-3 py-2.5"
        >
          <Loader2 className="size-4 shrink-0 animate-spin text-primary" aria-hidden />
          <div className="min-w-0 text-sm">
            <p className="font-medium">Scanning target…</p>
            <p className="truncate font-mono text-xs text-muted-foreground">
              {truncateUrl(scanning, 64)}
            </p>
          </div>
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">
          Only scan sites you own or are authorised to test. The probe sends a single HTTP request
          to this exact URL — it does not crawl the site.
        </p>
      )}
    </form>
  );
}
