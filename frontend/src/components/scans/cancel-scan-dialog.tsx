"use client";

import { CircleSlash, Loader2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { errorMessage } from "@/lib/errors";
import { truncateUrl } from "@/lib/format";
import { scanService } from "@/services/scan.service";
import type { Scan } from "@/types/scan";

interface CancelScanDialogProps {
  scan: Scan;
  /** Called with the row the backend returned, so the caller shows real state. */
  onRequested: (scan: Scan) => void;
  /** Rendered as the dialog trigger. Defaults to an icon button. */
  trigger?: React.ReactElement;
}

/**
 * Asks the backend to stop a scan.
 *
 * The wording throughout is deliberately "requested", not "cancelled": the
 * backend stops a running scan cooperatively, at its next safe boundary, so
 * the only thing this component can honestly report is that the request was
 * accepted. The status shown afterwards is whatever the backend returned.
 */
export function CancelScanDialog({ scan, onRequested, trigger }: CancelScanDialogProps) {
  const [open, setOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleCancel = async () => {
    setSubmitting(true);
    try {
      const updated = await scanService.cancel(scan.id);
      toast.success(
        updated.status === "CANCELLED"
          ? "Scan cancelled."
          : "Stop requested. The scan will finish shortly.",
      );
      setOpen(false);
      onRequested(updated);
    } catch (error) {
      toast.error("Could not cancel the scan", { description: errorMessage(error) });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger
        render={
          trigger ?? (
            <Button variant="ghost" size="icon" aria-label={`Cancel scan of ${scan.target_url}`}>
              <CircleSlash className="size-4 text-muted-foreground" aria-hidden />
            </Button>
          )
        }
      />
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Stop this scan?</DialogTitle>
          <DialogDescription>
            The scan of{" "}
            <span className="font-mono text-foreground">{truncateUrl(scan.target_url, 48)}</span>{" "}
            will stop at its next safe point, which may take a few seconds. Everything it has
            already found is kept, but the result will be partial and is not a clean pass.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <DialogClose render={<Button variant="outline" disabled={submitting} />}>
            Keep scanning
          </DialogClose>
          <Button variant="destructive" onClick={handleCancel} disabled={submitting}>
            {submitting ? <Loader2 className="size-4 animate-spin" aria-hidden /> : null}
            Stop scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
