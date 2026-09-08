"use client";

import { Loader2, Trash2 } from "lucide-react";
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
import { scanService } from "@/services/scan.service";
import { truncateUrl } from "@/lib/format";
import type { Scan } from "@/types/scan";

interface DeleteScanDialogProps {
  scan: Scan;
  onDeleted: () => void;
  /** Rendered as the dialog trigger. Defaults to an icon button. */
  trigger?: React.ReactElement;
}

export function DeleteScanDialog({ scan, onDeleted, trigger }: DeleteScanDialogProps) {
  const [open, setOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await scanService.remove(scan.id);
      toast.success("Scan deleted.");
      setOpen(false);
      onDeleted();
    } catch (error) {
      toast.error("Could not delete the scan", { description: errorMessage(error) });
    } finally {
      setDeleting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger
        render={
          trigger ?? (
            <Button variant="ghost" size="icon" aria-label={`Delete scan of ${scan.target_url}`}>
              <Trash2 className="size-4 text-muted-foreground" aria-hidden />
            </Button>
          )
        }
      />
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Delete this scan?</DialogTitle>
          <DialogDescription>
            The scan of{" "}
            <span className="font-mono text-foreground">{truncateUrl(scan.target_url, 48)}</span>{" "}
            and its result will be permanently removed. This cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <DialogClose render={<Button variant="outline" disabled={deleting} />}>Cancel</DialogClose>
          <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
            {deleting ? <Loader2 className="size-4 animate-spin" aria-hidden /> : null}
            Delete scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
