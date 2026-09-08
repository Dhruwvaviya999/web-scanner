import { AlertTriangle } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

interface ErrorAlertProps {
  title?: string;
  message: string;
}

export function ErrorAlert({ title = "Something went wrong", message }: ErrorAlertProps) {
  return (
    <Alert variant="destructive">
      <AlertTriangle className="size-4" aria-hidden />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  );
}
