import { format, formatDistanceToNow, isValid, parseISO } from "date-fns";

function toDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const parsed = parseISO(value);
  return isValid(parsed) ? parsed : null;
}

export function formatDateTime(value: string | null | undefined): string {
  const date = toDate(value);
  return date ? format(date, "d MMM yyyy, HH:mm") : "—";
}

export function formatRelative(value: string | null | undefined): string {
  const date = toDate(value);
  return date ? `${formatDistanceToNow(date)} ago` : "—";
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
}

/** Shorten a URL for table cells without hiding the host. */
export function truncateUrl(url: string, maxLength = 60): string {
  return url.length <= maxLength ? url : `${url.slice(0, maxLength - 1)}…`;
}

/** The `text/html` part of a `text/html; charset=utf-8` header. */
export function primaryContentType(value: string | null | undefined): string {
  if (!value) return "—";
  return value.split(";")[0].trim() || "—";
}
