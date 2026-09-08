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

/** Wall-clock elapsed time, e.g. `0:07`, `1:42`, `1:02:03`. */
export function formatElapsed(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || seconds < 0) return "—";
  const whole = Math.floor(seconds);
  const hours = Math.floor(whole / 3600);
  const minutes = Math.floor((whole % 3600) / 60);
  const secs = whole % 60;
  const padded = `${minutes.toString().padStart(hours ? 2 : 1, "0")}:${secs
    .toString()
    .padStart(2, "0")}`;
  return hours ? `${hours}:${padded}` : padded;
}

/** Seconds between two ISO timestamps, or from `from` until now. */
export function elapsedSeconds(
  from: string | null | undefined,
  to?: string | null,
): number | null {
  const start = toDate(from);
  if (!start) return null;
  const end = to ? toDate(to) : new Date();
  if (!end) return null;
  return Math.max(0, (end.getTime() - start.getTime()) / 1000);
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

/** Human-readable byte size, e.g. `559 B`, `12.4 KB`. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

/** Standard reason phrase for the status codes a basic probe encounters. */
const STATUS_TEXT: Record<number, string> = {
  200: "OK",
  201: "Created",
  204: "No Content",
  301: "Moved Permanently",
  302: "Found",
  304: "Not Modified",
  307: "Temporary Redirect",
  308: "Permanent Redirect",
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  410: "Gone",
  429: "Too Many Requests",
  500: "Internal Server Error",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
};

export function statusCodeText(code: number | null | undefined): string | null {
  return code ? (STATUS_TEXT[code] ?? null) : null;
}

/** Which family a status code belongs to, for colouring. */
export type StatusFamily = "success" | "redirect" | "client-error" | "server-error" | "unknown";

export function statusFamily(code: number | null | undefined): StatusFamily {
  if (!code) return "unknown";
  if (code >= 200 && code < 300) return "success";
  if (code >= 300 && code < 400) return "redirect";
  if (code >= 400 && code < 500) return "client-error";
  if (code >= 500) return "server-error";
  return "unknown";
}
