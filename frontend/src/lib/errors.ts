import { AxiosError } from "axios";

import type { ApiErrorDetail, ApiErrorResponse } from "@/types/api";

/**
 * A backend failure normalised into something the UI can render directly.
 *
 * Raw axios/network errors never reach components: the api client converts
 * every rejection into one of these, so screens always have a safe message.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: ApiErrorDetail[];

  constructor(status: number, code: string, message: string, details: ApiErrorDetail[] = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }

  get isUnauthorized(): boolean {
    return this.status === 401;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }

  get isValidation(): boolean {
    return this.status === 422 || this.status === 400;
  }

  /** Per-field messages, keyed by field name, for wiring into a form. */
  fieldErrors(): Record<string, string> {
    const result: Record<string, string> = {};
    for (const detail of this.details) {
      if (detail.field && !(detail.field in result)) {
        result[detail.field] = detail.message;
      }
    }
    return result;
  }
}

const NETWORK_MESSAGE =
  "Could not reach the API. Check that the backend is running and NEXT_PUBLIC_API_URL is correct.";

const STATUS_FALLBACKS: Record<number, string> = {
  400: "The request could not be processed.",
  401: "Your session has expired. Please sign in again.",
  403: "You do not have access to this resource.",
  404: "The requested resource was not found.",
  409: "That resource already exists.",
  422: "Some fields are invalid.",
  500: "Something went wrong on the server. Please try again.",
};

function isApiErrorResponse(data: unknown): data is ApiErrorResponse {
  return (
    typeof data === "object" &&
    data !== null &&
    "error" in data &&
    typeof (data as ApiErrorResponse).error?.message === "string"
  );
}

/** Convert any thrown value into an `ApiError`. */
export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;

  if (error instanceof AxiosError) {
    const { response } = error;

    if (!response) {
      const timedOut = error.code === "ECONNABORTED" || error.code === "ETIMEDOUT";
      return new ApiError(
        0,
        timedOut ? "timeout" : "network_error",
        timedOut ? "The request timed out. Please try again." : NETWORK_MESSAGE,
      );
    }

    if (isApiErrorResponse(response.data)) {
      const { code, message, details } = response.data.error;
      return new ApiError(response.status, code, message, details ?? []);
    }

    return new ApiError(
      response.status,
      "http_error",
      STATUS_FALLBACKS[response.status] ?? "The request failed. Please try again.",
    );
  }

  return new ApiError(0, "unknown_error", "An unexpected error occurred. Please try again.");
}

/** Safe message for any thrown value, for use in toasts and alerts. */
export function errorMessage(error: unknown): string {
  return toApiError(error).message;
}
