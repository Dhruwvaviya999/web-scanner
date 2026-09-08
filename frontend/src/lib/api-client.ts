import axios, { type AxiosInstance } from "axios";

import { toApiError } from "@/lib/errors";

/** Base URL of the FastAPI backend. Configured per environment, never hardcoded. */
export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"
).replace(/\/+$/, "");

/** Broadcast when the API rejects a request as unauthenticated. */
export const UNAUTHORIZED_EVENT = "webscanner:unauthorized";

/** Endpoints whose 401 is an expected outcome and must not force a sign-out. */
const SILENT_401_PATHS = ["/auth/login", "/auth/me", "/auth/logout"];

export const apiClient: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  // Sends and receives the httpOnly auth cookie. Requires the backend to allow
  // this exact origin with credentials (see CORS_ORIGINS).
  withCredentials: true,
  // A scan runs inline in the request, so allow for a slow target.
  timeout: 60_000,
  headers: { "Content-Type": "application/json" },
});

apiClient.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    const apiError = toApiError(error);
    const url = axios.isAxiosError(error) ? (error.config?.url ?? "") : "";

    // A session that expired mid-use: let the app tear down its auth state
    // instead of leaving a stale user on screen.
    if (
      apiError.isUnauthorized &&
      typeof window !== "undefined" &&
      !SILENT_401_PATHS.some((path) => url.startsWith(path))
    ) {
      window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    }

    return Promise.reject(apiError);
  },
);
