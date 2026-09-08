/** Shapes returned by the FastAPI backend for non-2xx responses. */

export interface ApiErrorDetail {
  field: string | null;
  message: string;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  details: ApiErrorDetail[];
}

export interface ApiErrorResponse {
  error: ApiErrorBody;
}

export interface MessageResponse {
  message: string;
}
