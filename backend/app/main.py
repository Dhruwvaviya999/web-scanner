"""FastAPI application entrypoint: wiring only, no business logic."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.core.database import engine
from app.core.errors import AppError, error_payload
from app.routers import auth, scans, users
from app.schemas.common import HealthResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        logger.info("Database connection OK")
    except Exception:  # noqa: BLE001 - start anyway so /api/health can report it
        logger.exception("Database connection failed at startup")
    yield
    engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="0.1.0",
    description="Phase 1: authentication, scan management and a basic HTTP probe.",
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url=None,
    openapi_url="/openapi.json" if not settings.is_production else None,
)

# Credentials are cookies, so the origin list must be explicit — "*" is rejected
# by browsers when allow_credentials is on, and would be unsafe regardless.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)


@app.exception_handler(AppError)
async def handle_app_error(_: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(exc.code, exc.message, exc.details),
    )


@app.exception_handler(RequestValidationError)
async def handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    """Flatten pydantic errors into `details`, without echoing the raw input back."""
    details = [
        {
            "field": ".".join(str(part) for part in error["loc"][1:]) or None,
            "message": error.get("msg", "Invalid value."),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=error_payload("validation_error", "Some fields are invalid.", details),
    )


@app.exception_handler(StarletteHTTPException)
async def handle_http_exception(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    codes = {
        status.HTTP_401_UNAUTHORIZED: "unauthorized",
        status.HTTP_403_FORBIDDEN: "forbidden",
        status.HTTP_404_NOT_FOUND: "not_found",
        status.HTTP_405_METHOD_NOT_ALLOWED: "method_not_allowed",
    }
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(codes.get(exc.status_code, "http_error"), detail),
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Last resort: log the traceback, return an opaque message.

    Stack traces, SQL and driver messages must never reach the client.
    """
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_payload("internal_error", "An unexpected error occurred."),
    )


@app.get("/api/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        database = "ok"
    except Exception:  # noqa: BLE001 - health must report, not raise
        logger.exception("Health check: database unreachable")
        database = "unavailable"
    return HealthResponse(status="ok", database=database, environment=settings.ENVIRONMENT)


app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(users.router, prefix=settings.API_PREFIX)
app.include_router(scans.router, prefix=settings.API_PREFIX)
