"""Scan request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.scan import ScanStatus
from app.scanner import ScannerError, parse_target_url


class ScanCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    target_url: str = Field(
        min_length=1,
        max_length=2048,
        description="The http(s) URL to scan. A bare hostname is treated as https://",
        examples=["https://example.com"],
    )

    @field_validator("target_url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        """Reject malformed targets during request validation (422).

        Only syntax is checked here; the DNS/SSRF check runs in the scanner, so
        that request handling never blocks on name resolution.
        """
        try:
            return parse_target_url(value).normalized_url
        except ScannerError as exc:
            raise ValueError(exc.message) from exc


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_url: str
    status: ScanStatus
    queued_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    cancelled_at: datetime | None = Field(
        default=None,
        description="When cancellation was requested, not when the run wound down.",
    )
    created_at: datetime
    updated_at: datetime

    # --- Progress. Coarse by design: the crawler discovers its own workload, so
    # a precise percentage cannot be justified and is not invented here.
    current_stage: str | None = Field(
        default=None, description="Lifecycle stage, e.g. CRAWLING. Null before a scan starts."
    )
    progress_percent: int | None = Field(
        default=None, description="Indicative only — a stage milestone, not a measurement."
    )
    progress_message: str | None = None
    #: True once the owner has asked the scan to stop. The scan is still RUNNING
    #: until it observes the request; the status is what says it has stopped.
    cancel_requested: bool = False
    #: Which stage a failed scan was in. A stage name only, never a trace.
    failure_stage: str | None = None

    http_status_code: int | None
    response_time_ms: int | None
    final_url: str | None
    content_type: str | None
    server_header: str | None
    is_https: bool | None
    redirect_count: int | None
    page_title: str | None
    content_length: int | None

    # Crawl summary. Null when the crawler did not run, which is distinct from
    # a crawl that ran and found nothing.
    pages_crawled: int | None
    pages_skipped: int | None
    max_depth_reached: int | None
    crawl_limit_reached: bool | None

    # Scan summary. Null when the corresponding stage did not run.
    endpoints_discovered: int | None
    endpoints_analyzed: int | None
    endpoints_skipped: int | None
    endpoints_failed: int | None
    forms_discovered: int | None
    parameters_discovered: int | None

    total_findings: int | None
    critical_count: int | None
    high_count: int | None
    medium_count: int | None
    low_count: int | None
    info_count: int | None

    error_message: str | None


class ScanListResponse(BaseModel):
    items: list[ScanRead]
    total: int
    limit: int
    offset: int


class ScanStats(BaseModel):
    """Counters backing the dashboard summary cards.

    One field per `ScanStatus`, so a new state cannot be silently dropped from
    the dashboard — `get_scan_stats` keys its result off the same enum.
    """

    total: int
    queued: int
    running: int
    completed: int
    failed: int
    cancelled: int
