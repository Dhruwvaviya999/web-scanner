"""Scan request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    computed_field,
    field_validator,
    model_validator,
)

from app.models.scan import ScanStatus
from app.scanner import ScannerError, parse_target_url
from app.scanner.auth import (
    MAX_COOKIES,
    MAX_COOKIE_VALUE_LENGTH,
    MAX_TOKEN_LENGTH,
    AuthConfigError,
    AuthMode,
    AuthStatus,
    validate_cookie,
    validate_mode_payload,
)
from app.scanner.auth import validate_bearer_token as _validate_bearer_token


class ScanAuthCookie(BaseModel):
    """One cookie the user supplies so the scan can reach their own pages.

    `SecretStr` is not decoration: it makes the value render as `**********` in
    every repr, log line, validation error and `model_dump_json`, so a cookie
    cannot escape through a stack trace or a debug print.

    Note the deliberate absence of `str_strip_whitespace` here. A session cookie
    is usually signed or encrypted; silently trimming it would break the
    signature and turn a working credential into an unexplained 401.
    """

    name: str = Field(min_length=1, max_length=256, examples=["session"])
    value: SecretStr = Field(max_length=MAX_COOKIE_VALUE_LENGTH)

    @model_validator(mode="after")
    def _validate(self) -> "ScanAuthCookie":
        try:
            validate_cookie(self.name, self.value.get_secret_value())
        except AuthConfigError as exc:
            raise ValueError(str(exc)) from exc
        return self


class ScanAuthentication(BaseModel):
    """Target-authentication material for one scan.

    **Not** the scanner's own login. This is a credential the authorized user
    already holds for the application they are asking the scanner to test. The
    scanner never discovers, guesses or refreshes one.

    Nothing here is ever written to the database. The material is turned into an
    in-memory context for the duration of the scan and is not part of any
    response model — `ScanRead` exposes only the mode and a status.
    """

    mode: AuthMode = AuthMode.NONE
    token: SecretStr | None = Field(
        default=None,
        max_length=MAX_TOKEN_LENGTH,
        description="Bearer token. Supply the token only; the scanner adds the prefix.",
    )
    cookies: list[ScanAuthCookie] = Field(default_factory=list, max_length=MAX_COOKIES)

    @model_validator(mode="after")
    def _validate(self) -> "ScanAuthentication":
        raw_token = self.token.get_secret_value() if self.token is not None else None
        pairs = [(c.name, c.value.get_secret_value()) for c in self.cookies]
        try:
            validate_mode_payload(self.mode, token=raw_token, cookies=pairs)
            if self.mode is AuthMode.BEARER_TOKEN:
                _validate_bearer_token(raw_token or "")
        except AuthConfigError as exc:
            raise ValueError(str(exc)) from exc
        return self


class ScanAuthenticationRead(BaseModel):
    """Safe authentication metadata. Structurally incapable of holding a secret."""

    model_config = ConfigDict(from_attributes=True)

    mode: AuthMode
    status: AuthStatus
    enabled: bool = Field(description="Whether any credential was configured for this scan.")


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


class ScanCreateWithAuth(ScanCreate):
    """Scan creation, optionally carrying target-authentication material.

    Separate from `ScanCreate` so the plain shape stays exactly what it was, and
    so it is obvious at a glance which request model can contain a secret.
    """

    authentication: ScanAuthentication | None = Field(
        default=None,
        description=(
            "Optional credentials for the target application, supplied by the "
            "authorized user. Never stored, never returned."
        ),
    )


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

    # --- Target authentication. Metadata only: there is no field on this model
    # that can carry a token, a cookie value or a header, so a secret has
    # nowhere to go even if one reached the row.
    auth_mode: AuthMode = AuthMode.NONE
    auth_status: AuthStatus = AuthStatus.NOT_CONFIGURED

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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authentication(self) -> ScanAuthenticationRead:
        """The same two facts, grouped, for clients that prefer an object."""
        return ScanAuthenticationRead(
            mode=self.auth_mode,
            status=self.auth_status,
            enabled=self.auth_mode is not AuthMode.NONE,
        )


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
