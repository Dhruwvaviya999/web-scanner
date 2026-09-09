"""Scan request/response schemas."""

from __future__ import annotations

import re
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
from app.scanner.authorization import AccessExpectation


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


#: Identifier for the anonymous context the scanner adds itself. Reserved, so a
#: user-supplied identity cannot collide with it and change what it means.
ANONYMOUS_CONTEXT_ID = "anonymous"

_CONTEXT_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

#: Separator for the stored context-label list. A unit separator cannot occur in
#: a label, so a label containing a comma cannot split into two on read-back.
LABEL_SEPARATOR = "\x1f"


class ScanAuthorizationContext(BaseModel):
    """One explicitly supplied testing identity.

    Reuses `ScanAuthentication`, so credential validation, redaction and
    transport are the phase-11 code paths rather than a second implementation.
    """

    id: str = Field(
        min_length=1,
        max_length=64,
        description="Stable identifier used by the policy rules. Not a secret.",
        examples=["alice"],
    )
    label: str = Field(min_length=1, max_length=120, examples=["Alice (customer)"])
    role: str | None = Field(
        default=None,
        max_length=64,
        description="Free-text role label. Metadata: the scanner attaches no meaning to it.",
        examples=["USER"],
    )
    privilege_rank: int = Field(
        default=0,
        ge=0,
        le=100,
        description=(
            "Higher means more privileged. Used only to tell a vertical "
            "comparison from a horizontal one, never to infer policy."
        ),
    )
    authentication: ScanAuthentication

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        if value == ANONYMOUS_CONTEXT_ID:
            raise ValueError(
                "That id is reserved for the built-in anonymous context."
            )
        if not _CONTEXT_ID_RE.fullmatch(value):
            raise ValueError(
                "A context id may contain letters, digits, and the characters _ . : -"
            )
        return value

    @model_validator(mode="after")
    def _require_credentials(self) -> "ScanAuthorizationContext":
        if self.authentication.mode is AuthMode.NONE:
            raise ValueError(
                "A named identity needs credentials. The unauthenticated case is "
                "covered by the built-in anonymous context."
            )
        return self


class ScanAuthorizationRule(BaseModel):
    """One declared expectation. The scanner never invents these."""

    context_id: str = Field(min_length=1, max_length=64)
    resource: str = Field(
        min_length=1,
        max_length=512,
        description="Path to match. A trailing * makes it a prefix.",
        examples=["/admin/*"],
    )
    expected: AccessExpectation


class ScanResourceOwnership(BaseModel):
    """Which identity a specific resource belongs to."""

    resource: str = Field(min_length=1, max_length=512, examples=["/api/orders/101"])
    owner: str = Field(min_length=1, max_length=64, examples=["alice"])


class ScanAuthorization(BaseModel):
    """Authorization-testing configuration for one scan.

    Nothing here is persisted beyond labels and counters. The credentials inside
    each context follow the phase-11 path: memory only, for the length of the
    scan.
    """

    enabled: bool = False
    #: The scanner adds an anonymous identity so "is this protected at all?" is
    #: always answerable. It carries no credential and cannot be given one.
    include_anonymous: bool = True
    contexts: list[ScanAuthorizationContext] = Field(default_factory=list, max_length=8)
    rules: list[ScanAuthorizationRule] = Field(default_factory=list, max_length=200)
    ownership: list[ScanResourceOwnership] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def _validate(self) -> "ScanAuthorization":
        if not self.enabled:
            return self

        ids = [context.id for context in self.contexts]
        if len(set(ids)) != len(ids):
            raise ValueError("Each authorization context needs a distinct id.")

        # A comparison needs two sides. One named identity plus anonymous is the
        # smallest useful configuration.
        available = len(ids) + (1 if self.include_anonymous else 0)
        if available < 2:
            raise ValueError(
                "Authorization testing needs at least two identities to compare. "
                "Supply another identity, or keep the anonymous context."
            )

        known = set(ids)
        if self.include_anonymous:
            known.add(ANONYMOUS_CONTEXT_ID)
        for rule in self.rules:
            if rule.context_id not in known:
                raise ValueError(f"Rule refers to unknown context {rule.context_id!r}.")
        for entry in self.ownership:
            if entry.owner not in known:
                raise ValueError(f"Ownership refers to unknown context {entry.owner!r}.")
        return self


class ScanAuthorizationRead(BaseModel):
    """Safe authorization coverage. Structurally incapable of holding a secret."""

    model_config = ConfigDict(from_attributes=True)

    enabled: bool
    contexts: int | None = None
    context_labels: list[str] = Field(default_factory=list)
    endpoints_eligible: int | None = None
    endpoints_tested: int | None = None
    comparisons: int | None = None
    unknown: int | None = Field(
        default=None,
        description="Comparisons with no declared policy to judge against. Not findings.",
    )
    skipped: int | None = None
    failed: int | None = None


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
    authorization: ScanAuthorization | None = Field(
        default=None,
        description=(
            "Optional authorization testing: identities to compare and the access "
            "policy they are measured against. Credentials are never stored or "
            "returned."
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

    # --- Authorization coverage. Counters and user-chosen labels only; there is
    # no field on this model that could carry a credential.
    authz_enabled: bool = False
    authz_contexts: int | None = None
    authz_context_labels: str | None = None
    authz_endpoints_eligible: int | None = None
    authz_endpoints_tested: int | None = None
    authz_comparisons: int | None = None
    authz_unknown: int | None = None
    authz_skipped: int | None = None
    authz_failed: int | None = None

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
    def authorization(self) -> ScanAuthorizationRead:
        """Authorization coverage, grouped. Contains no credential."""
        raw = self.authz_context_labels or ""
        return ScanAuthorizationRead(
            enabled=self.authz_enabled,
            contexts=self.authz_contexts,
            context_labels=[label for label in raw.split(LABEL_SEPARATOR) if label],
            endpoints_eligible=self.authz_endpoints_eligible,
            endpoints_tested=self.authz_endpoints_tested,
            comparisons=self.authz_comparisons,
            unknown=self.authz_unknown,
            skipped=self.authz_skipped,
            failed=self.authz_failed,
        )

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
