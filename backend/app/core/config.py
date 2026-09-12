"""Application settings loaded from environment variables / .env file."""

from functools import lru_cache
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

Environment = Literal["development", "staging", "production"]
SameSitePolicy = Literal["lax", "strict", "none"]


def _split_csv(value: Any) -> Any:
    """Allow list-valued settings to be written as `a,b,c` in a .env file."""
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("["):
            return stripped  # Looks like JSON; let pydantic parse it.
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return value


# NoDecode stops pydantic-settings from JSON-parsing the raw .env value before
# `_split_csv` gets a chance to read it as a comma-separated list.
CommaSeparatedList = Annotated[list[str], NoDecode, BeforeValidator(_split_csv)]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application ---
    ENVIRONMENT: Environment = "development"
    PROJECT_NAME: str = "Web Scanner API"
    API_PREFIX: str = "/api"

    # --- Database ---
    DATABASE_URL: str = Field(
        description="SQLAlchemy URL, e.g. postgresql+psycopg://user:pass@localhost:5432/webscanner",
    )
    DATABASE_ECHO: bool = False

    # --- JWT ---
    JWT_SECRET_KEY: str = Field(min_length=32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60, gt=0)

    # --- Auth cookie ---
    # The access token is delivered as an httpOnly cookie so that page scripts
    # (and therefore XSS payloads) cannot read it.
    AUTH_COOKIE_NAME: str = "ws_access_token"
    AUTH_COOKIE_SECURE: bool = False  # Must be True whenever the site is served over HTTPS.
    AUTH_COOKIE_SAMESITE: SameSitePolicy = "lax"
    AUTH_COOKIE_DOMAIN: str | None = None  # e.g. ".example.com" when API and UI are on subdomains.
    AUTH_COOKIE_PATH: str = "/"

    # --- CORS ---
    CORS_ORIGINS: CommaSeparatedList = ["http://localhost:3000"]

    # --- Scanner ---
    SCANNER_TIMEOUT_SECONDS: float = Field(default=10.0, gt=0)
    # Covers probe + security analysis + crawl. Raised in phase 4 because
    # the crawl runs inline in the same request.
    SCANNER_TOTAL_TIMEOUT_SECONDS: float = Field(default=150.0, gt=0)
    SCANNER_MAX_REDIRECTS: int = Field(default=5, ge=0, le=20)
    # Hard cap on body bytes read from a target. Only HTML bodies are read,
    # and only far enough to recover the page title.
    SCANNER_MAX_RESPONSE_BYTES: int = Field(default=262_144, gt=0)
    SCANNER_USER_AGENT: str = "WebScanner/0.1 (+https://github.com/local/web-scanner)"
    # Scanning private/loopback addresses is an SSRF vector. Only enable this on
    # an isolated network where you intend to scan internal hosts.
    SCANNER_ALLOW_PRIVATE_NETWORKS: bool = False

    # --- Crawler (phase 4) ---
    CRAWLER_ENABLED: bool = True
    CRAWLER_MAX_PAGES: int = Field(default=50, gt=0, le=500)
    CRAWLER_MAX_DEPTH: int = Field(default=3, ge=0, le=10)
    # Wall-clock budget for the crawl alone; must stay below
    # SCANNER_TOTAL_TIMEOUT_SECONDS to leave room for the probe.
    CRAWLER_TIME_BUDGET_SECONDS: float = Field(default=90.0, gt=0)
    CRAWLER_MAX_REDIRECTS_PER_PAGE: int = Field(default=3, ge=0, le=10)

    # --- Active probing (phase 7) ---
    # Budgets for every active detector, shared across a scan. Probes only ever
    # target URLs already inside the authorised scan scope.
    ACTIVE_SCAN_ENABLED: bool = True
    XSS_ENABLED: bool = True
    MAX_ACTIVE_PROBES_PER_PARAMETER: int = Field(default=8, gt=0, le=50)
    MAX_ACTIVE_PROBES_PER_ENDPOINT: int = Field(default=32, gt=0, le=500)
    MAX_ACTIVE_PROBES_PER_SCAN: int = Field(default=160, gt=0, le=2000)
    ACTIVE_SCAN_MAX_TARGETS: int = Field(default=25, gt=0, le=200)
    # Parameters one detector will test on a single endpoint. The budgets above
    # still apply on top of this.
    XSS_MAX_PARAMETERS_PER_ENDPOINT: int = Field(default=8, gt=0, le=50)
    # SQL-injection detector. Shares the active-probe budgets above.
    SQLI_ENABLED: bool = True
    SQLI_MAX_PARAMETERS_PER_ENDPOINT: int = Field(default=6, gt=0, le=50)

    # --- Authorization testing (phase 12) ---
    # Off unless a scan supplies at least two identities. The budget matters
    # more here than anywhere else in the scanner: every extra identity re-tests
    # every eligible endpoint, so cost is contexts x endpoints.
    AUTHZ_ENABLED: bool = True
    AUTHZ_MAX_CONTEXTS: int = Field(default=4, gt=1, le=8)
    AUTHZ_MAX_ENDPOINTS: int = Field(default=100, gt=0, le=1000)
    AUTHZ_MAX_COMPARISONS_PER_ENDPOINT: int = Field(default=8, gt=0, le=64)
    AUTHZ_MAX_REQUESTS: int = Field(default=400, gt=0, le=4000)
    #: Body similarity at or above which two responses count as the same
    #: resource. High on purpose: "roughly alike" is how a shared page template
    #: gets mistaken for a leaked record.
    AUTHZ_EQUIVALENCE_THRESHOLD: float = Field(default=0.95, gt=0.5, le=1.0)

    # --- API discovery (phase 13) ---
    # Reconnaissance, not exploitation. The only traffic this stage generates is
    # a handful of GETs to conventional documentation paths on the origin
    # already being scanned; the rest is classification of responses the crawl
    # already paid for.
    API_DISCOVERY_ENABLED: bool = True
    #: Whether to request well-known specification paths at all. Turning this
    #: off leaves classification working and sends nothing extra.
    API_FETCH_DOCUMENTS: bool = True
    #: Conventional documentation paths tried. Small and fixed: raising this
    #: into the hundreds would turn discovery into path enumeration, which this
    #: phase deliberately does not do.
    API_MAX_DOCUMENT_CANDIDATES: int = Field(default=8, gt=0, le=16)
    API_MAX_PARSED_PATHS: int = Field(default=500, gt=0, le=5000)
    API_MAX_ENDPOINTS: int = Field(default=500, gt=0, le=5000)
    API_MAX_PARAMETERS_PER_ENDPOINT: int = Field(default=50, gt=0, le=200)
    API_MAX_JSON_FIELDS: int = Field(default=50, gt=0, le=200)
    API_MAX_JSON_DEPTH: int = Field(default=6, gt=0, le=20)

    # --- API security analysis (phase 14) ---
    # Read-only. The stage sends no request of its own: it reads the field
    # names, headers and error signals earlier phases already captured.
    API_SECURITY_ENABLED: bool = True
    API_SECURITY_MAX_ENDPOINTS: int = Field(default=500, gt=0, le=5000)
    API_SECURITY_MAX_FIELDS_PER_ENDPOINT: int = Field(default=50, gt=0, le=200)
    API_SECURITY_MAX_PROPERTY_COMPARISONS: int = Field(default=200, gt=0, le=2000)
    #: Whether plaintext HTTP is reported as a weakness. Off by default: every
    #: local fixture and development target is HTTP, and calling that a
    #: production TLS failure would be wrong far more often than right.
    API_SECURITY_FLAG_PLAINTEXT_HTTP: bool = False

    # --- Session security and CSRF analysis (phase 15) ---
    # Passive. The stage sends nothing: it correlates the cookies, URLs, forms
    # and token metadata earlier phases already captured. The limits bound how
    # much of that it retains, not how much traffic it generates.
    SESSION_SECURITY_ENABLED: bool = True
    SESSION_MAX_COOKIES: int = Field(default=100, gt=0, le=1000)
    SESSION_MAX_URLS: int = Field(default=500, gt=0, le=5000)
    SESSION_MAX_FORMS: int = Field(default=200, gt=0, le=2000)
    SESSION_MAX_JWTS: int = Field(default=50, gt=0, le=500)
    #: Requests this stage may make. Zero, and the module never reads it: the
    #: ceiling exists so that a later phase adding fixture-only CSRF
    #: verification has to raise it deliberately rather than by omission.
    SESSION_MAX_REQUESTS: int = Field(default=0, ge=0, le=50)
    #: Whether a session cookie set over plain HTTP is reported as a finding.
    #: Off by default, matching API_SECURITY_FLAG_PLAINTEXT_HTTP and for the
    #: same reason: local and development targets are HTTP, and grading each
    #: one as a transport failure would be wrong more often than right.
    SESSION_FLAG_PLAINTEXT_HTTP: bool = False

    # --- Configuration, deployment and transport security (phase 16) ---
    # Bounded GET/HEAD/OPTIONS against fixed candidate lists. There is no
    # wordlist, no recursion and no filename generation anywhere in the stage,
    # so these numbers bound a small constant rather than an open-ended sweep.
    CONFIG_SECURITY_ENABLED: bool = True
    #: Every request the stage may make, across all candidate lists.
    CONFIG_SECURITY_MAX_REQUESTS: int = Field(default=100, ge=0, le=500)
    CONFIG_SECURITY_MAX_ADMIN_CANDIDATES: int = Field(default=50, ge=0, le=200)
    CONFIG_SECURITY_MAX_FILE_CANDIDATES: int = Field(default=50, ge=0, le=200)
    CONFIG_SECURITY_MAX_BACKUP_CANDIDATES: int = Field(default=50, ge=0, le=200)
    #: Backup spellings derived per file the scan already found. Three, not a
    #: wordlist — raising this turns a check into enumeration.
    CONFIG_SECURITY_MAX_BACKUP_VARIANTS: int = Field(default=3, ge=0, le=5)
    CONFIG_SECURITY_MAX_SOURCE_MAPS: int = Field(default=10, ge=0, le=50)
    CONFIG_SECURITY_MAX_METHOD_CHECKS: int = Field(default=20, ge=0, le=100)
    CONFIG_SECURITY_MAX_RESPONSES: int = Field(default=200, ge=1, le=2000)
    #: Bytes read from a candidate before the body is discarded. Enough to tell
    #: a real file from a catch-all HTML route; nowhere near a download.
    CONFIG_SECURITY_MAX_CANDIDATE_BYTES: int = Field(default=8192, ge=256, le=65536)
    #: Whether the stage requests candidate paths at all. Off makes it fully
    #: passive: it then reads only what earlier phases already captured.
    CONFIG_SECURITY_PROBE_CANDIDATES: bool = True
    #: Whether a plain-HTTP target is reported as a transport finding. Off by
    #: default, and loopback and private-network targets stay exempt even when
    #: it is on — a developer scanning their own machine has misconfigured
    #: nothing, and grading it would be wrong more often than right.
    CONFIG_SECURITY_REQUIRE_HTTPS: bool = False

    # --- Path traversal and local file inclusion (phase 17) ---
    # Active, but bounded and canary-based: probes aim at a controlled marker
    # file, never a real system file. The variant set is fixed and small; these
    # numbers cap how many parameters and endpoints it touches, not a wordlist.
    PATH_SECURITY_ENABLED: bool = True
    PATH_SECURITY_MAX_PARAMETERS_PER_ENDPOINT: int = Field(default=3, gt=0, le=20)
    #: Traversal variants per parameter. The built-in set is 8; this only caps
    #: it lower, and can never enlarge it.
    PATH_SECURITY_MAX_VARIANTS_PER_PARAMETER: int = Field(default=8, gt=0, le=8)
    PATH_SECURITY_MAX_TARGETS: int = Field(default=25, gt=0, le=200)
    #: Hard scan-wide probe ceiling for this stage, separate from the general
    #: active-scan budget. Fails closed.
    PATH_SECURITY_MAX_PROBES_PER_SCAN: int = Field(default=200, gt=0, le=2000)
    PATH_SECURITY_PER_PARAMETER_BUDGET: int = Field(default=12, gt=0, le=64)
    PATH_SECURITY_PER_ENDPOINT_BUDGET: int = Field(default=48, gt=0, le=512)
    #: Bytes of a probe response scanned for the canary before it is discarded.
    PATH_SECURITY_MAX_RESPONSE_BYTES: int = Field(default=32768, ge=256, le=262144)

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def _reject_placeholder_secret(cls, value: str) -> str:
        if "change-me" in value.lower() or "changeme" in value.lower():
            raise ValueError(
                "JWT_SECRET_KEY is still the placeholder value. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
            )
        return value

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # values come from the environment


settings = get_settings()
