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
