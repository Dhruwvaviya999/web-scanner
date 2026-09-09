"""API attack-surface response schemas.

None of these can carry a response body, a parameter value, a credential or a
header. `json_field_names` is a list of field *names* — the shape of the
interface — and the data that was in those fields never left the scanner's
memory, let alone reached a row or a response.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field

from app.models.api_surface import split_list


class ApiEndpointParameterRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str = Field(description="Parameter name. Values are never recorded.")
    location: str = Field(description="PATH, QUERY, HEADER, COOKIE or BODY.")
    required: bool | None = Field(
        default=None,
        description="From a specification, when it said. Null means nobody said.",
    )


class ApiEndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    #: The crawl row this was seen on. Null for a documented-only operation,
    #: which by definition was never requested.
    endpoint_id: uuid.UUID | None = None
    path: str
    method: str
    url: str | None = None
    confidence: str = Field(description="HIGH, MEDIUM or LOW. LOW is not an API.")
    auth_status: str
    observed: bool = Field(description="The scanner requested it and something answered.")
    documented: bool = Field(
        description="A specification says it exists. A claim, not a fact."
    )
    status_code: int | None = None
    request_media_type: str | None = None
    response_media_type: str | None = None
    operation_id: str | None = None
    json_top_level: str | None = None
    json_depth: int | None = None
    json_field_count: int | None = None
    discovered_at: datetime
    parameters: list[ApiEndpointParameterRead] = []

    #: Stored packed; unpacked here so a client sees a list.
    sources: str | None = Field(default=None, exclude=True)
    security: str | None = Field(default=None, exclude=True)
    json_field_names: str | None = Field(default=None, exclude=True)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def discovery_sources(self) -> list[str]:
        """Every mechanism that found this operation. More than one is normal."""
        return split_list(self.sources)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def security_schemes(self) -> list[str]:
        """Scheme names a specification declared. Never a credential."""
        return split_list(self.security)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def response_fields(self) -> list[str]:
        """Field names seen in a JSON response. Never a value from one."""
        return split_list(self.json_field_names)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def documented_only(self) -> bool:
        return self.documented and not self.observed


class ApiDocumentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    version: str
    title: str | None = None
    document_version: str | None = None
    path_count: int
    operation_count: int
    truncated: bool
    discovered_at: datetime

    security_schemes: str | None = Field(default=None, exclude=True)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def schemes(self) -> list[str]:
        return split_list(self.security_schemes)


class ApiSurfaceSummary(BaseModel):
    """Counters for the API attack-surface header."""

    detected: bool
    endpoints_discovered: int | None = None
    endpoints_observed: int | None = Field(
        default=None,
        description="Actually requested and answered, as opposed to merely described.",
    )
    endpoints_documented_only: int | None = Field(
        default=None, description="Described by a specification and never reached."
    )
    parameters_discovered: int | None = None
    documents: int | None = None
    authenticated_endpoints: int | None = None
    unknown_auth_endpoints: int | None = None
    graphql_detected: bool = False
    graphql_path: str | None = None
    truncated: bool = False


class ApiEndpointListResponse(BaseModel):
    items: list[ApiEndpointRead]
    documents: list[ApiDocumentRead]
    summary: ApiSurfaceSummary
