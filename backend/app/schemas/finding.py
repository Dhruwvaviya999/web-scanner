"""Finding response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
)


class EndpointRef(BaseModel):
    """Minimal endpoint context carried on a finding."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    method: str
    path: str


class FindingOccurrenceRead(BaseModel):
    """One endpoint a finding was observed on."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    endpoint_id: uuid.UUID | None
    endpoint_url: str | None
    evidence: str


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    rule_id: str = Field(
        description="Stable identifier of the rule that fired. The deduplication key."
    )
    subject: str | None = Field(
        default=None,
        description="What the finding is about within its rule, such as a cookie name.",
    )
    title: str
    category: FindingCategory
    severity: FindingSeverity
    confidence: FindingConfidence
    description: str
    evidence: str = Field(
        description="What was observed. Never contains secrets or cookie values."
    )
    impact: str
    remediation: str
    created_at: datetime
    updated_at: datetime

    #: The first endpoint this was observed on, when one is known.
    endpoint: EndpointRef | None = None
    #: How many endpoints the rule failed on.
    occurrence_count: int = 1
    #: Every affected endpoint. One entry even for a scan-level finding.
    occurrences: list[FindingOccurrenceRead] = []


class FindingSummary(BaseModel):
    """Counts by severity, for the scan detail header."""

    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class FindingListResponse(BaseModel):
    items: list[FindingRead]
    summary: FindingSummary
