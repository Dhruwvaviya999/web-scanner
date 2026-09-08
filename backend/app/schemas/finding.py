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


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    code: str = Field(description="Stable identifier of the rule that produced this finding.")
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
