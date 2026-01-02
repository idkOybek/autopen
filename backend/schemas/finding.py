"""Finding schemas."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from backend.models.finding import Severity, FindingStatus


class FindingBase(BaseModel):
    """Base finding schema."""

    title: str = Field(..., min_length=1, max_length=512)
    description: str
    severity: Severity
    url: str = Field(..., max_length=1024)
    parameter: Optional[str] = Field(None, max_length=255)
    method: Optional[str] = Field(None, max_length=10)
    payload: Optional[str] = None
    evidence: Optional[str] = None
    cve_id: Optional[str] = Field(None, max_length=50)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    recommendation: Optional[str] = None
    references: Optional[str] = None


class FindingCreate(FindingBase):
    """Schema for creating a finding."""

    scan_id: int
    target_id: int


class FindingUpdate(BaseModel):
    """Schema for updating a finding."""

    status: Optional[FindingStatus] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None


class FindingResponse(FindingBase):
    """Schema for finding response."""

    id: int
    scan_id: int
    target_id: int
    status: FindingStatus
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
