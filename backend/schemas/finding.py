"""Finding schemas."""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field

from backend.models.finding import Severity, RemediationEffort


class FindingBase(BaseModel):
    """Base finding schema."""

    title: str = Field(..., min_length=1, max_length=512)
    description: str
    severity: Severity
    finding_type: str = Field(..., max_length=255)
    category: str = Field(..., max_length=255)


class FindingCreate(BaseModel):
    """Schema for creating a finding."""

    scan_id: uuid.UUID
    target_id: uuid.UUID
    title: str = Field(..., min_length=1, max_length=512)
    description: str
    severity: Severity
    finding_type: str = Field(..., max_length=255)
    category: str = Field(..., max_length=255)
    cwe_id: Optional[str] = Field(None, max_length=50)
    cve_id: Optional[str] = Field(None, max_length=50)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    affected_component: str = Field(..., max_length=512)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    remediation_effort: RemediationEffort
    remediation_priority: int = Field(..., ge=1, le=10)
    tool: str = Field(..., max_length=255)
    confidence: int = Field(..., ge=0, le=100)
    false_positive_probability: Optional[float] = Field(None, ge=0.0, le=1.0)
    fingerprint: str = Field(..., max_length=255)
    sources: Dict[str, Any] = Field(default_factory=dict)


class FindingUpdate(BaseModel):
    """Schema for updating a finding."""

    description: Optional[str] = None
    remediation: Optional[str] = None
    remediation_effort: Optional[RemediationEffort] = None
    remediation_priority: Optional[int] = Field(None, ge=1, le=10)


class FindingResponse(FindingBase):
    """Schema for finding response."""

    id: uuid.UUID
    scan_id: uuid.UUID
    target_id: uuid.UUID
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_component: str
    evidence: Dict[str, Any]
    remediation: Optional[str] = None
    remediation_effort: RemediationEffort
    remediation_priority: int
    tool: str
    confidence: int
    false_positive_probability: Optional[float] = None
    fingerprint: str
    sources: Dict[str, Any]
    discovered_at: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
