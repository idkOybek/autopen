"""Scan schemas."""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field

from backend.models.scan import ScanStatus


class ScanBase(BaseModel):
    """Base scan schema."""

    name: str = Field(..., min_length=1, max_length=255)
    pipeline_config: Dict[str, Any] = Field(default_factory=dict)


class ScanCreate(ScanBase):
    """Schema for creating a scan."""

    pass


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[ScanStatus] = None
    pipeline_config: Optional[Dict[str, Any]] = None
    total_targets: Optional[int] = None
    completed_targets: Optional[int] = None
    failed_targets: Optional[int] = None
    total_findings: Optional[int] = None
    critical_findings: Optional[int] = None
    high_findings: Optional[int] = None
    medium_findings: Optional[int] = None
    low_findings: Optional[int] = None
    risk_score: Optional[float] = None
    error_count: Optional[int] = None


class ScanResponse(ScanBase):
    """Schema for scan response."""

    id: uuid.UUID
    status: ScanStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_targets: int
    completed_targets: int
    failed_targets: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    risk_score: Optional[float] = None
    error_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
