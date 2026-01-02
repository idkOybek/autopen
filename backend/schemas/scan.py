"""Scan schemas."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from backend.models.scan import ScanStatus, ScanType


class ScanBase(BaseModel):
    """Base scan schema."""

    target_id: int
    scan_type: ScanType = ScanType.FULL
    depth: int = Field(default=3, ge=1, le=10)
    timeout: int = Field(default=3600, ge=60, le=7200)


class ScanCreate(ScanBase):
    """Schema for creating a scan."""

    pass


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""

    status: Optional[ScanStatus] = None
    error_message: Optional[str] = None
    total_findings: Optional[int] = None
    critical_findings: Optional[int] = None
    high_findings: Optional[int] = None
    medium_findings: Optional[int] = None
    low_findings: Optional[int] = None
    info_findings: Optional[int] = None


class ScanResponse(ScanBase):
    """Schema for scan response."""

    id: int
    status: ScanStatus
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    celery_task_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
