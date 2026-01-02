"""Target schemas."""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field

from backend.models.target import TargetType, TargetStatus


class TargetBase(BaseModel):
    """Base target schema."""

    raw_value: str = Field(..., min_length=1, max_length=1024)
    normalized_value: str = Field(..., min_length=1, max_length=1024)
    target_type: TargetType
    classification: Dict[str, Any] = Field(default_factory=dict)


class TargetCreate(BaseModel):
    """Schema for creating a target."""

    scan_id: uuid.UUID
    raw_value: str = Field(..., min_length=1, max_length=1024)
    normalized_value: str = Field(..., min_length=1, max_length=1024)
    target_type: TargetType
    classification: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TargetUpdate(BaseModel):
    """Schema for updating a target."""

    status: Optional[TargetStatus] = None
    current_stage: Optional[str] = Field(None, max_length=255)
    findings_count: Optional[int] = None
    risk_score: Optional[float] = None
    blacklisted: Optional[bool] = None
    blacklist_reason: Optional[str] = Field(None, max_length=512)
    individual_report_path: Optional[str] = Field(None, max_length=512)
    metadata: Optional[Dict[str, Any]] = None
    error_log: Optional[Dict[str, Any]] = None


class TargetResponse(TargetBase):
    """Schema for target response."""

    id: uuid.UUID
    scan_id: uuid.UUID
    status: TargetStatus
    current_stage: Optional[str] = None
    findings_count: int
    risk_score: Optional[float] = None
    blacklisted: bool
    blacklist_reason: Optional[str] = None
    scan_started_at: Optional[datetime] = None
    scan_completed_at: Optional[datetime] = None
    individual_report_path: Optional[str] = None
    metadata: Dict[str, Any]
    error_log: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
