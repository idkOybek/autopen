"""Target API schemas."""

from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class TargetClassification(BaseModel):
    """Target classification result."""

    raw_value: str
    normalized_value: str
    target_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    classification: Dict
    recommended_tools: List[str]


class TargetValidation(BaseModel):
    """Target validation result."""

    target: str
    valid: bool
    errors: List[str] = []
    warnings: List[str] = []


class TargetResponse(BaseModel):
    """Target response schema."""

    id: UUID
    scan_id: UUID
    raw_value: str
    normalized_value: str
    target_type: str
    status: str
    classification: Dict
    blacklisted: bool
    created_at: datetime
    scanned_at: Optional[datetime]
    error_message: Optional[str]

    class Config:
        from_attributes = True


class TargetClassifyRequest(BaseModel):
    """Classify targets request."""

    targets: List[str] = Field(..., min_length=1, max_length=1000)


class TargetValidateRequest(BaseModel):
    """Validate targets request."""

    targets: List[str] = Field(..., min_length=1, max_length=1000)


class TargetUploadResponse(BaseModel):
    """Target upload response."""

    total_uploaded: int
    valid_targets: int
    invalid_targets: int
    errors: List[str] = []
