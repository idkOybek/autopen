"""Checkpoint schemas."""

import uuid
from datetime import datetime
from typing import Dict, Any, Optional

from pydantic import BaseModel, Field


class CheckpointBase(BaseModel):
    """Base checkpoint schema."""

    stage: str = Field(..., max_length=255)
    completed_stages: Dict[str, Any] = Field(default_factory=dict)
    state_data: Dict[str, Any] = Field(default_factory=dict)


class CheckpointCreate(CheckpointBase):
    """Schema for creating a checkpoint."""

    scan_id: uuid.UUID
    target_id: uuid.UUID


class CheckpointUpdate(BaseModel):
    """Schema for updating a checkpoint."""

    stage: Optional[str] = Field(None, max_length=255)
    completed_stages: Optional[Dict[str, Any]] = None
    state_data: Optional[Dict[str, Any]] = None


class CheckpointResponse(CheckpointBase):
    """Schema for checkpoint response."""

    id: uuid.UUID
    scan_id: uuid.UUID
    target_id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
