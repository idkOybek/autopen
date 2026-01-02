"""Blacklist schemas."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from backend.models.blacklist import BlacklistEntryType


class BlacklistEntryBase(BaseModel):
    """Base blacklist entry schema."""

    entry_type: BlacklistEntryType
    value: str = Field(..., min_length=1, max_length=512)
    reason: str
    source: str = Field(..., max_length=255)
    severity: str = Field(..., max_length=50)


class BlacklistEntryCreate(BlacklistEntryBase):
    """Schema for creating a blacklist entry."""

    active: bool = True
    expires_at: Optional[datetime] = None


class BlacklistEntryUpdate(BaseModel):
    """Schema for updating a blacklist entry."""

    reason: Optional[str] = None
    active: Optional[bool] = None
    expires_at: Optional[datetime] = None


class BlacklistEntryResponse(BlacklistEntryBase):
    """Schema for blacklist entry response."""

    id: uuid.UUID
    active: bool
    expires_at: Optional[datetime] = None
    hit_count: int
    last_hit: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
