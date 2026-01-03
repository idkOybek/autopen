"""Blacklist API schemas."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class BlacklistCreate(BaseModel):
    """Create blacklist entry."""

    value: str = Field(..., min_length=1, max_length=1024, description="Target value to blacklist")
    entry_type: str = Field(..., description="Entry type: ip, domain, network, pattern")
    reason: Optional[str] = Field(None, max_length=2048, description="Reason for blacklisting")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp (optional)")

    @property
    def entry_type_enum(self):
        """Convert to enum value."""
        from backend.models.blacklist import BlacklistEntryType
        return BlacklistEntryType(self.entry_type)


class BlacklistUpdate(BaseModel):
    """Update blacklist entry."""

    reason: Optional[str] = Field(None, max_length=2048)
    expires_at: Optional[datetime] = None


class BlacklistResponse(BaseModel):
    """Blacklist entry response."""

    id: UUID
    value: str
    entry_type: str
    reason: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool

    class Config:
        from_attributes = True


class BlacklistCheck(BaseModel):
    """Check if target is blacklisted."""

    target: str = Field(..., min_length=1, max_length=1024)


class BlacklistCheckResponse(BaseModel):
    """Blacklist check response."""

    target: str
    blacklisted: bool
    reason: Optional[str]
    matched_entry: Optional[UUID]


class BlacklistStats(BaseModel):
    """Blacklist statistics."""

    total_entries: int
    active_entries: int
    expired_entries: int
    by_type: dict = Field(default_factory=dict)
