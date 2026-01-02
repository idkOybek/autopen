"""Target schemas."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, HttpUrl, EmailStr, Field


class TargetBase(BaseModel):
    """Base target schema."""

    name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., min_length=1, max_length=512)
    description: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    contact_name: Optional[str] = Field(None, max_length=255)
    is_active: bool = True


class TargetCreate(TargetBase):
    """Schema for creating a target."""

    pass


class TargetUpdate(BaseModel):
    """Schema for updating a target."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    url: Optional[str] = Field(None, min_length=1, max_length=512)
    description: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    contact_name: Optional[str] = Field(None, max_length=255)
    is_active: Optional[bool] = None


class TargetResponse(TargetBase):
    """Schema for target response."""

    id: int
    total_scans: int
    last_scan_at: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
