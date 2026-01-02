"""Blacklist endpoints."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_session

router = APIRouter()


class BlacklistCreate(BaseModel):
    """Schema for creating a blacklist entry."""

    pattern: str
    description: str | None = None
    reason: str | None = None
    is_active: bool = True


class BlacklistResponse(BaseModel):
    """Schema for blacklist response."""

    id: int
    pattern: str
    description: str | None
    reason: str | None
    is_active: bool

    class Config:
        from_attributes = True


@router.post("/", response_model=BlacklistResponse, status_code=201)
async def create_blacklist_entry(
    entry: BlacklistCreate,
    db: AsyncSession = Depends(get_session)
) -> BlacklistResponse:
    """Create a new blacklist entry."""
    # TODO: Implement blacklist creation logic
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/", response_model=List[BlacklistResponse])
async def list_blacklist(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = False,
    db: AsyncSession = Depends(get_session)
) -> List[BlacklistResponse]:
    """List all blacklist entries."""
    # TODO: Implement blacklist listing logic
    return []


@router.delete("/{entry_id}", status_code=204)
async def delete_blacklist_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_session)
) -> None:
    """Delete a blacklist entry."""
    # TODO: Implement blacklist deletion logic
    raise HTTPException(status_code=501, detail="Not implemented yet")
