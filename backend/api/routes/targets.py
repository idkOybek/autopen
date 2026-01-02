"""Target endpoints."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_session
from backend.schemas.target import TargetCreate, TargetUpdate, TargetResponse

router = APIRouter()


@router.post("/", response_model=TargetResponse, status_code=201)
async def create_target(
    target: TargetCreate,
    db: AsyncSession = Depends(get_session)
) -> TargetResponse:
    """Create a new target."""
    # TODO: Implement target creation logic
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/", response_model=List[TargetResponse])
async def list_targets(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = False,
    db: AsyncSession = Depends(get_session)
) -> List[TargetResponse]:
    """List all targets."""
    # TODO: Implement target listing logic
    return []


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: int,
    db: AsyncSession = Depends(get_session)
) -> TargetResponse:
    """Get target by ID."""
    # TODO: Implement target retrieval logic
    raise HTTPException(status_code=404, detail="Target not found")


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: int,
    target: TargetUpdate,
    db: AsyncSession = Depends(get_session)
) -> TargetResponse:
    """Update a target."""
    # TODO: Implement target update logic
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    target_id: int,
    db: AsyncSession = Depends(get_session)
) -> None:
    """Delete a target."""
    # TODO: Implement target deletion logic
    raise HTTPException(status_code=501, detail="Not implemented yet")
