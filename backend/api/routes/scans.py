"""Scan endpoints."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_session
from backend.schemas.scan import ScanCreate, ScanResponse

router = APIRouter()


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan: ScanCreate,
    db: AsyncSession = Depends(get_session)
) -> ScanResponse:
    """Create a new scan."""
    # TODO: Implement scan creation logic
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_session)
) -> List[ScanResponse]:
    """List all scans."""
    # TODO: Implement scan listing logic
    return []


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_session)
) -> ScanResponse:
    """Get scan by ID."""
    # TODO: Implement scan retrieval logic
    raise HTTPException(status_code=404, detail="Scan not found")


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_session)
) -> None:
    """Delete a scan."""
    # TODO: Implement scan deletion logic
    raise HTTPException(status_code=501, detail="Not implemented yet")
