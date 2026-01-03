"""Blacklist management endpoints."""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.blacklist import (
    BlacklistCreate,
    BlacklistUpdate,
    BlacklistResponse,
    BlacklistCheck,
    BlacklistCheckResponse,
    BlacklistStats,
)
from backend.core.blacklist_manager import BlacklistManager
from backend.core.database import get_db
from backend.models.blacklist import BlacklistEntry, BlacklistEntryType

router = APIRouter()


@router.get("/", response_model=List[BlacklistResponse])
async def list_blacklist(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    entry_type: Optional[str] = Query(None, description="Filter by entry type"),
    active_only: bool = Query(True, description="Show only active entries"),
    db: AsyncSession = Depends(get_db),
):
    """List blacklist entries."""
    try:
        from datetime import datetime

        query = select(BlacklistEntry)

        # Apply filters
        filters = []

        if entry_type:
            try:
                filters.append(BlacklistEntry.entry_type == BlacklistEntryType(entry_type))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid entry type: {entry_type}")

        if active_only:
            # Filter out expired entries
            from sqlalchemy import or_
            filters.append(
                or_(
                    BlacklistEntry.expires_at.is_(None),
                    BlacklistEntry.expires_at > datetime.utcnow()
                )
            )

        if filters:
            from sqlalchemy import and_
            query = query.where(and_(*filters))

        query = query.order_by(BlacklistEntry.created_at.desc())
        query = query.offset(skip).limit(limit)

        result = await db.execute(query)
        entries = result.scalars().all()

        return list(entries)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing blacklist: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list blacklist")


@router.post("/", response_model=BlacklistResponse, status_code=201)
async def add_to_blacklist(
    entry: BlacklistCreate,
    db: AsyncSession = Depends(get_db),
):
    """Add entry to blacklist."""
    try:
        new_entry = BlacklistEntry(
            value=entry.value,
            entry_type=entry.entry_type_enum,
            reason=entry.reason,
            expires_at=entry.expires_at,
        )

        db.add(new_entry)
        await db.commit()
        await db.refresh(new_entry)

        logger.info(f"Added {entry.entry_type} to blacklist: {entry.value}")
        return new_entry

    except Exception as e:
        logger.error(f"Error adding to blacklist: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to add to blacklist: {str(e)}")


@router.delete("/{entry_id}", status_code=204)
async def remove_from_blacklist(
    entry_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Remove entry from blacklist."""
    try:
        entry = await db.get(BlacklistEntry, entry_id)
        if not entry:
            raise HTTPException(status_code=404, detail="Blacklist entry not found")

        await db.delete(entry)
        await db.commit()

        logger.info(f"Removed from blacklist: {entry.value}")
        return None

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing from blacklist: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to remove from blacklist")


@router.post("/check", response_model=BlacklistCheckResponse)
async def check_blacklist(
    check: BlacklistCheck,
    db: AsyncSession = Depends(get_db),
):
    """Check if a target is blacklisted."""
    try:
        manager = BlacklistManager()
        await manager.load_blacklist(db)

        is_blacklisted, reason = await manager.is_blacklisted(check.target)

        matched_entry = None
        if is_blacklisted:
            result = await db.execute(
                select(BlacklistEntry).where(BlacklistEntry.value == check.target)
            )
            entry = result.scalar_one_or_none()
            if entry:
                matched_entry = entry.id

        return BlacklistCheckResponse(
            target=check.target,
            blacklisted=is_blacklisted,
            reason=reason if is_blacklisted else None,
            matched_entry=matched_entry,
        )

    except Exception as e:
        logger.error(f"Error checking blacklist: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Blacklist check failed: {str(e)}")


@router.get("/stats", response_model=BlacklistStats)
async def blacklist_stats(
    db: AsyncSession = Depends(get_db),
):
    """Get blacklist statistics."""
    try:
        from datetime import datetime
        from sqlalchemy import or_

        total_result = await db.execute(select(func.count(BlacklistEntry.id)))
        total_entries = total_result.scalar_one()

        active_result = await db.execute(
            select(func.count(BlacklistEntry.id)).where(
                or_(
                    BlacklistEntry.expires_at.is_(None),
                    BlacklistEntry.expires_at > datetime.utcnow()
                )
            )
        )
        active_entries = active_result.scalar_one()

        expired_entries = total_entries - active_entries

        by_type_result = await db.execute(
            select(
                BlacklistEntry.entry_type,
                func.count(BlacklistEntry.id)
            ).group_by(BlacklistEntry.entry_type)
        )
        by_type = {str(entry_type.value): count for entry_type, count in by_type_result.all()}

        return BlacklistStats(
            total_entries=total_entries,
            active_entries=active_entries,
            expired_entries=expired_entries,
            by_type=by_type,
        )

    except Exception as e:
        logger.error(f"Error getting blacklist stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get blacklist stats")
