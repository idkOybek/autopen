"""Scan management endpoints."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from loguru import logger
from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.scan import (
    ScanCreate,
    ScanUpdate,
    ScanResponse,
    ScanDetailResponse,
    ScanStatusResponse,
    ScanStartRequest,
    ScanTargetStats,
    ScanFindingStats,
)
from backend.core.database import get_db
from backend.core.orchestrator import orchestrator
from backend.models.finding import Finding, Severity
from backend.models.scan import Scan, ScanStatus
from backend.models.target import Target, TargetStatus

router = APIRouter()


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan: ScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new scan.

    Args:
        scan: Scan creation data

    Returns:
        Created scan

    Example:
        ```json
        {
            "name": "Production Network Scan",
            "description": "Weekly security scan",
            "pipeline_config": {
                "stages": [
                    {
                        "name": "discovery",
                        "scanners": ["nmap", "masscan"]
                    }
                ]
            }
        }
        ```
    """
    try:
        new_scan = Scan(
            name=scan.name,
            description=scan.description,
            pipeline_config=scan.pipeline_config,
            status=ScanStatus.PENDING,
        )

        db.add(new_scan)
        await db.commit()
        await db.refresh(new_scan)

        logger.info(f"Created scan {new_scan.id}: {new_scan.name}")
        return new_scan

    except Exception as e:
        logger.error(f"Error creating scan: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None, description="Filter by status"),
    name_contains: Optional[str] = Query(None, description="Filter by name"),
    db: AsyncSession = Depends(get_db),
):
    """
    List all scans with optional filtering.

    Args:
        skip: Number of scans to skip
        limit: Maximum number of scans to return
        status: Filter by scan status
        name_contains: Filter by name (case-insensitive)

    Returns:
        List of scans
    """
    try:
        query = select(Scan)

        # Apply filters
        filters = []
        if status:
            try:
                filters.append(Scan.status == ScanStatus(status))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

        if name_contains:
            filters.append(Scan.name.ilike(f"%{name_contains}%"))

        if filters:
            query = query.where(and_(*filters))

        # Order by creation date (newest first)
        query = query.order_by(Scan.created_at.desc())

        # Apply pagination
        query = query.offset(skip).limit(limit)

        result = await db.execute(query)
        scans = result.scalars().all()

        return list(scans)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing scans: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list scans")


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed information about a specific scan.

    Args:
        scan_id: UUID of the scan

    Returns:
        Detailed scan information
    """
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get target statistics
        target_stats_result = await db.execute(
            select(Target.status, func.count(Target.id))
            .where(Target.scan_id == scan_id)
            .group_by(Target.status)
        )
        target_stats_raw = dict(target_stats_result.all())

        target_stats = ScanTargetStats(
            pending=target_stats_raw.get(TargetStatus.PENDING, 0),
            in_progress=target_stats_raw.get(TargetStatus.IN_PROGRESS, 0),
            completed=target_stats_raw.get(TargetStatus.COMPLETED, 0),
            failed=target_stats_raw.get(TargetStatus.FAILED, 0),
        )

        # Get finding statistics
        finding_stats_result = await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.severity)
        )
        finding_stats_raw = dict(finding_stats_result.all())

        finding_stats = ScanFindingStats(
            critical=finding_stats_raw.get(Severity.CRITICAL, 0),
            high=finding_stats_raw.get(Severity.HIGH, 0),
            medium=finding_stats_raw.get(Severity.MEDIUM, 0),
            low=finding_stats_raw.get(Severity.LOW, 0),
            info=finding_stats_raw.get(Severity.INFO, 0),
        )

        # Calculate duration and progress
        duration = None
        if scan.started_at and scan.completed_at:
            duration = (scan.completed_at - scan.started_at).total_seconds()

        total_targets = sum(
            [target_stats.pending, target_stats.in_progress, target_stats.completed, target_stats.failed]
        )
        completed_targets = target_stats.completed + target_stats.failed
        progress = (completed_targets / total_targets * 100) if total_targets > 0 else 0

        return ScanDetailResponse(
            id=scan.id,
            name=scan.name,
            description=scan.description,
            status=scan.status.value,
            pipeline_config=scan.pipeline_config,
            total_targets=scan.total_targets,
            total_findings=scan.total_findings,
            target_stats=target_stats,
            finding_stats=finding_stats,
            created_at=scan.created_at,
            updated_at=scan.updated_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            duration=duration,
            progress_percentage=round(progress, 2),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get scan")


@router.post("/{scan_id}/start")
async def start_scan(
    scan_id: UUID,
    request: Optional[ScanStartRequest] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Start a scan execution.

    Args:
        scan_id: UUID of the scan
        request: Optional scan configuration

    Returns:
        Scan start status
    """
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.status not in [ScanStatus.PENDING]:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot start scan in status: {scan.status.value}"
            )

        # Prepare config
        config = {
            "pipeline": scan.pipeline_config,
            "blacklist_enabled": True,
            "parallel_workers": 10,
        }

        if request and request.config:
            config.update(request.config.model_dump())

        # Start scan via orchestrator
        result = await orchestrator.start_scan(str(scan_id), config)

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")


@router.post("/{scan_id}/stop")
async def stop_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Stop a running scan.

    Args:
        scan_id: UUID of the scan

    Returns:
        Stop status
    """
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        result = await orchestrator.stop_scan(str(scan_id))
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to stop scan: {str(e)}")


@router.post("/{scan_id}/pause")
async def pause_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Pause a running scan.

    Args:
        scan_id: UUID of the scan

    Returns:
        Pause status
    """
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        result = await orchestrator.pause_scan(str(scan_id))
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error pausing scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to pause scan: {str(e)}")


@router.post("/{scan_id}/resume")
async def resume_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Resume a paused scan.

    Args:
        scan_id: UUID of the scan

    Returns:
        Resume status
    """
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        result = await orchestrator.resume_scan(str(scan_id))
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resuming scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to resume scan: {str(e)}")


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Get real-time scan status and progress.

    Args:
        scan_id: UUID of the scan

    Returns:
        Current scan status
    """
    try:
        result = await orchestrator.get_scan_progress(str(scan_id))
        return result

    except Exception as e:
        logger.error(f"Error getting scan status {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get scan status")


@router.websocket("/{scan_id}/logs")
async def scan_logs_websocket(
    websocket: WebSocket,
    scan_id: UUID,
):
    """
    WebSocket endpoint for streaming scan logs.

    Args:
        websocket: WebSocket connection
        scan_id: UUID of the scan
    """
    await websocket.accept()

    try:
        # TODO: Implement log streaming from Redis or file
        # For now, send a welcome message
        await websocket.send_json({
            "type": "info",
            "message": f"Connected to scan {scan_id} logs",
            "timestamp": datetime.utcnow().isoformat()
        })

        # Keep connection alive
        while True:
            # Wait for client messages (ping/pong)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
        await websocket.close()


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a scan and all associated data.

    Args:
        scan_id: UUID of the scan

    Returns:
        No content
    """
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Prevent deletion of running scans
        if scan.status in [ScanStatus.RUNNING, ScanStatus.PENDING]:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete running or pending scan. Stop it first."
            )

        await db.delete(scan)
        await db.commit()

        logger.info(f"Deleted scan {scan_id}")
        return None

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete scan")


@router.patch("/{scan_id}", response_model=ScanResponse)
async def update_scan(
    scan_id: UUID,
    scan_update: ScanUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Update scan information.

    Args:
        scan_id: UUID of the scan
        scan_update: Fields to update

    Returns:
        Updated scan
    """
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Update fields
        update_data = scan_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(scan, field, value)

        await db.commit()
        await db.refresh(scan)

        logger.info(f"Updated scan {scan_id}")
        return scan

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating scan {scan_id}: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update scan")
