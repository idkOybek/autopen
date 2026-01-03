"""Health check and monitoring endpoints."""

import asyncio
import psutil
from datetime import datetime, timedelta
from typing import Dict

from fastapi import APIRouter, Depends
from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.health import (
    HealthResponse,
    ReadinessResponse,
    MetricsResponse,
    ServiceStatus,
    SystemMetrics,
    WorkloadMetrics,
)
from backend.core.config import settings
from backend.core.database import get_db
from backend.core.state_manager import StateManager
from backend.models.scan import Scan, ScanStatus

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Basic health check endpoint.

    Returns service status and timestamp. Always returns 200 OK unless
    the service is completely down.

    Returns:
        HealthResponse: Basic health status
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow(),
        version=settings.VERSION,
    )


@router.get("/readiness", response_model=ReadinessResponse)
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """
    Readiness check for container orchestration.

    Checks availability of critical dependencies:
    - PostgreSQL database
    - Redis cache
    - Celery workers

    Returns:
        ReadinessResponse: Detailed readiness status

    Example:
        ```json
        {
            "ready": true,
            "services": {
                "database": {"available": true, "latency_ms": 5.2},
                "redis": {"available": true, "latency_ms": 1.3},
                "celery": {"available": true}
            },
            "timestamp": "2024-01-01T00:00:00Z"
        }
        ```
    """
    services: Dict[str, ServiceStatus] = {}
    all_ready = True

    # Check PostgreSQL
    try:
        start = datetime.utcnow()
        await db.execute(text("SELECT 1"))
        latency = (datetime.utcnow() - start).total_seconds() * 1000
        services["database"] = ServiceStatus(available=True, latency_ms=latency)
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        services["database"] = ServiceStatus(available=False, error=str(e))
        all_ready = False

    # Check Redis
    try:
        state_manager = StateManager()
        start = datetime.utcnow()
        await state_manager.connect()
        await state_manager.redis.ping()
        latency = (datetime.utcnow() - start).total_seconds() * 1000
        await state_manager.disconnect()
        services["redis"] = ServiceStatus(available=True, latency_ms=latency)
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        services["redis"] = ServiceStatus(available=False, error=str(e))
        all_ready = False

    # Check Celery workers
    try:
        from backend.tasks.celery_app import celery_app

        # Inspect active workers
        inspector = celery_app.control.inspect()
        active_workers = inspector.active()

        if active_workers and len(active_workers) > 0:
            services["celery"] = ServiceStatus(available=True)
        else:
            services["celery"] = ServiceStatus(
                available=False, error="No active workers"
            )
            all_ready = False
    except Exception as e:
        logger.error(f"Celery health check failed: {e}")
        services["celery"] = ServiceStatus(available=False, error=str(e))
        all_ready = False

    return ReadinessResponse(
        ready=all_ready,
        services=services,
        timestamp=datetime.utcnow(),
    )


@router.get("/metrics", response_model=MetricsResponse)
async def get_metrics(db: AsyncSession = Depends(get_db)):
    """
    Get system and workload metrics.

    Returns:
        MetricsResponse: System resource usage and workload statistics

    Example:
        ```json
        {
            "system": {
                "cpu_percent": 45.2,
                "memory_percent": 62.8,
                "disk_percent": 35.1
            },
            "workload": {
                "active_scans": 3,
                "queued_tasks": 15,
                "completed_scans_24h": 42,
                "failed_scans_24h": 2
            },
            "timestamp": "2024-01-01T00:00:00Z"
        }
        ```
    """
    # Get system metrics
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    system_metrics = SystemMetrics(
        cpu_percent=cpu_percent,
        memory_percent=memory.percent,
        disk_percent=disk.percent,
    )

    # Get workload metrics
    try:
        # Count active scans
        from sqlalchemy import select, and_

        active_scans_result = await db.execute(
            select(Scan).where(
                Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING])
            )
        )
        active_scans = len(active_scans_result.scalars().all())

        # Count completed scans in last 24 hours
        yesterday = datetime.utcnow() - timedelta(hours=24)
        completed_result = await db.execute(
            select(Scan).where(
                and_(
                    Scan.status == ScanStatus.COMPLETED,
                    Scan.completed_at >= yesterday,
                )
            )
        )
        completed_24h = len(completed_result.scalars().all())

        # Count failed scans in last 24 hours
        failed_result = await db.execute(
            select(Scan).where(
                and_(
                    Scan.status == ScanStatus.FAILED,
                    Scan.completed_at >= yesterday,
                )
            )
        )
        failed_24h = len(failed_result.scalars().all())

        # Get queued tasks count from Celery
        queued_tasks = 0
        try:
            from backend.tasks.celery_app import celery_app

            inspector = celery_app.control.inspect()
            reserved = inspector.reserved()
            if reserved:
                queued_tasks = sum(len(tasks) for tasks in reserved.values())
        except Exception as e:
            logger.warning(f"Could not get Celery queue length: {e}")

        workload_metrics = WorkloadMetrics(
            active_scans=active_scans,
            queued_tasks=queued_tasks,
            completed_scans_24h=completed_24h,
            failed_scans_24h=failed_24h,
        )

    except Exception as e:
        logger.error(f"Error getting workload metrics: {e}")
        workload_metrics = WorkloadMetrics(
            active_scans=0,
            queued_tasks=0,
            completed_scans_24h=0,
            failed_scans_24h=0,
        )

    return MetricsResponse(
        system=system_metrics,
        workload=workload_metrics,
        timestamp=datetime.utcnow(),
    )


@router.get("/ping")
async def ping():
    """
    Simple ping endpoint for load balancer health checks.

    Returns:
        dict: Simple pong response
    """
    return {"ping": "pong", "timestamp": datetime.utcnow().isoformat()}
