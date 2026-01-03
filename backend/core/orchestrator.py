"""
Main orchestrator for managing scan execution lifecycle.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from celery import group, chord
from celery.result import AsyncResult, GroupResult
from loguru import logger
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.config import settings
from backend.core.database import get_db
from backend.core.state_manager import StateManager
from backend.integrations.ftp_client import FTPClient
from backend.models.scan import Scan, ScanStatus
from backend.models.target import Target, TargetStatus
from backend.tasks.scan_tasks import (
    process_targets,
    scan_single_target,
    generate_final_reports,
)


class ScanOrchestrator:
    """
    Main orchestrator for coordinating scan execution.

    Manages the complete scan lifecycle:
    1. Initialization and validation
    2. Target acquisition from FTP
    3. Target processing (blacklist, dedup, classify)
    4. Parallel scan execution
    5. Result aggregation
    6. Report generation
    7. Error handling and recovery
    """

    def __init__(self):
        """Initialize orchestrator."""
        self.state_manager = StateManager()
        self.ftp_client = FTPClient()
        self._active_scans: Dict[str, GroupResult] = {}

    async def start_scan(
        self, scan_id: str, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Start a complete scan execution.

        Args:
            scan_id: UUID of the scan to execute
            config: Scan configuration including:
                - pipeline: Pipeline stages and scanners
                - ftp_path: Path to targets file on FTP
                - blacklist_enabled: Whether to filter blacklisted targets
                - parallel_workers: Number of parallel workers

        Returns:
            Dict with scan status and task information

        Raises:
            ValueError: If scan not found or invalid configuration
            Exception: For other errors during scan initialization
        """
        logger.info(f"Starting scan {scan_id}")

        try:
            async for db in get_db():
                # Stage 1: Initialize and validate
                scan = await self._initialize_scan(db, scan_id, config)

                # Stage 2: Fetch targets from FTP
                raw_targets = await self._fetch_targets(config)

                if not raw_targets:
                    raise ValueError("No targets found in FTP file")

                logger.info(f"Loaded {len(raw_targets)} raw targets")

                # Stage 3: Process targets (async task)
                logger.info("Processing targets (blacklist, dedup, classify)")

                process_task = process_targets.delay(
                    scan_id=scan_id,
                    raw_targets=raw_targets,
                    blacklist_enabled=config.get("blacklist_enabled", True),
                )

                # Wait for target processing to complete
                processed_targets = process_task.get(timeout=600)  # 10 min timeout

                # Stage 4: Launch scan tasks for all targets
                scan_tasks = []

                for target_type, targets in processed_targets.items():
                    logger.info(
                        f"Scheduling {len(targets)} {target_type} targets for scanning"
                    )

                    for target in targets:
                        task = scan_single_target.delay(
                            scan_id=scan_id,
                            target_data=target,
                            pipeline_config=config.get("pipeline", {}),
                        )
                        scan_tasks.append(task)

                # Create chord: all scans -> final report
                if scan_tasks:
                    # Group all scan tasks
                    scan_group = group(scan_tasks)

                    # Create chord with report generation as callback
                    workflow = chord(scan_group)(
                        generate_final_reports.s(scan_id=scan_id)
                    )

                    # Store task group for monitoring
                    self._active_scans[scan_id] = workflow

                    # Update scan status
                    scan.status = ScanStatus.RUNNING
                    scan.started_at = datetime.utcnow()
                    await db.commit()

                    logger.info(
                        f"Scan {scan_id} started with {len(scan_tasks)} target tasks"
                    )

                    # Start monitoring in background
                    asyncio.create_task(self._monitor_scan(scan_id, workflow))

                    return {
                        "scan_id": scan_id,
                        "status": "running",
                        "total_tasks": len(scan_tasks),
                        "task_id": workflow.id,
                    }
                else:
                    # No targets to scan
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    await db.commit()

                    logger.warning(f"Scan {scan_id} has no targets to scan")

                    return {
                        "scan_id": scan_id,
                        "status": "completed",
                        "total_tasks": 0,
                        "message": "No targets to scan",
                    }

        except Exception as e:
            logger.error(f"Error starting scan {scan_id}: {e}", exc_info=True)
            await self._handle_scan_error(scan_id, e)
            raise

    async def stop_scan(self, scan_id: str) -> Dict[str, Any]:
        """
        Stop a running scan.

        Args:
            scan_id: UUID of the scan to stop

        Returns:
            Dict with stop status
        """
        logger.info(f"Stopping scan {scan_id}")

        try:
            async for db in get_db():
                scan = await db.get(Scan, UUID(scan_id))
                if not scan:
                    raise ValueError(f"Scan {scan_id} not found")

                if scan.status not in [ScanStatus.RUNNING, ScanStatus.PAUSED]:
                    return {
                        "scan_id": scan_id,
                        "status": "already_stopped",
                        "current_status": scan.status.value,
                    }

                # Revoke all pending tasks
                if scan_id in self._active_scans:
                    workflow = self._active_scans[scan_id]
                    workflow.revoke(terminate=True)
                    del self._active_scans[scan_id]

                # Update scan status
                scan.status = ScanStatus.STOPPED
                scan.completed_at = datetime.utcnow()
                await db.commit()

                # Update all pending/in-progress targets
                await db.execute(
                    Target.__table__.update()
                    .where(
                        and_(
                            Target.scan_id == UUID(scan_id),
                            Target.status.in_(
                                [TargetStatus.PENDING, TargetStatus.IN_PROGRESS]
                            ),
                        )
                    )
                    .values(status=TargetStatus.FAILED, error_message="Scan stopped by user")
                )
                await db.commit()

                logger.info(f"Scan {scan_id} stopped successfully")

                return {
                    "scan_id": scan_id,
                    "status": "stopped",
                    "stopped_at": datetime.utcnow().isoformat(),
                }

        except Exception as e:
            logger.error(f"Error stopping scan {scan_id}: {e}", exc_info=True)
            raise

    async def pause_scan(self, scan_id: str) -> Dict[str, Any]:
        """
        Pause a running scan.

        Args:
            scan_id: UUID of the scan to pause

        Returns:
            Dict with pause status
        """
        logger.info(f"Pausing scan {scan_id}")

        try:
            async for db in get_db():
                scan = await db.get(Scan, UUID(scan_id))
                if not scan:
                    raise ValueError(f"Scan {scan_id} not found")

                if scan.status != ScanStatus.RUNNING:
                    return {
                        "scan_id": scan_id,
                        "status": "cannot_pause",
                        "current_status": scan.status.value,
                    }

                # Set pause flag in state manager
                await self.state_manager.connect()
                await self.state_manager.set_state(
                    f"scan:{scan_id}:paused", "true", ttl=86400
                )

                # Update scan status
                scan.status = ScanStatus.PAUSED
                await db.commit()

                logger.info(f"Scan {scan_id} paused")

                return {
                    "scan_id": scan_id,
                    "status": "paused",
                    "paused_at": datetime.utcnow().isoformat(),
                }

        except Exception as e:
            logger.error(f"Error pausing scan {scan_id}: {e}", exc_info=True)
            raise
        finally:
            await self.state_manager.disconnect()

    async def resume_scan(self, scan_id: str) -> Dict[str, Any]:
        """
        Resume a paused scan.

        Args:
            scan_id: UUID of the scan to resume

        Returns:
            Dict with resume status
        """
        logger.info(f"Resuming scan {scan_id}")

        try:
            async for db in get_db():
                scan = await db.get(Scan, UUID(scan_id))
                if not scan:
                    raise ValueError(f"Scan {scan_id} not found")

                if scan.status != ScanStatus.PAUSED:
                    return {
                        "scan_id": scan_id,
                        "status": "cannot_resume",
                        "current_status": scan.status.value,
                    }

                # Remove pause flag
                await self.state_manager.connect()
                await self.state_manager.delete_state(f"scan:{scan_id}:paused")

                # Find targets that need to be rescanned
                failed_targets_result = await db.execute(
                    select(Target).where(
                        and_(
                            Target.scan_id == UUID(scan_id),
                            Target.status.in_(
                                [TargetStatus.PENDING, TargetStatus.FAILED]
                            ),
                        )
                    )
                )
                failed_targets = failed_targets_result.scalars().all()

                # Relaunch tasks for failed/pending targets
                scan_tasks = []
                for target in failed_targets:
                    target_data = {
                        "id": str(target.id),
                        "value": target.normalized_value,
                        "type": target.target_type.value,
                        "classification": target.classification,
                    }

                    task = scan_single_target.delay(
                        scan_id=scan_id,
                        target_data=target_data,
                        pipeline_config=scan.pipeline_config,
                    )
                    scan_tasks.append(task)

                # Update scan status
                scan.status = ScanStatus.RUNNING
                await db.commit()

                logger.info(
                    f"Scan {scan_id} resumed with {len(scan_tasks)} tasks"
                )

                return {
                    "scan_id": scan_id,
                    "status": "resumed",
                    "tasks_relaunched": len(scan_tasks),
                    "resumed_at": datetime.utcnow().isoformat(),
                }

        except Exception as e:
            logger.error(f"Error resuming scan {scan_id}: {e}", exc_info=True)
            raise
        finally:
            await self.state_manager.disconnect()

    async def recover_interrupted_scans(self) -> List[Dict[str, Any]]:
        """
        Recover scans that were interrupted due to system failure.

        Called automatically on system startup.

        Returns:
            List of recovered scans with their status
        """
        logger.info("Searching for interrupted scans to recover")

        recovered = []

        try:
            async for db in get_db():
                # Find scans that were running but system crashed
                interrupted_result = await db.execute(
                    select(Scan).where(
                        Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PAUSED])
                    )
                )
                interrupted_scans = interrupted_result.scalars().all()

                for scan in interrupted_scans:
                    try:
                        logger.info(f"Recovering scan {scan.id}")

                        # Resume the scan
                        result = await self.resume_scan(str(scan.id))
                        recovered.append(result)

                    except Exception as scan_error:
                        logger.error(
                            f"Failed to recover scan {scan.id}: {scan_error}"
                        )
                        # Mark as failed
                        scan.status = ScanStatus.FAILED
                        await db.commit()

                logger.info(f"Recovered {len(recovered)} scans")
                return recovered

        except Exception as e:
            logger.error(f"Error during scan recovery: {e}", exc_info=True)
            return recovered

    async def get_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        """
        Get current progress of a scan.

        Args:
            scan_id: UUID of the scan

        Returns:
            Dict with progress information
        """
        try:
            async for db in get_db():
                scan = await db.get(Scan, UUID(scan_id))
                if not scan:
                    raise ValueError(f"Scan {scan_id} not found")

                # Count targets by status
                targets_result = await db.execute(
                    select(Target).where(Target.scan_id == UUID(scan_id))
                )
                targets = targets_result.scalars().all()

                status_counts = {
                    "pending": 0,
                    "in_progress": 0,
                    "completed": 0,
                    "failed": 0,
                }

                for target in targets:
                    status_counts[target.status.value] += 1

                total = len(targets)
                completed = status_counts["completed"] + status_counts["failed"]
                progress_pct = (completed / total * 100) if total > 0 else 0

                return {
                    "scan_id": scan_id,
                    "status": scan.status.value,
                    "total_targets": total,
                    "completed_targets": completed,
                    "progress_percentage": round(progress_pct, 2),
                    "status_breakdown": status_counts,
                    "total_findings": scan.total_findings,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "estimated_completion": None,  # Could calculate based on average time
                }

        except Exception as e:
            logger.error(f"Error getting scan progress: {e}", exc_info=True)
            raise

    # Private helper methods

    async def _initialize_scan(
        self, db: AsyncSession, scan_id: str, config: Dict[str, Any]
    ) -> Scan:
        """Initialize and validate scan."""
        scan = await db.get(Scan, UUID(scan_id))
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        if scan.status not in [ScanStatus.PENDING]:
            raise ValueError(
                f"Scan {scan_id} cannot be started (status: {scan.status})"
            )

        # Validate config
        if "pipeline" not in config:
            raise ValueError("Pipeline configuration is required")

        # Update scan with config
        scan.pipeline_config = config.get("pipeline")
        scan.status = ScanStatus.PENDING
        await db.commit()

        return scan

    async def _fetch_targets(self, config: Dict[str, Any]) -> List[str]:
        """Fetch targets from FTP server."""
        ftp_path = config.get("ftp_path")
        if not ftp_path:
            raise ValueError("FTP path is required in configuration")

        try:
            # Connect to FTP and fetch targets
            await self.ftp_client.connect()
            targets = await self.ftp_client.fetch_targets(ftp_path)
            await self.ftp_client.disconnect()

            return targets

        except Exception as e:
            logger.error(f"Error fetching targets from FTP: {e}", exc_info=True)
            raise

    async def _monitor_scan(self, scan_id: str, workflow: AsyncResult):
        """Monitor scan execution and update status."""
        try:
            # Wait for workflow to complete
            while not workflow.ready():
                await asyncio.sleep(10)  # Check every 10 seconds

            # Workflow completed
            async for db in get_db():
                scan = await db.get(Scan, UUID(scan_id))
                if scan and scan.status == ScanStatus.RUNNING:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    await db.commit()

            # Remove from active scans
            if scan_id in self._active_scans:
                del self._active_scans[scan_id]

            logger.info(f"Scan {scan_id} monitoring completed")

        except Exception as e:
            logger.error(f"Error monitoring scan {scan_id}: {e}", exc_info=True)

    async def _handle_scan_error(self, scan_id: str, error: Exception):
        """Handle scan error and update status."""
        try:
            async for db in get_db():
                scan = await db.get(Scan, UUID(scan_id))
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.utcnow()
                    await db.commit()

                logger.error(f"Scan {scan_id} failed: {error}")

        except Exception as db_error:
            logger.error(f"Failed to update scan error status: {db_error}")


# Global orchestrator instance
orchestrator = ScanOrchestrator()
