"""
Recovery manager for handling interrupted scans and system failures.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import UUID

from loguru import logger
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import get_db
from backend.core.state_manager import StateManager
from backend.models.checkpoint import Checkpoint
from backend.models.scan import Scan, ScanStatus
from backend.models.target import Target, TargetStatus


class RecoveryManager:
    """
    Manages recovery of interrupted scans and validation of checkpoints.

    Automatically detects and recovers scans that were interrupted due to:
    - System crashes
    - Worker failures
    - Network issues
    - Unexpected terminations
    """

    def __init__(self):
        """Initialize recovery manager."""
        self.state_manager = StateManager()

    async def find_interrupted_scans(
        self, max_age_hours: int = 24
    ) -> List[Scan]:
        """
        Find scans that were interrupted and need recovery.

        Args:
            max_age_hours: Maximum age of scans to consider (default: 24 hours)

        Returns:
            List of interrupted scans
        """
        logger.info("Searching for interrupted scans")

        try:
            async for db in get_db():
                cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)

                # Find scans that are stuck in RUNNING or PAUSED status
                interrupted_result = await db.execute(
                    select(Scan).where(
                        and_(
                            Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PAUSED]),
                            Scan.started_at >= cutoff_time,
                        )
                    )
                )
                interrupted_scans = interrupted_result.scalars().all()

                logger.info(f"Found {len(interrupted_scans)} interrupted scans")
                return list(interrupted_scans)

        except Exception as e:
            logger.error(f"Error finding interrupted scans: {e}", exc_info=True)
            return []

    async def recover_scan(self, scan_id: str) -> bool:
        """
        Attempt to recover an interrupted scan.

        Args:
            scan_id: UUID of the scan to recover

        Returns:
            True if recovery successful, False otherwise
        """
        logger.info(f"Attempting to recover scan {scan_id}")

        try:
            async for db in get_db():
                scan = await db.get(Scan, UUID(scan_id))
                if not scan:
                    logger.error(f"Scan {scan_id} not found")
                    return False

                # Get all checkpoints for this scan
                checkpoints_result = await db.execute(
                    select(Checkpoint)
                    .where(Checkpoint.scan_id == UUID(scan_id))
                    .order_by(Checkpoint.created_at.desc())
                )
                checkpoints = checkpoints_result.scalars().all()

                if not checkpoints:
                    logger.warning(f"No checkpoints found for scan {scan_id}")
                    # Try to recover without checkpoints
                    return await self._recover_without_checkpoints(db, scan)

                # Validate and use most recent checkpoint
                latest_checkpoint = checkpoints[0]

                if not await self.validate_checkpoint(latest_checkpoint.__dict__):
                    logger.error(
                        f"Checkpoint validation failed for scan {scan_id}"
                    )
                    return False

                # Resume from checkpoint
                success = await self.resume_from_checkpoint(
                    scan_id, latest_checkpoint
                )

                if success:
                    logger.info(f"Successfully recovered scan {scan_id}")
                else:
                    logger.error(f"Failed to recover scan {scan_id}")

                return success

        except Exception as e:
            logger.error(f"Error recovering scan {scan_id}: {e}", exc_info=True)
            return False

    async def validate_checkpoint(self, checkpoint_data: Dict) -> bool:
        """
        Validate a checkpoint to ensure it's usable for recovery.

        Args:
            checkpoint_data: Checkpoint data dictionary

        Returns:
            True if checkpoint is valid
        """
        try:
            # Check required fields
            required_fields = ["scan_id", "target_id", "stage", "data"]
            for field in required_fields:
                if field not in checkpoint_data:
                    logger.error(f"Checkpoint missing required field: {field}")
                    return False

            # Check checkpoint age (not too old)
            created_at = checkpoint_data.get("created_at")
            if created_at:
                age = datetime.utcnow() - created_at
                if age > timedelta(hours=48):  # 48 hours max
                    logger.warning(
                        f"Checkpoint is too old: {age.total_seconds() / 3600:.1f} hours"
                    )
                    return False

            # Validate data structure
            data = checkpoint_data.get("data", {})
            if not isinstance(data, dict):
                logger.error("Checkpoint data is not a dictionary")
                return False

            # Check for corruption indicators
            if "corrupted" in data or "error" in data:
                logger.error("Checkpoint appears to be corrupted")
                return False

            logger.debug(f"Checkpoint validation passed")
            return True

        except Exception as e:
            logger.error(f"Error validating checkpoint: {e}", exc_info=True)
            return False

    async def resume_from_checkpoint(
        self, scan_id: str, checkpoint: Checkpoint
    ) -> bool:
        """
        Resume scan execution from a checkpoint.

        Args:
            scan_id: UUID of the scan
            checkpoint: Checkpoint object to resume from

        Returns:
            True if resume successful
        """
        logger.info(
            f"Resuming scan {scan_id} from checkpoint at stage {checkpoint.stage}"
        )

        try:
            async for db in get_db():
                scan = await db.get(Scan, UUID(scan_id))
                if not scan:
                    return False

                target = await db.get(Target, checkpoint.target_id)
                if not target:
                    logger.error(f"Target {checkpoint.target_id} not found")
                    return False

                # Get checkpoint data
                checkpoint_data = checkpoint.data
                stage_index = checkpoint_data.get("stage_index", 0)

                # Reset target status to retry from this stage
                target.status = TargetStatus.PENDING
                target.error_message = None

                # Update scan status
                scan.status = ScanStatus.RUNNING

                await db.commit()

                # Trigger re-execution of target from this stage
                # This would normally call the orchestrator to relaunch the task
                from backend.tasks.scan_tasks import scan_single_target

                # Extract target data
                target_data = {
                    "id": str(target.id),
                    "value": target.normalized_value,
                    "type": target.target_type.value,
                    "classification": target.classification,
                }

                # Get pipeline config with stages starting from checkpoint
                pipeline_config = scan.pipeline_config.copy()
                if "stages" in pipeline_config:
                    # Resume from the stage where it failed
                    pipeline_config["stages"] = pipeline_config["stages"][
                        stage_index:
                    ]

                # Launch task asynchronously
                scan_single_target.delay(
                    scan_id=scan_id,
                    target_data=target_data,
                    pipeline_config=pipeline_config,
                )

                logger.info(
                    f"Relaunched task for target {target.id} from stage {checkpoint.stage}"
                )
                return True

        except Exception as e:
            logger.error(
                f"Error resuming from checkpoint: {e}", exc_info=True
            )
            return False

    async def create_recovery_checkpoint(
        self,
        scan_id: str,
        target_id: str,
        stage: str,
        data: Dict,
    ) -> Optional[Checkpoint]:
        """
        Create a recovery checkpoint for a scan target.

        Args:
            scan_id: UUID of the scan
            target_id: UUID of the target
            stage: Current stage name
            data: Additional checkpoint data

        Returns:
            Created checkpoint or None if failed
        """
        try:
            async for db in get_db():
                checkpoint = Checkpoint(
                    scan_id=UUID(scan_id),
                    target_id=UUID(target_id),
                    stage=stage,
                    data=data,
                )

                db.add(checkpoint)
                await db.commit()
                await db.refresh(checkpoint)

                # Also store in Redis for quick access
                await self.state_manager.connect()
                await self.state_manager.create_checkpoint(
                    scan_id=scan_id,
                    target_id=target_id,
                    stage=stage,
                    data=data,
                )
                await self.state_manager.disconnect()

                logger.debug(
                    f"Created checkpoint for scan {scan_id}, target {target_id}, stage {stage}"
                )
                return checkpoint

        except Exception as e:
            logger.error(f"Error creating checkpoint: {e}", exc_info=True)
            return None

    async def clean_old_checkpoints(self, days: int = 7) -> int:
        """
        Clean up old checkpoints that are no longer needed.

        Args:
            days: Number of days to keep checkpoints (default: 7)

        Returns:
            Number of checkpoints deleted
        """
        logger.info(f"Cleaning up checkpoints older than {days} days")

        try:
            async for db in get_db():
                cutoff_date = datetime.utcnow() - timedelta(days=days)

                # Delete old checkpoints
                old_checkpoints_result = await db.execute(
                    select(Checkpoint).where(
                        Checkpoint.created_at < cutoff_date
                    )
                )
                old_checkpoints = old_checkpoints_result.scalars().all()

                count = len(old_checkpoints)

                for checkpoint in old_checkpoints:
                    await db.delete(checkpoint)

                await db.commit()

                logger.info(f"Deleted {count} old checkpoints")
                return count

        except Exception as e:
            logger.error(f"Error cleaning checkpoints: {e}", exc_info=True)
            return 0

    async def get_recovery_statistics(self) -> Dict:
        """
        Get statistics about recovery operations.

        Returns:
            Dict with recovery statistics
        """
        try:
            async for db in get_db():
                # Count interrupted scans
                interrupted = await self.find_interrupted_scans(max_age_hours=168)  # 7 days

                # Count total checkpoints
                checkpoints_result = await db.execute(select(Checkpoint))
                total_checkpoints = len(checkpoints_result.scalars().all())

                # Count failed recoveries (scans that couldn't be recovered)
                failed_result = await db.execute(
                    select(Scan).where(
                        and_(
                            Scan.status == ScanStatus.FAILED,
                            Scan.started_at
                            >= datetime.utcnow() - timedelta(days=7),
                        )
                    )
                )
                failed_scans = failed_result.scalars().all()

                return {
                    "interrupted_scans": len(interrupted),
                    "total_checkpoints": total_checkpoints,
                    "failed_recoveries": len(failed_scans),
                    "oldest_checkpoint": None,  # Could calculate from checkpoints
                }

        except Exception as e:
            logger.error(f"Error getting recovery statistics: {e}", exc_info=True)
            return {}

    # Private helper methods

    async def _recover_without_checkpoints(
        self, db: AsyncSession, scan: Scan
    ) -> bool:
        """
        Attempt to recover a scan without checkpoints.

        This is a fallback method that restarts failed/pending targets.
        """
        try:
            logger.info(
                f"Attempting recovery without checkpoints for scan {scan.id}"
            )

            # Find all targets that didn't complete
            incomplete_result = await db.execute(
                select(Target).where(
                    and_(
                        Target.scan_id == scan.id,
                        Target.status.in_(
                            [
                                TargetStatus.PENDING,
                                TargetStatus.IN_PROGRESS,
                                TargetStatus.FAILED,
                            ]
                        ),
                    )
                )
            )
            incomplete_targets = incomplete_result.scalars().all()

            if not incomplete_targets:
                # All targets completed, just update scan status
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                await db.commit()
                return True

            # Reset target statuses and relaunch
            from backend.tasks.scan_tasks import scan_single_target

            for target in incomplete_targets:
                target.status = TargetStatus.PENDING
                target.error_message = None

                target_data = {
                    "id": str(target.id),
                    "value": target.normalized_value,
                    "type": target.target_type.value,
                    "classification": target.classification,
                }

                # Relaunch from beginning
                scan_single_target.delay(
                    scan_id=str(scan.id),
                    target_data=target_data,
                    pipeline_config=scan.pipeline_config,
                )

            # Update scan status
            scan.status = ScanStatus.RUNNING
            await db.commit()

            logger.info(
                f"Relaunched {len(incomplete_targets)} targets for scan {scan.id}"
            )
            return True

        except Exception as e:
            logger.error(
                f"Error recovering without checkpoints: {e}", exc_info=True
            )
            return False


# Global recovery manager instance
recovery_manager = RecoveryManager()
