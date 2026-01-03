"""
Celery tasks for scan execution and management.
"""

import asyncio
import json
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

from celery import Task
from celery.exceptions import SoftTimeLimitExceeded
from loguru import logger
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.blacklist_manager import BlacklistManager
from backend.core.config import settings
from backend.core.database import get_db
from backend.core.deduplicator import Deduplicator
from backend.core.error_handler import ErrorHandler, ErrorCategory
from backend.core.scanner_manager import scanner_manager
from backend.core.state_manager import StateManager
from backend.core.target_classifier import TargetClassifier
from backend.models.finding import Finding
from backend.models.scan import Scan, ScanStatus
from backend.models.target import Target, TargetStatus
from backend.schemas.target import TargetCreate
from backend.tasks.celery_app import celery_app, configured_task


class ScanTask(Task):
    """Base task class with shared functionality."""

    _db = None
    _state_manager = None
    _error_handler = None

    @property
    def db(self) -> AsyncSession:
        """Lazy database session initialization."""
        if self._db is None:
            self._db = get_db()
        return self._db

    @property
    def state_manager(self) -> StateManager:
        """Lazy state manager initialization."""
        if self._state_manager is None:
            self._state_manager = StateManager()
        return self._state_manager

    @property
    def error_handler(self) -> ErrorHandler:
        """Lazy error handler initialization."""
        if self._error_handler is None:
            self._error_handler = ErrorHandler()
        return self._error_handler


@configured_task(base=ScanTask, name="backend.tasks.scan_tasks.scan_single_target")
def scan_single_target(
    self, scan_id: str, target_data: Dict[str, Any], pipeline_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Scan a single target through the entire pipeline.

    Args:
        scan_id: UUID of the parent scan
        target_data: Target information (id, value, type, etc.)
        pipeline_config: Pipeline configuration with stages

    Returns:
        Dict with scan results including status, findings count, errors
    """
    target_id = target_data.get("id")
    target_value = target_data.get("value")
    target_type = target_data.get("type")

    logger.info(
        f"Starting scan for target {target_id} ({target_value}) in scan {scan_id}"
    )

    async def _scan_target():
        result = {
            "target_id": target_id,
            "status": "failed",
            "findings_count": 0,
            "errors": [],
            "stages_completed": [],
        }

        try:
            # Get database session
            async for db in get_db():
                # Update target status
                target = await db.get(Target, UUID(target_id))
                if not target:
                    raise ValueError(f"Target {target_id} not found")

                target.status = TargetStatus.IN_PROGRESS
                await db.commit()

                state_manager = StateManager()
                await state_manager.connect()

                # Get pipeline stages
                stages = pipeline_config.get("stages", [])

                for stage_idx, stage in enumerate(stages):
                    stage_name = stage.get("name")
                    scanners = stage.get("scanners", [])

                    logger.info(
                        f"Executing stage {stage_idx + 1}/{len(stages)}: {stage_name}"
                    )

                    try:
                        # Create checkpoint before stage
                        await state_manager.create_checkpoint(
                            scan_id=scan_id,
                            target_id=target_id,
                            stage=stage_name,
                            data={
                                "stage_index": stage_idx,
                                "target_data": target_data,
                                "timestamp": datetime.utcnow().isoformat(),
                            },
                        )

                        # Execute all scanners in this stage
                        for scanner_name in scanners:
                            scanner = scanner_manager.get_scanner(scanner_name)
                            if not scanner:
                                logger.warning(
                                    f"Scanner {scanner_name} not found, skipping"
                                )
                                continue

                            logger.info(f"Running {scanner_name} on {target_value}")

                            # Execute scanner
                            scan_result = await scanner.scan(target_data)

                            # Save findings to database
                            if scan_result.findings:
                                deduplicator = Deduplicator()

                                for finding_data in scan_result.findings:
                                    # Generate fingerprint
                                    fingerprint = deduplicator.generate_finding_fingerprint(
                                        finding_data
                                    )

                                    # Check for duplicates
                                    existing_finding = await db.execute(
                                        select(Finding).where(
                                            and_(
                                                Finding.scan_id == UUID(scan_id),
                                                Finding.fingerprint == fingerprint,
                                            )
                                        )
                                    )
                                    existing = existing_finding.scalar_one_or_none()

                                    if existing:
                                        # Merge metadata
                                        deduplicator.merge_finding_metadata(
                                            existing.__dict__, finding_data
                                        )
                                        await db.commit()
                                        logger.info(
                                            f"Merged duplicate finding: {fingerprint}"
                                        )
                                    else:
                                        # Create new finding
                                        new_finding = Finding(
                                            scan_id=UUID(scan_id),
                                            target_id=UUID(target_id),
                                            title=finding_data.get("title"),
                                            description=finding_data.get("description"),
                                            severity=finding_data.get("severity"),
                                            finding_type=finding_data.get("type"),
                                            cwe_id=finding_data.get("cwe_id"),
                                            cve_id=finding_data.get("cve_id"),
                                            cvss_score=finding_data.get("cvss_score"),
                                            evidence=finding_data.get("evidence", {}),
                                            remediation=finding_data.get("remediation"),
                                            remediation_effort=finding_data.get(
                                                "remediation_effort"
                                            ),
                                            remediation_priority=finding_data.get(
                                                "remediation_priority"
                                            ),
                                            references=finding_data.get("references", []),
                                            fingerprint=fingerprint,
                                            confidence=finding_data.get(
                                                "confidence", 0.8
                                            ),
                                        )
                                        db.add(new_finding)
                                        result["findings_count"] += 1

                                await db.commit()

                        result["stages_completed"].append(stage_name)

                    except Exception as stage_error:
                        logger.error(
                            f"Error in stage {stage_name}: {stage_error}",
                            exc_info=True,
                        )

                        error_handler = ErrorHandler()
                        error_category = error_handler.categorize_error(stage_error)
                        recovery_action = error_handler.determine_recovery_action(
                            error_category, stage_error
                        )

                        result["errors"].append(
                            {
                                "stage": stage_name,
                                "error": str(stage_error),
                                "category": error_category.value,
                                "recovery_action": recovery_action.value,
                            }
                        )

                        # Check if we should continue
                        if error_category in [
                            ErrorCategory.SYSTEM,
                            ErrorCategory.DATABASE,
                        ]:
                            raise  # Critical error, stop execution

                # Update target status
                target.status = TargetStatus.COMPLETED
                target.scanned_at = datetime.utcnow()
                await db.commit()

                result["status"] = "completed"
                logger.info(
                    f"Completed scan for target {target_id}: {result['findings_count']} findings"
                )

                await state_manager.disconnect()
                return result

        except SoftTimeLimitExceeded:
            logger.error(f"Task soft time limit exceeded for target {target_id}")
            result["status"] = "timeout"
            result["errors"].append(
                {"error": "Task timeout", "category": "timeout"}
            )
            return result

        except Exception as e:
            logger.error(
                f"Fatal error scanning target {target_id}: {e}", exc_info=True
            )
            result["status"] = "failed"
            result["errors"].append(
                {"error": str(e), "category": "unknown"}
            )

            # Update target status in DB
            try:
                async for db in get_db():
                    target = await db.get(Target, UUID(target_id))
                    if target:
                        target.status = TargetStatus.FAILED
                        target.error_message = str(e)
                        await db.commit()
            except Exception as db_error:
                logger.error(f"Failed to update target status: {db_error}")

            return result

    # Run async function
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_scan_target())


@celery_app.task(name="backend.tasks.scan_tasks.process_targets")
def process_targets(
    scan_id: str, raw_targets: List[str], blacklist_enabled: bool = True
) -> Dict[str, List[Dict]]:
    """
    Process raw targets: filter, deduplicate, classify, enrich.

    Args:
        scan_id: UUID of the parent scan
        raw_targets: List of raw target strings
        blacklist_enabled: Whether to apply blacklist filtering

    Returns:
        Dict mapping target types to lists of processed targets
    """
    logger.info(f"Processing {len(raw_targets)} targets for scan {scan_id}")

    async def _process():
        processed_targets = {
            "web": [],
            "api": [],
            "ip": [],
            "domain": [],
            "network": [],
        }

        try:
            async for db in get_db():
                classifier = TargetClassifier()
                deduplicator = Deduplicator()
                blacklist_manager = BlacklistManager()

                if blacklist_enabled:
                    await blacklist_manager.load_blacklist(db)

                seen_hashes = set()

                for raw_target in raw_targets:
                    try:
                        # Classify target
                        classification = classifier.classify_target(raw_target)
                        target_type = classification["type"]
                        normalized = classifier.normalize_target(
                            raw_target, target_type
                        )

                        # Check blacklist
                        if blacklist_enabled:
                            is_blacklisted, reason = await blacklist_manager.is_blacklisted(
                                normalized
                            )
                            if is_blacklisted:
                                logger.info(
                                    f"Target {normalized} blacklisted: {reason}"
                                )
                                continue

                        # Deduplicate
                        target_hash = deduplicator.generate_target_hash(
                            {"normalized_value": normalized, "target_type": target_type}
                        )

                        if target_hash in seen_hashes:
                            logger.debug(f"Duplicate target skipped: {normalized}")
                            continue

                        seen_hashes.add(target_hash)

                        # Enrich
                        enriched = classifier.enrich_target(classification)

                        # Create target in database
                        target = Target(
                            scan_id=UUID(scan_id),
                            raw_value=raw_target,
                            normalized_value=normalized,
                            target_type=target_type,
                            classification=enriched,
                            status=TargetStatus.PENDING,
                            blacklisted=False,
                        )
                        db.add(target)
                        await db.flush()

                        # Add to result
                        target_data = {
                            "id": str(target.id),
                            "value": normalized,
                            "type": target_type,
                            "classification": enriched,
                        }

                        if target_type in processed_targets:
                            processed_targets[target_type].append(target_data)

                    except Exception as target_error:
                        logger.error(
                            f"Error processing target {raw_target}: {target_error}"
                        )
                        continue

                await db.commit()

                # Update scan statistics
                scan = await db.get(Scan, UUID(scan_id))
                if scan:
                    total = sum(len(targets) for targets in processed_targets.values())
                    scan.total_targets = total
                    await db.commit()

                logger.info(
                    f"Processed targets: {sum(len(v) for v in processed_targets.values())} valid, "
                    f"{len(raw_targets) - sum(len(v) for v in processed_targets.values())} filtered"
                )

                return processed_targets

        except Exception as e:
            logger.error(f"Error processing targets: {e}", exc_info=True)
            raise

    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_process())


@celery_app.task(name="backend.tasks.scan_tasks.generate_final_reports")
def generate_final_reports(scan_id: str) -> Dict[str, str]:
    """
    Generate final reports for a completed scan.

    Args:
        scan_id: UUID of the scan

    Returns:
        Dict with report file paths
    """
    logger.info(f"Generating final reports for scan {scan_id}")

    async def _generate():
        try:
            async for db in get_db():
                scan = await db.get(Scan, UUID(scan_id))
                if not scan:
                    raise ValueError(f"Scan {scan_id} not found")

                # Get all findings
                findings_result = await db.execute(
                    select(Finding).where(Finding.scan_id == UUID(scan_id))
                )
                findings = findings_result.scalars().all()

                # Get all targets
                targets_result = await db.execute(
                    select(Target).where(Target.scan_id == UUID(scan_id))
                )
                targets = targets_result.scalars().all()

                # Aggregate statistics
                stats = {
                    "total_targets": len(targets),
                    "total_findings": len(findings),
                    "critical": sum(1 for f in findings if f.severity == "critical"),
                    "high": sum(1 for f in findings if f.severity == "high"),
                    "medium": sum(1 for f in findings if f.severity == "medium"),
                    "low": sum(1 for f in findings if f.severity == "low"),
                    "info": sum(1 for f in findings if f.severity == "info"),
                }

                # Update scan statistics
                scan.total_findings = stats["total_findings"]
                scan.completed_at = datetime.utcnow()
                await db.commit()

                logger.info(f"Report generation completed for scan {scan_id}")
                logger.info(f"Statistics: {stats}")

                # Return paths (actual report generation would happen here)
                return {
                    "technical_report": f"/reports/{scan_id}/technical.pdf",
                    "executive_report": f"/reports/{scan_id}/executive.pdf",
                    "json_export": f"/reports/{scan_id}/data.json",
                    "statistics": stats,
                }

        except Exception as e:
            logger.error(f"Error generating reports: {e}", exc_info=True)
            raise

    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_generate())


@celery_app.task(name="backend.tasks.scan_tasks.update_tools")
def update_tools() -> Dict[str, str]:
    """
    Update security scanning tools.

    Returns:
        Dict with update status for each tool
    """
    logger.info("Starting tools update")

    tools_update_commands = {
        "nuclei": "nuclei -update-templates",
        "nmap": "apt-get update && apt-get upgrade -y nmap",
        "masscan": "apt-get update && apt-get upgrade -y masscan",
    }

    results = {}

    for tool, command in tools_update_commands.items():
        try:
            logger.info(f"Updating {tool}")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes
            )

            if result.returncode == 0:
                results[tool] = "success"
                logger.info(f"{tool} updated successfully")
            else:
                results[tool] = f"failed: {result.stderr}"
                logger.error(f"{tool} update failed: {result.stderr}")

        except subprocess.TimeoutExpired:
            results[tool] = "timeout"
            logger.error(f"{tool} update timed out")
        except Exception as e:
            results[tool] = f"error: {str(e)}"
            logger.error(f"Error updating {tool}: {e}")

    return results


@celery_app.task(name="backend.tasks.scan_tasks.cleanup_old_scans")
def cleanup_old_scans(days: int = 30) -> Dict[str, int]:
    """
    Clean up old completed scans and their associated data.

    Args:
        days: Number of days to keep scans (default: 30)

    Returns:
        Dict with cleanup statistics
    """
    logger.info(f"Cleaning up scans older than {days} days")

    async def _cleanup():
        try:
            async for db in get_db():
                cutoff_date = datetime.utcnow() - timedelta(days=days)

                # Find old completed scans
                old_scans_result = await db.execute(
                    select(Scan).where(
                        and_(
                            Scan.status == ScanStatus.COMPLETED,
                            Scan.completed_at < cutoff_date,
                        )
                    )
                )
                old_scans = old_scans_result.scalars().all()

                stats = {
                    "scans_deleted": 0,
                    "targets_deleted": 0,
                    "findings_deleted": 0,
                }

                for scan in old_scans:
                    # Count related records
                    targets_count = await db.execute(
                        select(Target).where(Target.scan_id == scan.id)
                    )
                    findings_count = await db.execute(
                        select(Finding).where(Finding.scan_id == scan.id)
                    )

                    stats["targets_deleted"] += len(targets_count.scalars().all())
                    stats["findings_deleted"] += len(findings_count.scalars().all())

                    # Delete scan (cascade will delete targets and findings)
                    await db.delete(scan)
                    stats["scans_deleted"] += 1

                await db.commit()

                logger.info(f"Cleanup completed: {stats}")
                return stats

        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)
            raise

    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_cleanup())
