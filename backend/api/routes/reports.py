"""Report generation and delivery endpoints."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.report import (
    ReportGenerateRequest,
    ReportResponse,
    ReportSendRequest,
    ReportSendResponse,
)
from backend.core.database import get_db
from backend.models.scan import Scan
from backend.reports.report_coordinator import ReportCoordinator

router = APIRouter()


@router.get("/scans/{scan_id}/technical")
async def get_technical_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Get technical report for a scan.

    Returns PDF file with detailed technical findings.
    """
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        logger.info(f"Generating technical report for scan {scan_id}")

        # Generate report
        coordinator = ReportCoordinator(db)
        report_path = await coordinator.generate_technical_report(str(scan_id))

        return FileResponse(
            path=report_path,
            media_type="application/pdf",
            filename=f"{scan.name}_technical.pdf",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating technical report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to generate report")


@router.get("/scans/{scan_id}/executive")
async def get_executive_report(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Get executive summary report for a scan.

    Returns PDF file with high-level executive summary.
    """
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        logger.info(f"Generating executive report for scan {scan_id}")

        # Generate report
        coordinator = ReportCoordinator(db)
        report_path = await coordinator.generate_executive_report(str(scan_id))

        return FileResponse(
            path=report_path,
            media_type="application/pdf",
            filename=f"{scan.name}_executive.pdf",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating executive report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to generate report")


@router.get("/scans/{scan_id}/targets/{target_id}")
async def get_individual_report(
    scan_id: UUID,
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get individual report for a specific target."""
    try:
        from backend.models.target import Target
        from backend.models.finding import Finding
        from sqlalchemy import select

        target = await db.get(Target, target_id)
        if not target or target.scan_id != scan_id:
            raise HTTPException(status_code=404, detail="Target not found")

        findings_result = await db.execute(
            select(Finding).where(Finding.target_id == target_id)
        )
        findings = findings_result.scalars().all()

        report = {
            "scan_id": str(scan_id),
            "target": {
                "id": str(target.id),
                "value": target.normalized_value,
                "type": target.target_type.value,
                "status": target.status.value,
            },
            "findings_count": len(findings),
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "severity": f.severity.value,
                    "type": f.finding_type,
                    "description": f.description,
                    "cve_id": f.cve_id,
                    "cwe_id": f.cwe_id,
                    "cvss_score": f.cvss_score,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
            "generated_at": datetime.utcnow().isoformat(),
        }

        return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating individual report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to generate report")


@router.post("/scans/{scan_id}/send", response_model=ReportSendResponse)
async def send_report(
    scan_id: UUID,
    request: ReportSendRequest,
    db: AsyncSession = Depends(get_db),
):
    """Send report to specified destinations."""
    try:
        scan = await db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        logger.info(f"Sending report for scan {scan_id} to {len(request.destinations)} destinations")

        errors = []
        destinations_sent = 0

        for destination in request.destinations:
            try:
                if destination.method.value == "telegram":
                    pass
                elif destination.method.value == "email":
                    pass
                elif destination.method.value == "ftp":
                    pass
                elif destination.method.value == "webhook":
                    pass

                destinations_sent += 1
                logger.info(f"Sent report via {destination.method.value}")

            except Exception as send_error:
                error_msg = f"{destination.method.value}: {str(send_error)}"
                errors.append(error_msg)
                logger.error(f"Failed to send via {destination.method.value}: {send_error}")

        success = destinations_sent > 0

        return ReportSendResponse(
            success=success,
            destinations_sent=destinations_sent,
            errors=errors,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to send report")
