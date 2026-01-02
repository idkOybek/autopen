"""Report generation endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_session

router = APIRouter()


@router.get("/{scan_id}/pdf")
async def generate_pdf_report(
    scan_id: int,
    db: AsyncSession = Depends(get_session)
) -> FileResponse:
    """Generate PDF report for a scan."""
    # TODO: Implement PDF report generation
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/{scan_id}/html")
async def generate_html_report(
    scan_id: int,
    db: AsyncSession = Depends(get_session)
) -> FileResponse:
    """Generate HTML report for a scan."""
    # TODO: Implement HTML report generation
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.post("/{scan_id}/send-telegram")
async def send_telegram_report(
    scan_id: int,
    db: AsyncSession = Depends(get_session)
) -> dict:
    """Send report to Telegram."""
    # TODO: Implement Telegram report sending
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.post("/{scan_id}/upload-ftp")
async def upload_report_to_ftp(
    scan_id: int,
    db: AsyncSession = Depends(get_session)
) -> dict:
    """Upload report to FTP server."""
    # TODO: Implement FTP upload
    raise HTTPException(status_code=501, detail="Not implemented yet")
