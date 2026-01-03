"""Report API schemas."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ReportFormat(str, Enum):
    """Report format options."""

    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"


class ReportType(str, Enum):
    """Report type options."""

    TECHNICAL = "technical"
    EXECUTIVE = "executive"
    INDIVIDUAL = "individual"
    SUMMARY = "summary"


class DeliveryMethod(str, Enum):
    """Report delivery methods."""

    TELEGRAM = "telegram"
    EMAIL = "email"
    FTP = "ftp"
    WEBHOOK = "webhook"


class ReportDestination(BaseModel):
    """Report delivery destination."""

    method: DeliveryMethod
    telegram_chat_id: Optional[str] = None
    email_address: Optional[str] = None
    ftp_path: Optional[str] = None
    webhook_url: Optional[str] = None


class ReportGenerateRequest(BaseModel):
    """Generate report request."""

    report_type: ReportType = ReportType.TECHNICAL
    report_format: ReportFormat = ReportFormat.PDF
    include_evidence: bool = Field(True, description="Include evidence in report")
    include_raw_output: bool = Field(False, description="Include raw scanner output")


class ReportResponse(BaseModel):
    """Report generation response."""

    report_id: str
    report_type: str
    report_format: str
    file_path: str
    file_size: int
    generated_at: str


class ReportSendRequest(BaseModel):
    """Send report request."""

    destinations: list[ReportDestination] = Field(..., min_length=1)
    message: Optional[str] = Field(None, description="Optional message to include")


class ReportSendResponse(BaseModel):
    """Send report response."""

    success: bool
    destinations_sent: int
    errors: list[str] = []
