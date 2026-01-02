"""Scan model."""

from datetime import datetime
from typing import Optional

from sqlalchemy import String, Integer, Text, DateTime, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from backend.models.base import Base, TimestampMixin


class ScanStatus(str, enum.Enum):
    """Scan status enum."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    """Scan type enum."""

    FULL = "full"
    QUICK = "quick"
    CUSTOM = "custom"


class Scan(Base, TimestampMixin):
    """Scan model."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    scan_type: Mapped[ScanType] = mapped_column(SQLEnum(ScanType), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        SQLEnum(ScanStatus),
        default=ScanStatus.PENDING,
        nullable=False
    )

    # Scan configuration
    depth: Mapped[int] = mapped_column(Integer, default=3)
    timeout: Mapped[int] = mapped_column(Integer, default=3600)

    # Results
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, default=0)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0)
    low_findings: Mapped[int] = mapped_column(Integer, default=0)
    info_findings: Mapped[int] = mapped_column(Integer, default=0)

    # Metadata
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Task tracking
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, target_id={self.target_id}, status={self.status})>"
