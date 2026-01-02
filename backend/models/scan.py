"""Scan model."""

from datetime import datetime
from typing import Optional, List
import enum

from sqlalchemy import String, Integer, Float, DateTime, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.base import BaseModel


class ScanStatus(str, enum.Enum):
    """Scan status enum."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class Scan(BaseModel):
    """Scan model."""

    __tablename__ = "scans"

    # Basic info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        SQLEnum(ScanStatus),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True
    )

    # Configuration
    pipeline_config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # Target statistics
    total_targets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completed_targets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_targets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Finding statistics
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Risk assessment
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Error tracking
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    targets: Mapped[List["Target"]] = relationship(
        "Target",
        back_populates="scan",
        cascade="all, delete-orphan"
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan"
    )
    checkpoints: Mapped[List["Checkpoint"]] = relationship(
        "Checkpoint",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, name={self.name}, status={self.status})>"
