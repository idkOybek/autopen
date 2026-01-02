"""Target model."""

import uuid
from datetime import datetime
from typing import Optional, List
import enum

from sqlalchemy import String, Integer, Boolean, Float, DateTime, Enum as SQLEnum, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.base import BaseModel


class TargetType(str, enum.Enum):
    """Target type enum."""

    WEB = "web"
    API = "api"
    IP = "ip"
    DOMAIN = "domain"
    NETWORK = "network"
    CLOUD = "cloud"
    DATABASE = "database"
    SSH = "ssh"
    SMTP = "smtp"
    FTP = "ftp"
    RDP = "rdp"
    IOT = "iot"
    MOBILE_APP = "mobile_app"


class TargetStatus(str, enum.Enum):
    """Target status enum."""

    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLACKLISTED = "blacklisted"


class Target(BaseModel):
    """Target model for scan targets."""

    __tablename__ = "targets"

    # Foreign key
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Target identification
    raw_value: Mapped[str] = mapped_column(String(1024), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    target_type: Mapped[TargetType] = mapped_column(
        SQLEnum(TargetType),
        nullable=False,
        index=True
    )

    # Classification
    classification: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Status
    status: Mapped[TargetStatus] = mapped_column(
        SQLEnum(TargetStatus),
        default=TargetStatus.PENDING,
        nullable=False,
        index=True
    )
    current_stage: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Statistics
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Blacklist information
    blacklisted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    blacklist_reason: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # Timing
    scan_started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    scan_completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # Reports
    individual_report_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # Additional data
    metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    error_log: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="targets")
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="target",
        cascade="all, delete-orphan"
    )
    checkpoints: Mapped[List["Checkpoint"]] = relationship(
        "Checkpoint",
        back_populates="target",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Target(id={self.id}, raw_value={self.raw_value}, status={self.status})>"
