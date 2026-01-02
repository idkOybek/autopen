"""Finding model."""

import uuid
from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import String, Integer, Float, Text, DateTime, Enum as SQLEnum, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.base import BaseModel


class Severity(str, enum.Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RemediationEffort(str, enum.Enum):
    """Remediation effort levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    """Finding model for vulnerabilities."""

    __tablename__ = "findings"

    # Foreign keys
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Basic information
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), nullable=False, index=True)

    # Classification
    finding_type: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(255), nullable=False)

    # CVE/CWE information
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Location and affected component
    affected_component: Mapped[str] = mapped_column(String(512), nullable=False)

    # Evidence
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Remediation
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_effort: Mapped[RemediationEffort] = mapped_column(
        SQLEnum(RemediationEffort),
        nullable=False
    )
    remediation_priority: Mapped[int] = mapped_column(Integer, nullable=False)

    # Tool information
    tool: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    false_positive_probability: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Deduplication
    fingerprint: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Sources
    sources: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Discovery time
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    target: Mapped["Target"] = relationship("Target", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, title={self.title}, severity={self.severity})>"
