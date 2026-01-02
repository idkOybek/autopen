"""Finding model."""

from typing import Optional
import enum

from sqlalchemy import String, Integer, Text, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column

from backend.models.base import Base, TimestampMixin


class Severity(str, enum.Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    """Finding status."""

    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"


class Finding(Base, TimestampMixin):
    """Finding model for vulnerabilities."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)

    # Vulnerability details
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), nullable=False, index=True)
    status: Mapped[FindingStatus] = mapped_column(
        SQLEnum(FindingStatus),
        default=FindingStatus.NEW,
        nullable=False
    )

    # Location
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)

    # Technical details
    payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(nullable=True)

    # Remediation
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, title={self.title}, severity={self.severity})>"
