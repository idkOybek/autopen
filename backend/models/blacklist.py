"""Blacklist model."""

from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import String, Integer, Boolean, Text, DateTime, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column

from backend.models.base import BaseModel


class BlacklistEntryType(str, enum.Enum):
    """Blacklist entry type enum."""

    IP = "ip"
    DOMAIN = "domain"
    NETWORK = "network"
    PATTERN = "pattern"
    ASN = "asn"


class BlacklistEntry(BaseModel):
    """Blacklist model for forbidden targets."""

    __tablename__ = "blacklist_entries"

    # Entry information
    entry_type: Mapped[BlacklistEntryType] = mapped_column(
        SQLEnum(BlacklistEntryType),
        nullable=False,
        index=True
    )
    value: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    # Source and metadata
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)

    # Status
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    # Expiration
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # Usage tracking
    hit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_hit: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    def __repr__(self) -> str:
        return f"<BlacklistEntry(id={self.id}, value={self.value}, type={self.entry_type})>"
