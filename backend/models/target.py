"""Target model."""

from typing import Optional

from sqlalchemy import String, Integer, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.models.base import Base, TimestampMixin


class Target(Base, TimestampMixin):
    """Target model for scan targets."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Scan statistics
    total_scans: Mapped[int] = mapped_column(Integer, default=0)
    last_scan_at: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Contact information
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contact_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    def __repr__(self) -> str:
        return f"<Target(id={self.id}, name={self.name}, url={self.url})>"
