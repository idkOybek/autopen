"""Blacklist model."""

from typing import Optional

from sqlalchemy import String, Integer, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.models.base import Base, TimestampMixin


class Blacklist(Base, TimestampMixin):
    """Blacklist model for forbidden targets."""

    __tablename__ = "blacklist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    pattern: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<Blacklist(id={self.id}, pattern={self.pattern})>"
