"""Checkpoint model for scan recovery."""

import uuid
from typing import Optional

from sqlalchemy import String, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.models.base import BaseModel


class Checkpoint(BaseModel):
    """Checkpoint model for recovery and state management."""

    __tablename__ = "checkpoints"

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

    # Stage information
    stage: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Completed stages tracking
    completed_stages: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # State data for recovery
    state_data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="checkpoints")
    target: Mapped["Target"] = relationship("Target", back_populates="checkpoints")

    def __repr__(self) -> str:
        return f"<Checkpoint(id={self.id}, scan_id={self.scan_id}, stage={self.stage})>"
