"""Scan API schemas."""

from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class ScanConfig(BaseModel):
    """Scan configuration schema."""

    ftp_path: Optional[str] = Field(None, description="Path to targets file on FTP")
    blacklist_enabled: bool = Field(True, description="Enable blacklist filtering")
    parallel_workers: int = Field(10, ge=1, le=100, description="Number of parallel workers")
    pipeline: Dict = Field(..., description="Pipeline configuration with stages")

    @field_validator("pipeline")
    @classmethod
    def validate_pipeline(cls, v):
        """Validate pipeline structure."""
        if "stages" not in v:
            raise ValueError("Pipeline must contain 'stages' key")
        if not isinstance(v["stages"], list):
            raise ValueError("Pipeline stages must be a list")
        return v


class ScanCreate(BaseModel):
    """Create scan request schema."""

    name: str = Field(..., min_length=1, max_length=255, description="Scan name")
    description: Optional[str] = Field(None, max_length=2048, description="Scan description")
    pipeline_config: Dict = Field(..., description="Pipeline configuration")

    @field_validator("pipeline_config")
    @classmethod
    def validate_pipeline_config(cls, v):
        """Validate pipeline config."""
        if "stages" not in v:
            raise ValueError("Pipeline config must contain 'stages' key")
        return v


class ScanUpdate(BaseModel):
    """Update scan schema."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2048)
    pipeline_config: Optional[Dict] = None


class ScanResponse(BaseModel):
    """Scan response schema."""

    id: UUID
    name: str
    description: Optional[str]
    status: str
    total_targets: int
    total_findings: int
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class ScanTargetStats(BaseModel):
    """Target statistics."""

    pending: int = 0
    in_progress: int = 0
    completed: int = 0
    failed: int = 0


class ScanFindingStats(BaseModel):
    """Finding statistics by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanDetailResponse(BaseModel):
    """Detailed scan response schema."""

    id: UUID
    name: str
    description: Optional[str]
    status: str
    pipeline_config: Dict
    total_targets: int
    total_findings: int
    target_stats: ScanTargetStats
    finding_stats: ScanFindingStats
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration: Optional[float] = Field(None, description="Scan duration in seconds")
    progress_percentage: float = Field(0.0, ge=0.0, le=100.0)

    class Config:
        from_attributes = True


class ScanStatusResponse(BaseModel):
    """Scan status response."""

    scan_id: UUID
    status: str
    total_targets: int
    completed_targets: int
    progress_percentage: float
    status_breakdown: Dict[str, int]
    total_findings: int
    started_at: Optional[datetime]
    estimated_completion: Optional[datetime]


class ScanStartRequest(BaseModel):
    """Start scan request."""

    config: Optional[ScanConfig] = None


class ScanListFilters(BaseModel):
    """Filters for listing scans."""

    status: Optional[str] = None
    name_contains: Optional[str] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
