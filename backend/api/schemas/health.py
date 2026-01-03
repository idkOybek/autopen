"""Health check API schemas."""

from datetime import datetime
from typing import Dict, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Service status: healthy, degraded, unhealthy")
    timestamp: datetime
    version: str = "1.0.0"


class ServiceStatus(BaseModel):
    """Individual service status."""

    available: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class ReadinessResponse(BaseModel):
    """Readiness check response."""

    ready: bool
    services: Dict[str, ServiceStatus]
    timestamp: datetime


class SystemMetrics(BaseModel):
    """System resource metrics."""

    cpu_percent: float = Field(ge=0.0, le=100.0)
    memory_percent: float = Field(ge=0.0, le=100.0)
    disk_percent: float = Field(ge=0.0, le=100.0)


class WorkloadMetrics(BaseModel):
    """Workload metrics."""

    active_scans: int = Field(ge=0)
    queued_tasks: int = Field(ge=0)
    completed_scans_24h: int = Field(ge=0)
    failed_scans_24h: int = Field(ge=0)


class MetricsResponse(BaseModel):
    """System metrics response."""

    system: SystemMetrics
    workload: WorkloadMetrics
    timestamp: datetime
