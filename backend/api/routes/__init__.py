"""API routes package."""

from backend.api.routes import health, scans, targets, blacklist, reports

__all__ = ["health", "scans", "targets", "blacklist", "reports"]
