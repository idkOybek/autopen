"""Core configuration and utilities."""

from backend.core.target_classifier import TargetClassifier, TOOL_MAPPING
from backend.core.deduplicator import Deduplicator
from backend.core.blacklist_manager import BlacklistManager
from backend.core.error_handler import (
    ErrorHandler,
    ErrorCategory,
    RecoveryAction,
)
from backend.core.state_manager import StateManager
from backend.core.scanner_manager import ScannerManager, scanner_manager
from backend.core.parallel_executor import ParallelExecutor
from backend.core.orchestrator import ScanOrchestrator, orchestrator
from backend.core.recovery import RecoveryManager, recovery_manager

__all__ = [
    "TargetClassifier",
    "TOOL_MAPPING",
    "Deduplicator",
    "BlacklistManager",
    "ErrorHandler",
    "ErrorCategory",
    "RecoveryAction",
    "StateManager",
    "ScannerManager",
    "scanner_manager",
    "ParallelExecutor",
    "ScanOrchestrator",
    "orchestrator",
    "RecoveryManager",
    "recovery_manager",
]
