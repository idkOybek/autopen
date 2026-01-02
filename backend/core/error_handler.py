"""Centralized error handling and recovery strategies."""

import traceback
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum

from loguru import logger


class ErrorCategory(str, Enum):
    """Error category enumeration."""

    NETWORK = "network"
    TOOL = "tool"
    TARGET = "target"
    SYSTEM = "system"
    DATABASE = "database"
    TIMEOUT = "timeout"
    VALIDATION = "validation"
    PERMISSION = "permission"
    UNKNOWN = "unknown"


class RecoveryAction(str, Enum):
    """Recovery action enumeration."""

    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_IMMEDIATE = "retry_immediate"
    SKIP_TARGET = "skip_target"
    SKIP_TOOL = "skip_tool"
    REDUCE_PARALLELISM = "reduce_parallelism"
    FAIL_SCAN = "fail_scan"
    CONTINUE = "continue"
    REPORT_AND_CONTINUE = "report_and_continue"


# Error categories mapping
ERROR_CATEGORIES = {
    # Network errors
    "ConnectionError": ErrorCategory.NETWORK,
    "ConnectionRefusedError": ErrorCategory.NETWORK,
    "ConnectionResetError": ErrorCategory.NETWORK,
    "TimeoutError": ErrorCategory.TIMEOUT,
    "DNSError": ErrorCategory.NETWORK,
    "SSLError": ErrorCategory.NETWORK,
    # Tool errors
    "FileNotFoundError": ErrorCategory.TOOL,
    "CommandNotFoundError": ErrorCategory.TOOL,
    "ToolExecutionError": ErrorCategory.TOOL,
    # Target errors
    "InvalidTargetError": ErrorCategory.TARGET,
    "BlacklistedTargetError": ErrorCategory.TARGET,
    # System errors
    "MemoryError": ErrorCategory.SYSTEM,
    "DiskFullError": ErrorCategory.SYSTEM,
    "ResourceExhaustedError": ErrorCategory.SYSTEM,
    # Database errors
    "DatabaseError": ErrorCategory.DATABASE,
    "IntegrityError": ErrorCategory.DATABASE,
    # Permission errors
    "PermissionError": ErrorCategory.PERMISSION,
    "AccessDenied": ErrorCategory.PERMISSION,
    # Validation errors
    "ValidationError": ErrorCategory.VALIDATION,
    "ValueError": ErrorCategory.VALIDATION,
}

# Recovery strategy mapping
RECOVERY_STRATEGIES = {
    ErrorCategory.NETWORK: {
        "default": RecoveryAction.RETRY_WITH_BACKOFF,
        "max_retries": 3,
        "critical": False,
    },
    ErrorCategory.TOOL: {
        "default": RecoveryAction.SKIP_TOOL,
        "max_retries": 1,
        "critical": False,
    },
    ErrorCategory.TARGET: {
        "default": RecoveryAction.SKIP_TARGET,
        "max_retries": 0,
        "critical": False,
    },
    ErrorCategory.SYSTEM: {
        "default": RecoveryAction.FAIL_SCAN,
        "max_retries": 0,
        "critical": True,
    },
    ErrorCategory.DATABASE: {
        "default": RecoveryAction.RETRY_WITH_BACKOFF,
        "max_retries": 5,
        "critical": True,
    },
    ErrorCategory.TIMEOUT: {
        "default": RecoveryAction.RETRY_WITH_BACKOFF,
        "max_retries": 2,
        "critical": False,
    },
    ErrorCategory.VALIDATION: {
        "default": RecoveryAction.SKIP_TARGET,
        "max_retries": 0,
        "critical": False,
    },
    ErrorCategory.PERMISSION: {
        "default": RecoveryAction.SKIP_TOOL,
        "max_retries": 0,
        "critical": False,
    },
    ErrorCategory.UNKNOWN: {
        "default": RecoveryAction.REPORT_AND_CONTINUE,
        "max_retries": 1,
        "critical": False,
    },
}


class ErrorHandler:
    """Centralized error handler for scan operations."""

    def __init__(self):
        """Initialize the error handler."""
        logger.info("Initializing ErrorHandler")

    def handle_error(
        self, error: Exception, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle an error and determine recovery action.

        Args:
            error: Exception that occurred
            context: Context dictionary with scan/target/tool information

        Returns:
            Dictionary with error details and recovery action

        Example:
            >>> handler = ErrorHandler()
            >>> error = ConnectionError("Connection refused")
            >>> context = {"target_id": "123", "tool": "nmap"}
            >>> result = handler.handle_error(error, context)
            >>> result["recovery_action"]
            'retry_with_backoff'
        """
        try:
            logger.error(f"Handling error: {type(error).__name__}: {str(error)}")

            # Categorize error
            category = self.categorize_error(error)

            # Get recovery action
            recovery_action = self.get_recovery_action(category, error)

            # Check if critical
            is_critical = self.is_critical(category)

            # Create error entry
            error_entry = {
                "error_type": type(error).__name__,
                "error_message": str(error),
                "category": category.value,
                "recovery_action": recovery_action.value,
                "is_critical": is_critical,
                "timestamp": datetime.utcnow().isoformat(),
                "context": context,
                "traceback": traceback.format_exc(),
            }

            # Log error
            self.log_error(error_entry)

            logger.info(
                f"Error categorized as {category.value}, "
                f"recovery action: {recovery_action.value}"
            )

            return error_entry

        except Exception as e:
            logger.error(f"Error in error handler: {e}")
            # Fallback error entry
            return {
                "error_type": type(error).__name__,
                "error_message": str(error),
                "category": ErrorCategory.UNKNOWN.value,
                "recovery_action": RecoveryAction.CONTINUE.value,
                "is_critical": False,
                "timestamp": datetime.utcnow().isoformat(),
                "context": context,
            }

    def categorize_error(self, error: Exception) -> ErrorCategory:
        """
        Categorize an error.

        Args:
            error: Exception to categorize

        Returns:
            Error category

        Example:
            >>> handler = ErrorHandler()
            >>> error = ConnectionError("Connection refused")
            >>> category = handler.categorize_error(error)
            >>> category
            <ErrorCategory.NETWORK: 'network'>
        """
        error_type = type(error).__name__

        # Check known error types
        if error_type in ERROR_CATEGORIES:
            category = ERROR_CATEGORIES[error_type]
            logger.debug(f"Categorized {error_type} as {category.value}")
            return category

        # Check error message for hints
        error_message = str(error).lower()

        if any(
            keyword in error_message
            for keyword in ["connection", "network", "dns", "ssl", "timeout"]
        ):
            return ErrorCategory.NETWORK

        if any(
            keyword in error_message
            for keyword in ["command not found", "tool", "executable"]
        ):
            return ErrorCategory.TOOL

        if any(
            keyword in error_message for keyword in ["target", "blacklist", "invalid"]
        ):
            return ErrorCategory.TARGET

        if any(keyword in error_message for keyword in ["database", "sql", "query"]):
            return ErrorCategory.DATABASE

        if any(
            keyword in error_message
            for keyword in ["permission", "access denied", "forbidden"]
        ):
            return ErrorCategory.PERMISSION

        logger.debug(f"Categorized {error_type} as unknown")
        return ErrorCategory.UNKNOWN

    def get_recovery_action(
        self, category: ErrorCategory, error: Exception
    ) -> RecoveryAction:
        """
        Determine recovery action for an error category.

        Args:
            category: Error category
            error: Original exception

        Returns:
            Recovery action

        Example:
            >>> handler = ErrorHandler()
            >>> category = ErrorCategory.NETWORK
            >>> error = ConnectionError("Connection refused")
            >>> action = handler.get_recovery_action(category, error)
            >>> action
            <RecoveryAction.RETRY_WITH_BACKOFF: 'retry_with_backoff'>
        """
        strategy = RECOVERY_STRATEGIES.get(
            category, RECOVERY_STRATEGIES[ErrorCategory.UNKNOWN]
        )

        recovery_action = strategy["default"]

        logger.debug(
            f"Recovery action for {category.value}: {recovery_action.value}"
        )

        return recovery_action

    def is_critical(self, category: ErrorCategory) -> bool:
        """
        Check if an error category is critical.

        Args:
            category: Error category

        Returns:
            True if critical, False otherwise

        Example:
            >>> handler = ErrorHandler()
            >>> handler.is_critical(ErrorCategory.SYSTEM)
            True
            >>> handler.is_critical(ErrorCategory.TARGET)
            False
        """
        strategy = RECOVERY_STRATEGIES.get(
            category, RECOVERY_STRATEGIES[ErrorCategory.UNKNOWN]
        )

        is_critical = strategy.get("critical", False)

        if is_critical:
            logger.warning(f"Critical error category: {category.value}")

        return is_critical

    def get_max_retries(self, category: ErrorCategory) -> int:
        """
        Get maximum retry count for error category.

        Args:
            category: Error category

        Returns:
            Maximum number of retries

        Example:
            >>> handler = ErrorHandler()
            >>> handler.get_max_retries(ErrorCategory.NETWORK)
            3
        """
        strategy = RECOVERY_STRATEGIES.get(
            category, RECOVERY_STRATEGIES[ErrorCategory.UNKNOWN]
        )

        return strategy.get("max_retries", 0)

    def log_error(self, error_entry: Dict[str, Any]) -> None:
        """
        Log error to file and console.

        Args:
            error_entry: Error entry dictionary

        Note:
            This method logs to both console and file.
            In production, could also send to error tracking service.
        """
        try:
            category = error_entry.get("category", "unknown")
            error_type = error_entry.get("error_type", "Unknown")
            error_message = error_entry.get("error_message", "")
            recovery_action = error_entry.get("recovery_action", "continue")
            is_critical = error_entry.get("is_critical", False)

            # Format log message
            log_message = (
                f"[{category.upper()}] {error_type}: {error_message} "
                f"(Recovery: {recovery_action})"
            )

            # Log based on criticality
            if is_critical:
                logger.critical(log_message)
            else:
                logger.error(log_message)

            # Log context if available
            context = error_entry.get("context", {})
            if context:
                logger.debug(f"Error context: {context}")

            # Log traceback at debug level
            traceback_str = error_entry.get("traceback")
            if traceback_str:
                logger.debug(f"Traceback:\n{traceback_str}")

        except Exception as e:
            logger.error(f"Error logging error entry: {e}")

    def should_retry(
        self, category: ErrorCategory, retry_count: int
    ) -> bool:
        """
        Check if operation should be retried.

        Args:
            category: Error category
            retry_count: Current retry count

        Returns:
            True if should retry, False otherwise

        Example:
            >>> handler = ErrorHandler()
            >>> handler.should_retry(ErrorCategory.NETWORK, 1)
            True
            >>> handler.should_retry(ErrorCategory.NETWORK, 5)
            False
        """
        max_retries = self.get_max_retries(category)
        should_retry = retry_count < max_retries

        logger.debug(
            f"Retry check for {category.value}: "
            f"attempt {retry_count}/{max_retries} - {should_retry}"
        )

        return should_retry

    def get_backoff_delay(self, retry_count: int, base_delay: float = 2.0) -> float:
        """
        Calculate exponential backoff delay.

        Args:
            retry_count: Current retry attempt
            base_delay: Base delay in seconds

        Returns:
            Delay in seconds

        Example:
            >>> handler = ErrorHandler()
            >>> handler.get_backoff_delay(0)
            2.0
            >>> handler.get_backoff_delay(1)
            4.0
            >>> handler.get_backoff_delay(2)
            8.0
        """
        delay = base_delay * (2**retry_count)
        logger.debug(f"Backoff delay for retry {retry_count}: {delay}s")
        return delay

    def format_error_summary(self, errors: list[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Format error summary statistics.

        Args:
            errors: List of error entries

        Returns:
            Summary dictionary

        Example:
            >>> handler = ErrorHandler()
            >>> errors = [
            ...     {"category": "network", "is_critical": False},
            ...     {"category": "network", "is_critical": False},
            ...     {"category": "system", "is_critical": True}
            ... ]
            >>> summary = handler.format_error_summary(errors)
            >>> summary["total_errors"]
            3
            >>> summary["critical_errors"]
            1
        """
        total_errors = len(errors)
        critical_errors = sum(1 for e in errors if e.get("is_critical", False))

        # Count by category
        categories = {}
        for error in errors:
            category = error.get("category", "unknown")
            categories[category] = categories.get(category, 0) + 1

        return {
            "total_errors": total_errors,
            "critical_errors": critical_errors,
            "non_critical_errors": total_errors - critical_errors,
            "errors_by_category": categories,
        }
