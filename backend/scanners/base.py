"""Base scanner class for all security scanning tools."""

import asyncio
import shutil
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from loguru import logger


class ScannerStatus(str, Enum):
    """Scanner execution status."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ScanResult:
    """Result from a scanner execution."""

    tool: str
    target: str
    status: ScannerStatus
    findings: List[Dict[str, Any]]
    raw_output: str
    error: Optional[str] = None
    duration: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class BaseScanner(ABC):
    """Base class for all security scanners."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the scanner.

        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
        self.name = self.__class__.__name__
        self.timeout = config.get("timeout", 3600)
        self.retries = config.get("retries", 3)
        self.delay_between_retries = config.get("delay_between_retries", 5)

        logger.info(f"Initializing scanner: {self.name}")

    @abstractmethod
    async def scan(self, target: Dict[str, Any]) -> ScanResult:
        """
        Execute the scan against a target.

        Args:
            target: Target dictionary with details

        Returns:
            ScanResult with findings and metadata

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        raise NotImplementedError("Subclass must implement scan() method")

    @abstractmethod
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parse raw scanner output into structured findings.

        Args:
            raw_output: Raw output string from scanner

        Returns:
            List of finding dictionaries

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        raise NotImplementedError("Subclass must implement parse_output() method")

    @abstractmethod
    def validate_target(self, target: Dict[str, Any]) -> bool:
        """
        Validate if target is suitable for this scanner.

        Args:
            target: Target dictionary

        Returns:
            True if target is valid for this scanner

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        raise NotImplementedError("Subclass must implement validate_target() method")

    @abstractmethod
    def build_command(self, target: Dict[str, Any]) -> str:
        """
        Build the command string to execute.

        Args:
            target: Target dictionary

        Returns:
            Command string

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        raise NotImplementedError("Subclass must implement build_command() method")

    async def execute_command(
        self, command: str, timeout: Optional[int] = None
    ) -> Tuple[str, str, int]:
        """
        Execute a shell command asynchronously.

        Args:
            command: Command to execute
            timeout: Timeout in seconds (uses self.timeout if not specified)

        Returns:
            Tuple of (stdout, stderr, return_code)

        Example:
            >>> scanner = ConcreteScanner(config={})
            >>> stdout, stderr, code = await scanner.execute_command("ls -la")
        """
        timeout = timeout or self.timeout

        try:
            logger.debug(f"Executing command: {command}")

            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )

                stdout_str = stdout.decode("utf-8", errors="ignore")
                stderr_str = stderr.decode("utf-8", errors="ignore")
                return_code = process.returncode

                logger.debug(
                    f"Command completed with return code: {return_code}"
                )

                return stdout_str, stderr_str, return_code

            except asyncio.TimeoutError:
                logger.error(f"Command timed out after {timeout}s: {command}")
                process.kill()
                await process.wait()
                raise TimeoutError(f"Command timed out after {timeout}s")

        except Exception as e:
            logger.error(f"Error executing command: {e}")
            raise

    async def execute_with_timeout(
        self, command: str, timeout: int
    ) -> Tuple[str, str, int]:
        """
        Execute command with specific timeout.

        Args:
            command: Command to execute
            timeout: Timeout in seconds

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        return await self.execute_command(command, timeout=timeout)

    def handle_error(self, error: Exception, target: Dict[str, Any]) -> ScanResult:
        """
        Handle scanner errors and create error result.

        Args:
            error: Exception that occurred
            target: Target being scanned

        Returns:
            ScanResult with error information

        Example:
            >>> scanner = ConcreteScanner(config={})
            >>> result = scanner.handle_error(Exception("Test"), {"raw_value": "test.com"})
            >>> result.status
            <ScannerStatus.FAILED: 'failed'>
        """
        error_type = type(error).__name__
        error_message = str(error)

        logger.error(
            f"Scanner {self.name} failed for target {target.get('raw_value')}: "
            f"{error_type}: {error_message}"
        )

        status = ScannerStatus.FAILED
        if isinstance(error, TimeoutError):
            status = ScannerStatus.TIMEOUT

        return ScanResult(
            tool=self.name,
            target=target.get("raw_value", "unknown"),
            status=status,
            findings=[],
            raw_output="",
            error=f"{error_type}: {error_message}",
            metadata={"target_id": target.get("id")},
        )

    def check_tool_installed(self, tool_name: str) -> bool:
        """
        Check if a tool is installed and available.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if tool is installed

        Example:
            >>> scanner = ConcreteScanner(config={})
            >>> scanner.check_tool_installed("nmap")
            True
        """
        try:
            tool_path = shutil.which(tool_name)

            if tool_path:
                logger.debug(f"Tool {tool_name} found at: {tool_path}")
                return True
            else:
                logger.warning(f"Tool {tool_name} not found in PATH")
                return False

        except Exception as e:
            logger.error(f"Error checking tool {tool_name}: {e}")
            return False

    async def get_tool_version(self, tool_name: str) -> Optional[str]:
        """
        Get the version of an installed tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Version string or None if unable to determine

        Example:
            >>> scanner = ConcreteScanner(config={})
            >>> version = await scanner.get_tool_version("nmap")
        """
        try:
            # Try common version flags
            for flag in ["--version", "-v", "-V", "version"]:
                try:
                    stdout, stderr, code = await self.execute_command(
                        f"{tool_name} {flag}", timeout=10
                    )

                    if code == 0 and stdout:
                        # Extract version from first line
                        first_line = stdout.split("\n")[0]
                        logger.debug(f"{tool_name} version: {first_line}")
                        return first_line.strip()

                except Exception:
                    continue

            logger.warning(f"Could not determine version for {tool_name}")
            return None

        except Exception as e:
            logger.error(f"Error getting version for {tool_name}: {e}")
            return None

    def sanitize_target(self, target: str) -> str:
        """
        Sanitize target string for safe command execution.

        Args:
            target: Target string

        Returns:
            Sanitized target string

        Example:
            >>> scanner = ConcreteScanner(config={})
            >>> scanner.sanitize_target("example.com; rm -rf /")
            'example.com'
        """
        # Remove potentially dangerous characters
        dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r"]

        sanitized = target
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")

        # Remove extra whitespace
        sanitized = " ".join(sanitized.split())

        if sanitized != target:
            logger.warning(
                f"Target was sanitized: '{target}' -> '{sanitized}'"
            )

        return sanitized

    async def scan_with_retry(
        self, target: Dict[str, Any]
    ) -> ScanResult:
        """
        Execute scan with retry logic.

        Args:
            target: Target dictionary

        Returns:
            ScanResult

        Example:
            >>> scanner = ConcreteScanner(config={})
            >>> result = await scanner.scan_with_retry({"raw_value": "example.com"})
        """
        last_error = None

        for attempt in range(self.retries):
            try:
                logger.info(
                    f"Scan attempt {attempt + 1}/{self.retries} for "
                    f"{target.get('raw_value')}"
                )

                result = await self.scan(target)

                if result.status == ScannerStatus.COMPLETED:
                    return result

                # If not completed but no exception, treat as error
                last_error = Exception(f"Scan returned status: {result.status}")

            except Exception as e:
                last_error = e
                logger.warning(
                    f"Scan attempt {attempt + 1} failed: {e}"
                )

                # Wait before retry (except on last attempt)
                if attempt < self.retries - 1:
                    await asyncio.sleep(self.delay_between_retries)

        # All retries exhausted
        logger.error(
            f"All {self.retries} scan attempts failed for "
            f"{target.get('raw_value')}"
        )

        return self.handle_error(last_error, target)

    def __str__(self) -> str:
        """String representation."""
        return f"{self.name}(timeout={self.timeout}s, retries={self.retries})"

    def __repr__(self) -> str:
        """Object representation."""
        return f"<{self.__class__.__name__} name={self.name}>"
