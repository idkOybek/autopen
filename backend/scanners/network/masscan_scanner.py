"""Masscan fast port scanner implementation."""

import json
import tempfile
from typing import Dict, List, Any
from datetime import datetime

from loguru import logger

from backend.scanners.base import BaseScanner, ScanResult, ScannerStatus
from backend.models.finding import Severity


class MasscanScanner(BaseScanner):
    """Masscan for fast port scanning of large networks."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Masscan scanner.

        Args:
            config: Scanner configuration
        """
        super().__init__(config)
        self.rate = config.get("rate", 10000)
        self.port_range = config.get("port_range", "0-65535")
        self.max_rate = config.get("max_rate", 100000)

        # Check if masscan is installed
        if not self.check_tool_installed("masscan"):
            logger.error("Masscan is not installed or not in PATH")

    async def scan(self, target: Dict[str, Any]) -> ScanResult:
        """
        Execute masscan scan against target.

        Args:
            target: Target dictionary

        Returns:
            ScanResult with findings
        """
        start_time = datetime.utcnow()

        try:
            # Validate target
            if not self.validate_target(target):
                raise ValueError(f"Invalid target for Masscan: {target}")

            # Build command
            command = self.build_command(target)

            logger.info(f"Starting Masscan scan: {command}")

            # Execute scan
            stdout, stderr, return_code = await self.execute_command(command)

            # Calculate duration
            duration = (datetime.utcnow() - start_time).total_seconds()

            # Parse output
            findings = self.parse_output(stdout)

            logger.info(
                f"Masscan scan completed: {len(findings)} findings in {duration:.2f}s"
            )

            return ScanResult(
                tool=self.name,
                target=target.get("raw_value", ""),
                status=ScannerStatus.COMPLETED,
                findings=findings,
                raw_output=stdout,
                duration=duration,
                metadata={
                    "rate": self.rate,
                    "port_range": self.port_range,
                    "target_id": target.get("id"),
                },
            )

        except Exception as e:
            logger.error(f"Masscan scan error: {e}")
            return self.handle_error(e, target)

    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parse Masscan JSON output.

        Args:
            raw_output: Raw JSON output from masscan

        Returns:
            List of finding dictionaries
        """
        findings = []

        try:
            # Masscan outputs JSON array
            if not raw_output.strip():
                return findings

            data = json.loads(raw_output)

            # Parse each result
            for item in data:
                finding = self._parse_masscan_result(item)
                if finding:
                    findings.append(finding)

            logger.debug(f"Parsed {len(findings)} findings from Masscan output")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Masscan JSON output: {e}")
        except Exception as e:
            logger.error(f"Error parsing Masscan output: {e}")

        return findings

    def _parse_masscan_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse individual Masscan result."""
        try:
            ip = result.get("ip", "unknown")
            ports = result.get("ports", [])

            # Masscan can return multiple ports per IP
            if not ports:
                return None

            # Get first port (masscan typically returns one port per entry)
            port_info = ports[0]
            port = port_info.get("port")
            proto = port_info.get("proto", "tcp")
            status = port_info.get("status", "open")

            # Skip if not open
            if status != "open":
                return None

            # Determine severity based on port
            severity = self._determine_severity(port)

            # Build finding
            finding = {
                "title": f"Open port {port}/{proto}",
                "description": f"Port {port} is open on {ip}",
                "severity": severity,
                "finding_type": "open_port",
                "category": "network",
                "affected_component": f"{ip}:{port}",
                "evidence": {
                    "ip": ip,
                    "port": port,
                    "protocol": proto,
                    "status": status,
                    "ttl": result.get("ttl"),
                },
                "tool": self.name,
                "confidence": 100,
            }

            return finding

        except Exception as e:
            logger.error(f"Error parsing Masscan result: {e}")
            return None

    def _determine_severity(self, port: int) -> str:
        """Determine severity based on port number."""
        # Critical ports (commonly exploited)
        critical_ports = [21, 23, 445, 3389]

        if port in critical_ports:
            return Severity.HIGH.value

        # High-risk ports
        high_risk_ports = [22, 25, 53, 80, 443, 3306, 5432, 6379, 27017]

        if port in high_risk_ports:
            return Severity.MEDIUM.value

        # Default to low for other open ports
        return Severity.LOW.value

    def validate_target(self, target: Dict[str, Any]) -> bool:
        """
        Validate target for Masscan scanning.

        Args:
            target: Target dictionary

        Returns:
            True if valid
        """
        target_type = target.get("target_type")

        # Masscan works with IP and network targets
        valid_types = ["ip", "network"]

        if target_type not in valid_types:
            logger.debug(
                f"Target type {target_type} not suitable for Masscan"
            )
            return False

        return True

    def build_command(self, target: Dict[str, Any]) -> str:
        """
        Build masscan command.

        Args:
            target: Target dictionary

        Returns:
            Command string
        """
        # Get target value and sanitize
        target_value = self.sanitize_target(target.get("normalized_value", ""))

        # Create temp file for JSON output
        output_file = tempfile.mktemp(suffix=".json")

        # Build command
        command = (
            f"masscan {target_value} "
            f"-p{self.port_range} "
            f"--rate {self.rate} "
            f"-oJ {output_file}"
        )

        # Add command to read and delete temp file
        command += f" && cat {output_file} && rm {output_file}"

        logger.debug(f"Built masscan command: {command}")

        return command
