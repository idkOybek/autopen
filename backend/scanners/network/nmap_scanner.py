"""Nmap network scanner implementation."""

import xml.etree.ElementTree as ET
from typing import Dict, List, Any
from datetime import datetime
import tempfile
import os

from loguru import logger

from backend.scanners.base import BaseScanner, ScanResult, ScannerStatus
from backend.models.finding import Severity


class NmapScanner(BaseScanner):
    """Nmap network scanner for port scanning and service detection."""

    SCAN_MODES = {
        "quick": "-sV -T4 --top-ports 1000",
        "normal": "-sV -sC -T4",
        "comprehensive": "-sV -sC -A -p-",
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Nmap scanner.

        Args:
            config: Scanner configuration
        """
        super().__init__(config)
        self.scan_mode = config.get("scan_mode", "normal")
        self.custom_flags = config.get("custom_flags", "")
        self.output_format = config.get("output_format", "xml")

        # Check if nmap is installed
        if not self.check_tool_installed("nmap"):
            logger.error("Nmap is not installed or not in PATH")

    async def scan(self, target: Dict[str, Any]) -> ScanResult:
        """
        Execute nmap scan against target.

        Args:
            target: Target dictionary

        Returns:
            ScanResult with findings
        """
        start_time = datetime.utcnow()

        try:
            # Validate target
            if not self.validate_target(target):
                raise ValueError(f"Invalid target for Nmap: {target}")

            # Build command
            command = self.build_command(target)

            logger.info(f"Starting Nmap scan: {command}")

            # Execute scan
            stdout, stderr, return_code = await self.execute_command(command)

            # Calculate duration
            duration = (datetime.utcnow() - start_time).total_seconds()

            # Check for errors
            if return_code != 0:
                logger.error(f"Nmap scan failed: {stderr}")
                return ScanResult(
                    tool=self.name,
                    target=target.get("raw_value", ""),
                    status=ScannerStatus.FAILED,
                    findings=[],
                    raw_output=stdout + stderr,
                    error=stderr,
                    duration=duration,
                )

            # Parse output
            findings = self.parse_output(stdout)

            logger.info(
                f"Nmap scan completed: {len(findings)} findings in {duration:.2f}s"
            )

            return ScanResult(
                tool=self.name,
                target=target.get("raw_value", ""),
                status=ScannerStatus.COMPLETED,
                findings=findings,
                raw_output=stdout,
                duration=duration,
                metadata={
                    "scan_mode": self.scan_mode,
                    "target_id": target.get("id"),
                },
            )

        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return self.handle_error(e, target)

    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parse Nmap XML output.

        Args:
            raw_output: Raw XML output from nmap

        Returns:
            List of finding dictionaries
        """
        findings = []

        try:
            # Parse XML
            root = ET.fromstring(raw_output)

            # Iterate through hosts
            for host in root.findall("host"):
                # Get host address
                address_elem = host.find("address")
                if address_elem is None:
                    continue

                host_address = address_elem.get("addr", "unknown")

                # Get host status
                status_elem = host.find("status")
                if status_elem is None or status_elem.get("state") != "up":
                    continue

                # Get OS detection if available
                os_info = self._parse_os_detection(host)

                # Parse ports
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        finding = self._parse_port(port, host_address, os_info)
                        if finding:
                            findings.append(finding)

            logger.debug(f"Parsed {len(findings)} findings from Nmap output")

        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML output: {e}")
        except Exception as e:
            logger.error(f"Error parsing Nmap output: {e}")

        return findings

    def _parse_port(
        self, port_elem: ET.Element, host: str, os_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Parse individual port element."""
        try:
            port_id = port_elem.get("portid")
            protocol = port_elem.get("protocol", "tcp")

            # Get port state
            state_elem = port_elem.find("state")
            if state_elem is None:
                return None

            state = state_elem.get("state")

            # Skip closed ports
            if state != "open":
                return None

            # Get service information
            service_elem = port_elem.find("service")
            service_name = "unknown"
            service_version = ""
            service_product = ""

            if service_elem is not None:
                service_name = service_elem.get("name", "unknown")
                service_version = service_elem.get("version", "")
                service_product = service_elem.get("product", "")

            # Get script output (vulnerabilities)
            scripts = []
            for script in port_elem.findall("script"):
                scripts.append({
                    "id": script.get("id"),
                    "output": script.get("output"),
                })

            # Determine severity based on port and service
            severity = self._determine_severity(
                port_id, service_name, scripts
            )

            # Build finding
            finding = {
                "title": f"Open port {port_id}/{protocol} ({service_name})",
                "description": f"Port {port_id} is open on {host} running {service_name}",
                "severity": severity,
                "finding_type": "open_port",
                "category": "network",
                "affected_component": f"{host}:{port_id}",
                "evidence": {
                    "host": host,
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "version": service_version,
                    "product": service_product,
                    "scripts": scripts,
                    "os": os_info,
                },
                "tool": self.name,
                "confidence": 100,
            }

            return finding

        except Exception as e:
            logger.error(f"Error parsing port element: {e}")
            return None

    def _parse_os_detection(self, host_elem: ET.Element) -> Dict[str, Any]:
        """Parse OS detection information."""
        os_info = {}

        try:
            os_elem = host_elem.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    os_info = {
                        "name": osmatch.get("name"),
                        "accuracy": osmatch.get("accuracy"),
                    }

        except Exception as e:
            logger.error(f"Error parsing OS detection: {e}")

        return os_info

    def _determine_severity(
        self, port: str, service: str, scripts: List[Dict]
    ) -> str:
        """Determine finding severity based on port and service."""
        # Check for vulnerabilities in scripts
        if scripts:
            for script in scripts:
                if "vuln" in script.get("id", "").lower():
                    return Severity.HIGH.value

        # High-risk services
        high_risk_services = [
            "telnet", "ftp", "rlogin", "rsh", "rexec",
            "smb", "microsoft-ds", "netbios-ssn"
        ]

        if service.lower() in high_risk_services:
            return Severity.HIGH.value

        # Medium-risk ports
        medium_risk_ports = ["22", "23", "3389", "445", "139"]

        if port in medium_risk_ports:
            return Severity.MEDIUM.value

        # Default to low for open ports
        return Severity.LOW.value

    def validate_target(self, target: Dict[str, Any]) -> bool:
        """
        Validate target for Nmap scanning.

        Args:
            target: Target dictionary

        Returns:
            True if valid
        """
        target_type = target.get("target_type")

        # Nmap works with IP, domain, and network targets
        valid_types = ["ip", "domain", "network"]

        if target_type not in valid_types:
            logger.debug(
                f"Target type {target_type} not suitable for Nmap"
            )
            return False

        return True

    def build_command(self, target: Dict[str, Any]) -> str:
        """
        Build nmap command.

        Args:
            target: Target dictionary

        Returns:
            Command string
        """
        # Get target value and sanitize
        target_value = self.sanitize_target(target.get("normalized_value", ""))

        # Get scan mode flags
        mode_flags = self.SCAN_MODES.get(self.scan_mode, self.SCAN_MODES["normal"])

        # Create temp file for XML output
        output_file = tempfile.mktemp(suffix=".xml")

        # Build command
        command = f"nmap {mode_flags} -oX {output_file} {target_value}"

        # Add custom flags if specified
        if self.custom_flags:
            command += f" {self.custom_flags}"

        # Add command to read and delete temp file
        command += f" && cat {output_file} && rm {output_file}"

        logger.debug(f"Built nmap command: {command}")

        return command
