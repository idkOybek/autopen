"""Nuclei vulnerability scanner implementation."""

import json
import tempfile
from typing import Dict, List, Any
from datetime import datetime

from loguru import logger

from backend.scanners.base import BaseScanner, ScanResult, ScannerStatus
from backend.models.finding import Severity


class NucleiScanner(BaseScanner):
    """Nuclei vulnerability scanner for web applications."""

    SEVERITY_MAPPING = {
        "critical": Severity.CRITICAL.value,
        "high": Severity.HIGH.value,
        "medium": Severity.MEDIUM.value,
        "low": Severity.LOW.value,
        "info": Severity.INFO.value,
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Nuclei scanner.

        Args:
            config: Scanner configuration
        """
        super().__init__(config)
        self.severity_levels = config.get(
            "severity_levels", ["critical", "high", "medium"]
        )
        self.update_templates = config.get("update_templates", False)
        self.custom_templates = config.get("custom_templates", None)
        self.rate_limit = config.get("rate_limit", 150)

        # Check if nuclei is installed
        if not self.check_tool_installed("nuclei"):
            logger.error("Nuclei is not installed or not in PATH")

    async def scan(self, target: Dict[str, Any]) -> ScanResult:
        """
        Execute nuclei scan against target.

        Args:
            target: Target dictionary

        Returns:
            ScanResult with findings
        """
        start_time = datetime.utcnow()

        try:
            # Validate target
            if not self.validate_target(target):
                raise ValueError(f"Invalid target for Nuclei: {target}")

            # Update templates if configured
            if self.update_templates:
                await self._update_templates()

            # Build command
            command = self.build_command(target)

            logger.info(f"Starting Nuclei scan: {command}")

            # Execute scan
            stdout, stderr, return_code = await self.execute_command(command)

            # Calculate duration
            duration = (datetime.utcnow() - start_time).total_seconds()

            # Parse output (nuclei outputs JSON per line)
            findings = self.parse_output(stdout)

            logger.info(
                f"Nuclei scan completed: {len(findings)} findings in {duration:.2f}s"
            )

            return ScanResult(
                tool=self.name,
                target=target.get("raw_value", ""),
                status=ScannerStatus.COMPLETED,
                findings=findings,
                raw_output=stdout,
                duration=duration,
                metadata={
                    "severity_levels": self.severity_levels,
                    "target_id": target.get("id"),
                },
            )

        except Exception as e:
            logger.error(f"Nuclei scan error: {e}")
            return self.handle_error(e, target)

    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parse Nuclei JSON output.

        Args:
            raw_output: Raw JSON output from nuclei

        Returns:
            List of finding dictionaries
        """
        findings = []

        try:
            # Nuclei outputs one JSON object per line
            for line in raw_output.strip().split("\n"):
                if not line.strip():
                    continue

                try:
                    result = json.loads(line)
                    finding = self._parse_nuclei_result(result)
                    if finding:
                        findings.append(finding)

                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON line: {e}")
                    continue

            logger.debug(f"Parsed {len(findings)} findings from Nuclei output")

        except Exception as e:
            logger.error(f"Error parsing Nuclei output: {e}")

        return findings

    def _parse_nuclei_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse individual Nuclei result."""
        try:
            info = result.get("info", {})

            # Get basic information
            template_id = result.get("template-id", "unknown")
            template_name = info.get("name", template_id)
            severity = info.get("severity", "info")
            description = info.get("description", "")
            matched_at = result.get("matched-at", "")

            # Get metadata
            metadata = result.get("matcher-name", "")
            extracted_results = result.get("extracted-results", [])

            # Get CWE/CVE if available
            cwe_id = None
            cve_id = None
            classification = info.get("classification", {})

            if classification:
                cwe_list = classification.get("cwe-id", [])
                cve_list = classification.get("cve-id", [])

                if cwe_list:
                    cwe_id = cwe_list[0] if isinstance(cwe_list, list) else cwe_list

                if cve_list:
                    cve_id = cve_list[0] if isinstance(cve_list, list) else cve_list

            # Build finding
            finding = {
                "title": template_name,
                "description": description or f"Nuclei template {template_id} matched",
                "severity": self.SEVERITY_MAPPING.get(
                    severity.lower(), Severity.INFO.value
                ),
                "finding_type": self._categorize_template(template_id),
                "category": "web",
                "cwe_id": cwe_id,
                "cve_id": cve_id,
                "affected_component": matched_at,
                "evidence": {
                    "template_id": template_id,
                    "matcher": metadata,
                    "extracted": extracted_results,
                    "matched_at": matched_at,
                    "curl_command": result.get("curl-command"),
                },
                "tool": self.name,
                "confidence": self._calculate_confidence(severity, metadata),
                "remediation": info.get("remediation"),
                "references": info.get("reference", []),
            }

            return finding

        except Exception as e:
            logger.error(f"Error parsing Nuclei result: {e}")
            return None

    def _categorize_template(self, template_id: str) -> str:
        """Categorize finding type based on template ID."""
        template_id_lower = template_id.lower()

        if "xss" in template_id_lower:
            return "XSS"
        elif "sqli" in template_id_lower or "sql" in template_id_lower:
            return "SQLi"
        elif "rce" in template_id_lower or "command" in template_id_lower:
            return "RCE"
        elif "lfi" in template_id_lower or "file-inclusion" in template_id_lower:
            return "LFI"
        elif "ssrf" in template_id_lower:
            return "SSRF"
        elif "cve" in template_id_lower:
            return "CVE"
        elif "exposure" in template_id_lower:
            return "Information Disclosure"
        elif "misconfiguration" in template_id_lower:
            return "Misconfiguration"
        else:
            return "Other"

    def _calculate_confidence(self, severity: str, matcher: str) -> int:
        """Calculate confidence level based on severity and matcher."""
        # Base confidence on severity
        base_confidence = {
            "critical": 95,
            "high": 90,
            "medium": 85,
            "low": 80,
            "info": 70,
        }

        confidence = base_confidence.get(severity.lower(), 75)

        # Increase confidence if specific matcher
        if matcher and matcher != "":
            confidence = min(confidence + 5, 100)

        return confidence

    async def _update_templates(self) -> None:
        """Update Nuclei templates."""
        try:
            logger.info("Updating Nuclei templates...")

            command = "nuclei -update-templates"
            stdout, stderr, return_code = await self.execute_command(
                command, timeout=300
            )

            if return_code == 0:
                logger.info("Nuclei templates updated successfully")
            else:
                logger.warning(f"Template update returned code {return_code}")

        except Exception as e:
            logger.error(f"Failed to update Nuclei templates: {e}")

    def validate_target(self, target: Dict[str, Any]) -> bool:
        """
        Validate target for Nuclei scanning.

        Args:
            target: Target dictionary

        Returns:
            True if valid
        """
        target_type = target.get("target_type")

        # Nuclei works with web and API targets
        valid_types = ["web", "api"]

        if target_type not in valid_types:
            logger.debug(
                f"Target type {target_type} not suitable for Nuclei"
            )
            return False

        return True

    def build_command(self, target: Dict[str, Any]) -> str:
        """
        Build nuclei command.

        Args:
            target: Target dictionary

        Returns:
            Command string
        """
        # Get target value and sanitize
        target_value = self.sanitize_target(target.get("normalized_value", ""))

        # Build severity filter
        severity_filter = ",".join(self.severity_levels)

        # Build command
        command = (
            f"nuclei -u {target_value} "
            f"-severity {severity_filter} "
            f"-json "
            f"-rate-limit {self.rate_limit} "
            f"-silent"
        )

        # Add custom templates if specified
        if self.custom_templates:
            command += f" -t {self.custom_templates}"

        logger.debug(f"Built nuclei command: {command}")

        return command
