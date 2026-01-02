"""Base parser and parser registry for normalizing scanner outputs."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Type, Optional
import hashlib

from loguru import logger

from backend.models.finding import Severity, RemediationEffort


class BaseParser(ABC):
    """Base class for all output parsers."""

    def __init__(self):
        """Initialize the parser."""
        self.name = self.__class__.__name__
        logger.debug(f"Initialized parser: {self.name}")

    @abstractmethod
    def parse(self, raw_output: str, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse raw scanner output into normalized findings.

        Args:
            raw_output: Raw output from scanner
            metadata: Additional metadata (target, scan_id, etc.)

        Returns:
            List of normalized finding dictionaries

        Raises:
            NotImplementedError: Must be implemented by subclass
        """
        raise NotImplementedError("Subclass must implement parse() method")

    def normalize_finding(
        self, finding: Dict[str, Any], metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Normalize a finding to standard format.

        Args:
            finding: Finding dictionary
            metadata: Additional metadata

        Returns:
            Normalized finding dictionary
        """
        normalized = {
            "scan_id": metadata.get("scan_id"),
            "target_id": metadata.get("target_id"),
            "title": finding.get("title", "Unknown"),
            "description": finding.get("description", ""),
            "severity": self._normalize_severity(finding.get("severity")),
            "finding_type": finding.get("finding_type", "Other"),
            "category": finding.get("category", "general"),
            "cwe_id": finding.get("cwe_id"),
            "cve_id": finding.get("cve_id"),
            "cvss_score": finding.get("cvss_score"),
            "affected_component": finding.get("affected_component", ""),
            "evidence": finding.get("evidence", {}),
            "remediation": finding.get("remediation"),
            "remediation_effort": self._determine_remediation_effort(finding),
            "remediation_priority": self._calculate_priority(finding),
            "tool": finding.get("tool", self.name),
            "confidence": finding.get("confidence", 75),
            "false_positive_probability": finding.get("false_positive_probability"),
            "fingerprint": self._generate_fingerprint(finding, metadata),
            "sources": finding.get("sources", {self.name: True}),
        }

        return normalized

    def _normalize_severity(self, severity: Any) -> str:
        """Normalize severity to standard values."""
        if not severity:
            return Severity.INFO.value

        severity_str = str(severity).lower()

        # Map common severity values
        severity_map = {
            "critical": Severity.CRITICAL.value,
            "high": Severity.HIGH.value,
            "medium": Severity.MEDIUM.value,
            "low": Severity.LOW.value,
            "info": Severity.INFO.value,
            "informational": Severity.INFO.value,
            # Numeric mappings
            "4": Severity.CRITICAL.value,
            "3": Severity.HIGH.value,
            "2": Severity.MEDIUM.value,
            "1": Severity.LOW.value,
            "0": Severity.INFO.value,
        }

        return severity_map.get(severity_str, Severity.INFO.value)

    def _determine_remediation_effort(self, finding: Dict[str, Any]) -> str:
        """Determine remediation effort based on finding."""
        # If explicitly provided, use it
        if "remediation_effort" in finding:
            return finding["remediation_effort"]

        # Otherwise, estimate based on finding type and severity
        finding_type = finding.get("finding_type", "").lower()
        severity = finding.get("severity", "").lower()

        # Configuration issues are usually quick to fix
        if "configuration" in finding_type or "misconfiguration" in finding_type:
            return RemediationEffort.LOW.value

        # Complex vulnerabilities require more effort
        if any(
            vuln in finding_type
            for vuln in ["rce", "sqli", "authentication"]
        ):
            return RemediationEffort.HIGH.value

        # High severity findings generally need more effort
        if severity in ["critical", "high"]:
            return RemediationEffort.MEDIUM.value

        return RemediationEffort.LOW.value

    def _calculate_priority(self, finding: Dict[str, Any]) -> int:
        """Calculate remediation priority (1-10, 10 being highest)."""
        severity = finding.get("severity", "").lower()
        finding_type = finding.get("finding_type", "").lower()

        # Base priority on severity
        priority_map = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "info": 1,
        }

        priority = priority_map.get(severity, 5)

        # Increase priority for certain finding types
        if any(
            critical_type in finding_type
            for critical_type in ["rce", "sqli", "authentication", "authorization"]
        ):
            priority = min(priority + 2, 10)

        return priority

    def _generate_fingerprint(
        self, finding: Dict[str, Any], metadata: Dict[str, Any]
    ) -> str:
        """Generate fingerprint for finding deduplication."""
        # Components for fingerprint
        finding_type = finding.get("finding_type", "")
        severity = finding.get("severity", "")
        title = finding.get("title", "")
        target_id = metadata.get("target_id", "")
        component = finding.get("affected_component", "")

        # Create fingerprint string
        fingerprint_string = f"{finding_type}:{severity}:{title}:{target_id}:{component}"

        # Generate SHA256 hash
        fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()

        return fingerprint

    def extract_cve(self, text: str) -> Optional[str]:
        """Extract CVE ID from text."""
        import re

        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        match = re.search(cve_pattern, text, re.IGNORECASE)

        if match:
            return match.group(0).upper()

        return None

    def extract_cwe(self, text: str) -> Optional[str]:
        """Extract CWE ID from text."""
        import re

        cwe_pattern = r"CWE-\d+"
        match = re.search(cwe_pattern, text, re.IGNORECASE)

        if match:
            return match.group(0).upper()

        return None


class ParserRegistry:
    """Registry for output parsers."""

    def __init__(self):
        """Initialize the parser registry."""
        self.parsers: Dict[str, Type[BaseParser]] = {}
        logger.info("Initialized ParserRegistry")

    def register(self, name: str, parser_class: Type[BaseParser]) -> None:
        """
        Register a parser class.

        Args:
            name: Parser name/identifier
            parser_class: Parser class (subclass of BaseParser)

        Example:
            >>> registry = ParserRegistry()
            >>> registry.register("nmap", NmapParser)
        """
        if not issubclass(parser_class, BaseParser):
            raise ValueError(
                f"{parser_class} must be a subclass of BaseParser"
            )

        self.parsers[name] = parser_class
        logger.info(f"Registered parser: {name}")

    def get_parser(self, name: str) -> Optional[BaseParser]:
        """
        Get a parser instance by name.

        Args:
            name: Parser name

        Returns:
            Parser instance or None if not found

        Example:
            >>> registry = ParserRegistry()
            >>> parser = registry.get_parser("nmap")
        """
        if name not in self.parsers:
            logger.warning(f"Parser {name} not found in registry")
            return None

        parser_class = self.parsers[name]

        try:
            return parser_class()

        except Exception as e:
            logger.error(f"Failed to create parser {name}: {e}")
            return None

    def parse(
        self, parser_name: str, raw_output: str, metadata: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Parse output using specified parser.

        Args:
            parser_name: Parser name
            raw_output: Raw output to parse
            metadata: Additional metadata

        Returns:
            List of normalized findings

        Example:
            >>> registry = ParserRegistry()
            >>> findings = registry.parse("nmap", xml_output, {"scan_id": "123"})
        """
        parser = self.get_parser(parser_name)

        if not parser:
            logger.error(f"Parser {parser_name} not available")
            return []

        try:
            findings = parser.parse(raw_output, metadata)
            logger.info(f"Parsed {len(findings)} findings with {parser_name}")
            return findings

        except Exception as e:
            logger.error(f"Error parsing with {parser_name}: {e}")
            return []

    def list_parsers(self) -> List[str]:
        """
        List all registered parsers.

        Returns:
            List of parser names

        Example:
            >>> registry = ParserRegistry()
            >>> parsers = registry.list_parsers()
        """
        return list(self.parsers.keys())


# Global parser registry instance
parser_registry = ParserRegistry()
